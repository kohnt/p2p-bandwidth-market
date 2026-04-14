package com.p2p.bandwidthmarket.core;

import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Maintains a persistent connection to the EC2 relay server on behalf of the seller.
 *
 * All buyer sessions are multiplexed over a single control socket. EC2 sends:
 *   {"type":"relay_open",  "session_id":<id>, "target_host":<host>, "target_port":<port>}
 *   {"type":"relay_data",  "session_id":<id>, "data":<base64>}
 *   {"type":"relay_close", "session_id":<id>}
 *
 * This client responds with:
 *   {"type":"relay_data",  "session_id":<id>, "data":<base64>}  (target → EC2 → buyer)
 *   {"type":"relay_close", "session_id":<id>}                   (session ended)
 *
 * The seller's device makes the outbound TCP connections to the internet — so buyer
 * traffic exits via the seller's IP. EC2 only sees base64-wrapped bytes, not content.
 */
public class SellerRelayClient {
    private static final String TAG = "SellerRelayClient";
    private static final int RECONNECT_DELAY_MS = 5000;

    // Sentinel pushed into a session queue to signal the session has been closed.
    private static final byte[] SESSION_CLOSED = new byte[0];

    private final String ec2Host;
    private final int ec2Port;
    private final String sellerToken;

    private volatile boolean running = false;
    private Thread controlThread;
    private final ExecutorService sessionPool = Executors.newCachedThreadPool();

    // session_id → queue of incoming byte chunks from buyer (via EC2)
    private final ConcurrentHashMap<String, LinkedBlockingQueue<byte[]>> sessionQueues =
            new ConcurrentHashMap<>();

    public SellerRelayClient(String ec2Host, int ec2Port, String sellerToken) {
        this.ec2Host = ec2Host;
        this.ec2Port = ec2Port;
        this.sellerToken = sellerToken;
    }

    public void start() {
        if (running) return;
        running = true;
        controlThread = new Thread(this::controlLoop, "seller-relay-control");
        controlThread.setDaemon(true);
        controlThread.start();
        Log.i(TAG, "Started (token=" + sellerToken + ")");
    }

    public void stop() {
        running = false;
        if (controlThread != null) controlThread.interrupt();
        sessionPool.shutdownNow();
        sessionQueues.clear();
        Log.i(TAG, "Stopped");
    }

    // -------------------------------------------------------------------------
    // Control loop — reconnects on failure
    // -------------------------------------------------------------------------

    private void controlLoop() {
        while (running) {
            try {
                connectAndDispatch();
            } catch (Exception e) {
                if (running) {
                    Log.e(TAG, "Control connection lost: " + e.getMessage() + " — retrying");
                    // Drain all session queues so blocked handlers wake up
                    for (LinkedBlockingQueue<byte[]> q : sessionQueues.values()) {
                        q.offer(SESSION_CLOSED);
                    }
                    sessionQueues.clear();
                    try { Thread.sleep(RECONNECT_DELAY_MS); } catch (InterruptedException ie) { break; }
                }
            }
        }
    }

    private void connectAndDispatch() throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ec2Host, ec2Port), 10000);
            socket.setSoTimeout(0); // persistent connection, no read timeout
            InputStream  in  = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // Register as seller
            JSONObject reg = new JSONObject();
            reg.put("type",         "seller_register");
            reg.put("seller_token", sellerToken);
            SocksTcpRelay.writeFrame(out, reg);

            JSONObject ack = SocksTcpRelay.readFrame(in);
            if (!"ok".equals(ack.optString("status"))) {
                throw new IOException("EC2 rejected seller registration: " + ack);
            }
            Log.i(TAG, "Registered with EC2 relay");

            // Dispatch incoming frames
            while (running) {
                JSONObject frame = SocksTcpRelay.readFrame(in);
                String type      = frame.optString("type");
                String sessionId = frame.optString("session_id");

                switch (type) {
                    case "relay_open": {
                        String host = frame.getString("target_host");
                        int    port = frame.getInt("target_port");
                        LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
                        sessionQueues.put(sessionId, queue);
                        sessionPool.execute(() -> handleSession(out, sessionId, host, port, queue));
                        break;
                    }
                    case "relay_data": {
                        byte[] data = Base64.decode(frame.getString("data"), Base64.NO_WRAP);
                        LinkedBlockingQueue<byte[]> queue = sessionQueues.get(sessionId);
                        if (queue != null) queue.offer(data);
                        break;
                    }
                    case "relay_close": {
                        LinkedBlockingQueue<byte[]> queue = sessionQueues.remove(sessionId);
                        if (queue != null) queue.offer(SESSION_CLOSED);
                        break;
                    }
                    default:
                        Log.w(TAG, "Unknown frame type: " + type);
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Per-session handler — runs on sessionPool
    // -------------------------------------------------------------------------

    private void handleSession(OutputStream controlOut, String sessionId,
                                String host, int port,
                                LinkedBlockingQueue<byte[]> queue) {
        Log.d(TAG, "Session " + sessionId + " → " + host + ":" + port);
        try (Socket target = new Socket()) {
            target.connect(new InetSocketAddress(host, port), 10000);
            target.setSoTimeout(60000);

            InputStream  targetIn  = target.getInputStream();
            OutputStream targetOut = target.getOutputStream();

            // target → EC2 (response path: seller reads from target, writes to EC2)
            Thread respThread = new Thread(() -> {
                byte[] buf = new byte[4096];
                int n;
                try {
                    while ((n = targetIn.read(buf)) != -1) {
                        JSONObject frame = new JSONObject();
                        frame.put("type",       "relay_data");
                        frame.put("session_id", sessionId);
                        frame.put("data", Base64.encodeToString(buf, 0, n, Base64.NO_WRAP));
                        synchronized (controlOut) {
                            SocksTcpRelay.writeFrame(controlOut, frame);
                        }
                    }
                } catch (Exception ignored) {
                } finally {
                    // Notify EC2 the session is done from this side
                    try {
                        JSONObject close = new JSONObject();
                        close.put("type",       "relay_close");
                        close.put("session_id", sessionId);
                        synchronized (controlOut) {
                            SocksTcpRelay.writeFrame(controlOut, close);
                        }
                    } catch (Exception ignored) {}
                }
            }, "seller-resp-" + sessionId);
            respThread.setDaemon(true);
            respThread.start();

            // EC2 → target (request path: seller reads from queue, writes to target)
            while (true) {
                byte[] data = queue.poll(30, TimeUnit.SECONDS);
                if (data == null || data == SESSION_CLOSED) break; // timeout or closed sentinel
                targetOut.write(data);
                targetOut.flush();
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            Log.e(TAG, "Session " + sessionId + " error: " + e.getMessage());
        } finally {
            sessionQueues.remove(sessionId);
        }
    }
}
