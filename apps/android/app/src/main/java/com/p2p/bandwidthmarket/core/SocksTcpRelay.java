package com.p2p.bandwidthmarket.core;

import android.util.Base64;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Relays TCP traffic through the EC2 relay server using p2p.py's JSON-frame protocol.
 *
 * Protocol:
 *   All messages: [4-byte big-endian length][UTF-8 JSON body]
 *
 *   connect() sends:
 *     {"type":"hello","session":<token>,"target_host":<str>,"target_port":<int>,"seller":<token>}
 *
 *   send() sends:
 *     {"type":"relay","session":<token>,"data":<base64>}
 *
 *   Inbound frames:
 *     {"type":"data","data":<base64>}
 *
 * Session tokens come from a one-shot ECDH handshake (performHandshake).
 * Call that once when the VPN starts; reuse the token for all relays.
 */
public class SocksTcpRelay {
    private static final String TAG = "SocksTcpRelay";

    private final String ec2Host;
    private final int ec2Port;
    private final String targetHost;
    private final int targetPort;
    private final String sessionToken;
    private final String sellerToken;
    private final String bootstrapProxyHost; // seller's SOCKS5 proxy — used to reach EC2 via LocalOnlyHotspot
    private final int bootstrapProxyPort;

    private Socket socket;
    private InputStream in;
    private OutputStream out;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private RelayCallback callback;

    public interface RelayCallback {
        void onDataReceived(byte[] data, int length);
        void onClosed();
    }

    public interface Protector {
        boolean protect(Socket socket);
    }

    private Protector protector;

    public void setProtector(Protector protector) {
        this.protector = protector;
    }

    public SocksTcpRelay(String ec2Host, int ec2Port, String targetHost, int targetPort,
                          String sessionToken, String sellerToken,
                          String bootstrapProxyHost, int bootstrapProxyPort) {
        this.ec2Host = ec2Host;
        this.ec2Port = ec2Port;
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.sessionToken = sessionToken;
        this.sellerToken = sellerToken;
        this.bootstrapProxyHost = bootstrapProxyHost;
        this.bootstrapProxyPort = bootstrapProxyPort;
    }

    // -------------------------------------------------------------------------
    // One-shot ECDH handshake — call once on VPN start to obtain a session token
    // -------------------------------------------------------------------------

    public static String performHandshake(String ec2Host, int ec2Port,
                                           String bootstrapProxyHost, int bootstrapProxyPort) throws Exception {
        try (Socket socket = openSocket(ec2Host, ec2Port, bootstrapProxyHost, bootstrapProxyPort, null)) {
            socket.setSoTimeout(15000);
            InputStream in   = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // Ephemeral EC keypair for ECDH
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            String pubB64 = Base64.encodeToString(kp.getPublic().getEncoded(), Base64.NO_WRAP);

            byte[] nonce = new byte[16];
            new SecureRandom().nextBytes(nonce);

            JSONObject hs = new JSONObject();
            hs.put("type",         "handshake");
            hs.put("timestamp",    System.currentTimeMillis());
            hs.put("nonce",        Base64.encodeToString(nonce, Base64.NO_WRAP));
            hs.put("identity_pub", pubB64);
            hs.put("session_pub",  pubB64);
            writeFrame(out, hs);

            JSONObject resp = readFrame(in);
            String token = resp.getString("session_token");
            Log.i(TAG, "Handshake OK — session token obtained");
            return token;
        }
    }

    // -------------------------------------------------------------------------
    // Relay connection
    // -------------------------------------------------------------------------

    public void connect(RelayCallback callback) {
        this.callback = callback;
        executor.execute(() -> {
            try {
                socket = openSocket(ec2Host, ec2Port, bootstrapProxyHost, bootstrapProxyPort, protector);
                socket.setSoTimeout(30000);
                in  = socket.getInputStream();
                out = socket.getOutputStream();

                JSONObject hello = new JSONObject();
                hello.put("type",        "hello");
                hello.put("session",     sessionToken);
                hello.put("target_host", targetHost);
                hello.put("target_port", targetPort);
                if (sellerToken != null && !sellerToken.isEmpty()) {
                    hello.put("seller", sellerToken);
                }
                writeFrame(out, hello);

                Log.i(TAG, "Relay open → " + targetHost + ":" + targetPort);
                startReading();

            } catch (Exception e) {
                Log.e(TAG, "Relay connect failed: " + e.getMessage());
                close();
            }
        });
    }

    private void startReading() {
        Thread t = new Thread(() -> {
            try {
                while (true) {
                    JSONObject frame = readFrame(in);
                    if (!"data".equals(frame.optString("type"))) continue;
                    byte[] data = Base64.decode(frame.getString("data"), Base64.NO_WRAP);
                    if (callback != null) callback.onDataReceived(data, data.length);
                }
            } catch (Exception e) {
                Log.d(TAG, "Relay reader closed: " + e.getMessage());
            } finally {
                close();
            }
        }, "relay-reader");
        t.setDaemon(true);
        t.start();
    }

    public void send(byte[] data, int length) {
        executor.execute(() -> {
            try {
                JSONObject frame = new JSONObject();
                frame.put("type",    "relay");
                frame.put("session", sessionToken);
                frame.put("data",    Base64.encodeToString(data, 0, length, Base64.NO_WRAP));
                writeFrame(out, frame);
            } catch (Exception e) {
                Log.e(TAG, "Send failed: " + e.getMessage());
                close();
            }
        });
    }

    public void close() {
        try { if (socket != null) socket.close(); } catch (IOException ignored) {}
        if (callback != null) callback.onClosed();
        executor.shutdownNow();
    }

    // -------------------------------------------------------------------------
    // Socket factory — optionally tunnels through a SOCKS5 bootstrap proxy
    // (needed because LocalOnlyHotspot blocks direct internet; the seller's
    // proxy on :8080 provides the path from the hotspot to EC2)
    // -------------------------------------------------------------------------

    private static Socket openSocket(String destHost, int destPort,
                                      String proxyHost, int proxyPort,
                                      Protector protector) throws IOException {
        Socket socket = new Socket();
        if (proxyHost != null && !proxyHost.isEmpty()) {
            // Connect to seller's SOCKS5 proxy first
            socket.connect(new InetSocketAddress(proxyHost, proxyPort), 10000);
            socks5Connect(socket, destHost, destPort);
        } else {
            if (protector != null) protector.protect(socket);
            socket.connect(new InetSocketAddress(destHost, destPort), 10000);
        }
        return socket;
    }

    /** Sends a SOCKS5 CONNECT through an already-connected socket. */
    private static void socks5Connect(Socket socket, String host, int port) throws IOException {
        OutputStream out = socket.getOutputStream();
        InputStream  in  = socket.getInputStream();

        // Greeting — no auth
        out.write(new byte[]{0x05, 0x01, 0x00});
        byte[] gr = readExactly(in, 2);
        if (gr[0] != 0x05 || gr[1] != 0x00) throw new IOException("SOCKS5 greeting failed");

        // CONNECT request
        byte[] hostBytes = host.getBytes("UTF-8");
        ByteBuffer req = ByteBuffer.allocate(7 + hostBytes.length);
        req.put((byte) 0x05); // VER
        req.put((byte) 0x01); // CMD=CONNECT
        req.put((byte) 0x00); // RSV
        req.put((byte) 0x03); // ATYP=domain
        req.put((byte) hostBytes.length);
        req.put(hostBytes);
        req.putShort((short) port);
        out.write(req.array());
        out.flush();

        // Response — skip BND.ADDR/PORT
        byte[] resp = readExactly(in, 4);
        if (resp[1] != 0x00) throw new IOException("SOCKS5 CONNECT rejected: " + resp[1]);
        int addrLen = (resp[3] == 0x01) ? 4 : (resp[3] == 0x04) ? 16 : (in.read() & 0xFF);
        readExactly(in, addrLen + 2); // skip addr + port
    }

    // -------------------------------------------------------------------------
    // Frame I/O — package-visible so SellerRelayClient can reuse them
    // -------------------------------------------------------------------------

    static void writeFrame(OutputStream out, JSONObject obj) throws IOException {
        byte[] body = obj.toString().getBytes("UTF-8");
        out.write(ByteBuffer.allocate(4).putInt(body.length).array());
        out.write(body);
        out.flush();
    }

    static JSONObject readFrame(InputStream in) throws IOException, JSONException {
        byte[] lenBuf = readExactly(in, 4);
        int length = ByteBuffer.wrap(lenBuf).getInt();
        if (length <= 0 || length > 1_048_576) {
            throw new IOException("Bad frame length: " + length);
        }
        byte[] body = readExactly(in, length);
        return new JSONObject(new String(body, "UTF-8"));
    }

    static byte[] readExactly(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r == -1) throw new EOFException("Stream ended after " + off + "/" + n + " bytes");
            off += r;
        }
        return buf;
    }
}
