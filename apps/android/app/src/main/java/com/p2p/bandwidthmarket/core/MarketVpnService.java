package com.p2p.bandwidthmarket.core;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Base64;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

import org.json.JSONObject;

/**
 * MarketVpnService intercepts device traffic and forwards it to a SOCKS5 proxy.
 */
public class MarketVpnService extends VpnService implements Runnable {
    private static final String TAG = "MarketVpnService";
    private static final long FAILED_SESSION_COOLDOWN_MS = 10_000; // 10 seconds before retrying a dead flow

    private Thread thread;
    private ParcelFileDescriptor vpnInterface;
    private boolean running = false;
    private String proxyHost = "127.0.0.1";
    private int proxyPort = 8080;
    private String serverHost = "3.25.162.240"; // CHANGE THIS to your ngrok host or public IP
    private int serverPort = 9999;               // CHANGE THIS to your ngrok port
    private static volatile Network underlyingNetwork;
    private static volatile PublicKey serverkey;
    private static volatile SecretKey sessionAesKey;
    private static volatile String sessionToken;

    public static void setUnderlyingNetwork(Network network) {
        underlyingNetwork = network;
        Log.i(TAG, "Underlying network set: " + network);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "STOP".equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }

        if (intent != null) {
            proxyHost = intent.getStringExtra("PROXY_HOST");
            proxyPort = intent.getIntExtra("PROXY_PORT", 1080);
            Log.i(TAG, "Starting VPN → proxy=" + proxyHost + ":" + proxyPort + " underlyingNetwork=" + underlyingNetwork);
        }

        startVpn();
        return START_STICKY;
    }

    private void startVpn() {
        if (running) return;
        running = true;
        thread = new Thread(this, "MarketVpnThread");
        thread.start();
        Log.i(TAG, "VPN Service started");
    }

    private void stopVpn() {
        running = false;
        if (thread != null) {
            thread.interrupt();
            thread = null;
        }
        try {
            if (vpnInterface != null) {
                vpnInterface.close();
                vpnInterface = null;
            }
        } catch (IOException e) {
            Log.e(TAG, "Error closing VPN interface: " + e.getMessage());
        }
        stopSelf();
        Log.i(TAG, "VPN Service stopped");
    }

    private static class SessionState {
        SocksTcpRelay relay;
        long seq = 1000; // our outgoing ACK value (tracks bytes received from client; initialized to clientISN+1)
        long ack = 1000; // our outgoing SEQ value (tracks bytes we have sent to client; starts at our ISN)
        String srcAddr;
        int srcPort;
        String dstAddr;
        int dstPort;
    }

    private final Map<String, SessionState> sessions = new ConcurrentHashMap<>();
    private final Map<String, Long> failedSessions = new ConcurrentHashMap<>(); // key → time of failure
    private final Map<String, String> ipToDomain = new ConcurrentHashMap<>();
    private int nextFakeIp = 1;

    @Override
    public void run() {
        try {
            setupVpn();
            new Thread(() -> {
                try {
                    Thread.sleep(2000); // IMPORTANT: allow routing table to settle
                    performCryptoHandshake();
                } catch (Exception e) {
                    Log.e(TAG, "Handshake delayed start failed", e);
                }
            }).start();

            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

            ByteBuffer buffer = ByteBuffer.allocate(32768);

            while (running) {
                int length = in.read(buffer.array());
                if (length > 0) {
                    IpPacketParser.PacketInfo info = IpPacketParser.parse(buffer, length);
                    if (info != null) {
                        if (info.protocol == 6) {
                            handleTcpPacket(info, buffer, out);
                        } else if (info.protocol == 17 && info.destinationPort == 53) {
                            handleDnsPacket(info, buffer, out);
                        }
                    }
                    buffer.clear();
                }

                if (Thread.interrupted()) break;
            }

        } catch (Exception e) {
            Log.e(TAG, "VPN Execution error: " + e.getMessage());
        } finally {
            stopVpn();
        }
    }

    /** Finds the active WiFi Network, preferring the one set explicitly via setUnderlyingNetwork(). */
    private Network findWifiNetwork() {
        if (underlyingNetwork != null) return underlyingNetwork;
        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (cm == null) return null;
        for (Network net : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(net);
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                Log.d(TAG, "Dynamically found WiFi network: " + net);
                return net;
            }
        }
        return null;
    }

    private void handleTcpPacket(IpPacketParser.PacketInfo info, ByteBuffer buffer, FileOutputStream out) throws IOException {
        String key = info.destinationAddress + ":" + info.destinationPort + "<-" + info.sourcePort;
        SessionState state = sessions.get(key);

        if (state == null) {
            // Don't retry a recently failed flow — prevents the relay spam
            Long failedAt = failedSessions.get(key);
            if (failedAt != null && System.currentTimeMillis() - failedAt < FAILED_SESSION_COOLDOWN_MS) {
                return;
            }
            failedSessions.remove(key);

            state = new SessionState();
            state.srcAddr = "10.0.0.2";
            state.srcPort = info.sourcePort;
            state.dstAddr = info.destinationAddress;
            state.dstPort = info.destinationPort;
            // Initialize our ack to client's ISN + 1 so SYN-ACK and subsequent ACKs are correct.
            // SYN consumes one sequence number, so ack = clientISN + 1.
            state.seq = (info.tcpSeq + 1) & 0xFFFFFFFFL;

            String targetHost = ipToDomain.getOrDefault(info.destinationAddress, info.destinationAddress);
            
            // To place the server "between" the seller and the internet:
            // 1. We tell the SOCKS proxy (Seller) to connect to our ServerHost.
            // 2. We pass the actual destination (google.com) inside the encrypted payload.
            state.relay = new SocksTcpRelay(proxyHost, proxyPort, serverHost, serverPort, sessionAesKey, sessionToken);

            state.relay.setProtector(socket -> {
                // IMPORTANT:
                // Always bypass VPN for handshake + relay control channel
                boolean ok = protect(socket);
                Log.i(TAG, "protect(socket) applied = " + ok);
                return ok;
            });

            sessions.put(key, state);

            // Send SYN-ACK so the client's TCP stack completes the handshake and sends data.
            // Without this, the browser waits forever and never transmits the HTTP/TLS payload.
            boolean isSyn = (info.tcpFlags & 0x02) != 0 && (info.tcpFlags & 0x10) == 0;
            if (isSyn) {
                byte[] synAck = PacketUtils.createTcpPacket(
                    state.dstAddr, state.dstPort,
                    state.srcAddr, state.srcPort,
                    state.ack, state.seq, // seq=our ISN (1000), ack=clientISN+1
                    (byte) 0x12,          // SYN + ACK
                    null
                );
                synchronized (out) {
                    out.write(synAck);
                }
                state.ack += 1; // SYN consumes one sequence number on our side
                Log.d(TAG, "Sent SYN-ACK for " + key);
            }

            final SessionState finalState = state;
            state.relay.connect(new SocksTcpRelay.RelayCallback() {
                @Override
                public void onDataReceived(byte[] data, int length) {
                    try {
                        byte[] response = PacketUtils.createTcpPacket(
                            finalState.dstAddr, finalState.dstPort,
                            finalState.srcAddr, finalState.srcPort,
                            finalState.ack, finalState.seq,
                            (byte) 0x10,
                            data
                        );
                        synchronized (out) {
                            out.write(response);
                        }
                        finalState.ack += length;
                    } catch (IOException e) {
                        Log.e(TAG, "Error writing to TUN: " + e.getMessage());
                    }
                }

                @Override
                public void onClosed() {
                    sessions.remove(key);
                    failedSessions.put(key, System.currentTimeMillis()); // Cooldown before retry
                }
            });
        }

        if (info.payloadLength > 0) {
            byte[] data = new byte[info.payloadLength];
            buffer.position(info.payloadOffset);
            buffer.get(data);
            state.relay.send(data, info.payloadLength);
            state.seq += info.payloadLength;
            // ACK the client's data immediately so it stops retransmitting while
            // waiting for the upstream response (e.g. TLS handshake latency).
            byte[] ackPkt = PacketUtils.createTcpPacket(
                state.dstAddr, state.dstPort,
                state.srcAddr, state.srcPort,
                state.ack, state.seq,
                (byte) 0x10, null
            );
            synchronized (out) {
                out.write(ackPkt);
            }
        }
    }

    private void handleDnsPacket(IpPacketParser.PacketInfo info, ByteBuffer buffer, FileOutputStream out) throws IOException {
        byte[] query = new byte[info.payloadLength];
        buffer.position(info.payloadOffset);
        buffer.get(query);

        String domain = PacketUtils.parseDnsQuery(query);
        if (domain != null) {
            String fakeIp = "10.1.0." + (nextFakeIp++);
            if (nextFakeIp > 254) nextFakeIp = 1;
            ipToDomain.put(fakeIp, domain);

            byte[] dnsResponse = PacketUtils.createDnsResponse(query, fakeIp);
            if (dnsResponse != null) {
                byte[] packet = PacketUtils.createUdpPacket(
                    info.destinationAddress, info.destinationPort,
                    "10.0.0.2", info.sourcePort,
                    dnsResponse
                );
                synchronized (out) {
                    out.write(packet);
                }
                Log.d(TAG, "DNS: " + domain + " -> " + fakeIp);
            }
        }
    }

    private void setupVpn() throws Exception {
        Network wifi = findWifiNetwork();
        Builder builder = new Builder();
        builder.setMtu(1400);
        builder.addAddress("10.0.0.2", 32);
        builder.addRoute("0.0.0.0", 0);
        builder.addDnsServer("8.8.8.8");
        builder.setSession("P2P Bandwidth Market");
        if (wifi != null) {
            builder.setUnderlyingNetworks(new Network[]{wifi});
            Log.i(TAG, "VPN underlying network: " + wifi);
        } else {
            Log.w(TAG, "No WiFi network found for VPN underlying — protect() may fail");
        }

        vpnInterface = builder.establish();
        if (vpnInterface == null) {
            throw new RuntimeException("Failed to establish VPN interface");
        }
        Log.i(TAG, "VPN Interface established");
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    public synchronized void performCryptoHandshake() throws Exception {
        Log.i(TAG, "Starting crypto handshake with " + proxyHost + ":" + proxyPort);

        // 1. Generate identity and session keys
        KeyPair userKeyPair = KeyManager.getECKeyPair();
        KeyPair sessionKeyPair = KeyManager.generateSessionKeyPair();

        // KeyManager.generateNonce() returns a Base64 string.
        String nonceBase64 = KeyManager.generateNonce();
        byte[] nonceBytes = Base64.decode(nonceBase64, Base64.NO_WRAP);

        long timestamp = System.currentTimeMillis();
        byte[] sessionPubEncoded = sessionKeyPair.getPublic().getEncoded();
        byte[] identityPubEncoded = userKeyPair.getPublic().getEncoded();

        // 2. Prepare data to sign: timestamp | nonce | sessionPub | identityPub
        // This matches the format expected by the server for verification
        ByteBuffer toSign = ByteBuffer.allocate(8 + 4 + nonceBytes.length + 4 + sessionPubEncoded.length + 4 + identityPubEncoded.length);
        toSign.putLong(timestamp);
        toSign.putInt(nonceBytes.length);
        toSign.put(nonceBytes);
        toSign.putInt(sessionPubEncoded.length);
        toSign.put(sessionPubEncoded);
        toSign.putInt(identityPubEncoded.length);
        toSign.put(identityPubEncoded);

        byte[] signature = KeyManager.signData(toSign.array(), userKeyPair.getPrivate());

        // 3. Build JSON request
        JSONObject packet = new JSONObject();
        packet.put("timestamp", timestamp);
        packet.put("nonce", nonceBase64);
        packet.put("identity_pub", Base64.encodeToString(identityPubEncoded, Base64.NO_WRAP));
        packet.put("session_pub", Base64.encodeToString(sessionPubEncoded, Base64.NO_WRAP));
        packet.put("signature", Base64.encodeToString(signature, Base64.NO_WRAP));

        // 4. Send to server via a PROTECTED socket to avoid routing loops
        try (Socket socket = new Socket()) {
            protect(socket);

            Log.i(TAG, "Connecting to EC2: " + serverHost + ":" + serverPort);

            // Connect to the actual Crypto Server for the handshake
            socket.connect(new InetSocketAddress(serverHost, serverPort), 5000);
            
            OutputStream out = socket.getOutputStream();
            out.write(packet.toString().getBytes());
            out.flush();

            // 5. Receive and verify response
            InputStream in = socket.getInputStream();
            byte[] responseBuffer = new byte[4096];
            int n = in.read(responseBuffer);
            if (n <= 0) throw new IOException("Empty response from server during handshake");

            JSONObject response = new JSONObject(new String(responseBuffer, 0, n));
            byte[] serverSessionPubBytes = Base64.decode(response.getString("session_pub"), Base64.NO_WRAP);
            byte[] serverNonceBytes = Base64.decode(response.getString("nonce"), Base64.NO_WRAP);
            byte[] serverSignature = Base64.decode(response.getString("signature"), Base64.NO_WRAP);

            // Verify server signature over (UserSessionPub | UserNonce)
            ByteBuffer serverToVerify = ByteBuffer.allocate(4 + sessionPubEncoded.length + 4 + nonceBytes.length);
            serverToVerify.putInt(sessionPubEncoded.length);
            serverToVerify.put(sessionPubEncoded);
            serverToVerify.putInt(nonceBytes.length);
            serverToVerify.put(nonceBytes);
            
            if (serverkey == null) serverkey = KeyManager.loadServerPublicKeyFromBase64();
            
            if (!KeyManager.verifySignature(serverToVerify.array(), serverSignature, serverkey)) {
                throw new SecurityException("Server handshake signature verification failed!");
            }

            // 6. Derive shared AES key (session key)
            PublicKey serverSessionPub = KeyManager.decodeECPublicKey(serverSessionPubBytes);
            sessionAesKey = KeyManager.generateSharedKey(sessionKeyPair.getPrivate(), serverSessionPub);
            sessionToken = response.getString("session_token");
            
            Log.i(TAG, "Crypto handshake successful. Session token: " + sessionToken);
        } catch (Exception e) {
            Log.e(TAG, "Crypto handshake failed", e);
            throw e;
        }
    }

}
