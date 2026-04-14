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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Relays TCP traffic through the EC2 relay server using p2p.py's JSON-frame protocol.
 *
 * Protocol:
 *   All messages: [4-byte big-endian length][UTF-8 JSON body]
 *
 *   connect() sends:
 *     {"type":"hello","session":<token>,"target_host":<str>,"target_port":<int>}
 *
 *   send() sends:
 *     {"type":"relay","session":<token>,"data":<base64 of AES-GCM(plaintext)>}
 *
 *   Inbound frames:
 *     {"type":"data","data":<base64 of AES-GCM(plaintext)>}
 *
 * All relay data is encrypted with AES-128-GCM using a key derived from an ECDH
 * handshake with EC2. The seller's SOCKS5 proxy carries the bytes but sees only
 * ciphertext — it cannot read the payload.
 *
 * Frame encryption format: [12-byte random IV][AES-GCM ciphertext + 16-byte tag]
 *
 * Session tokens and AES keys come from performHandshake(). Call that once when the
 * VPN starts; reuse both for all relays.
 */
public class SocksTcpRelay {
    private static final String TAG = "SocksTcpRelay";

    /** Result of a completed ECDH handshake with EC2. */
    public static class HandshakeResult {
        public final String sessionToken;
        public final byte[] aesKey; // 16-byte AES-128 key
        public HandshakeResult(String sessionToken, byte[] aesKey) {
            this.sessionToken = sessionToken;
            this.aesKey = aesKey;
        }
    }

    private final String ec2Host;
    private final int ec2Port;
    private final String targetHost;
    private final int targetPort;
    private final String sessionToken;
    private final String sellerToken;
    private final String bootstrapProxyHost;
    private final int bootstrapProxyPort;
    private final byte[] aesKey; // AES-128 key shared with EC2

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
                          String bootstrapProxyHost, int bootstrapProxyPort,
                          byte[] aesKey) {
        this.ec2Host = ec2Host;
        this.ec2Port = ec2Port;
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.sessionToken = sessionToken;
        this.sellerToken = sellerToken;
        this.bootstrapProxyHost = bootstrapProxyHost;
        this.bootstrapProxyPort = bootstrapProxyPort;
        this.aesKey = aesKey;
    }

    // -------------------------------------------------------------------------
    // One-shot ECDH handshake — call once on VPN start to obtain session token + AES key
    // -------------------------------------------------------------------------

    public static HandshakeResult performHandshake(String ec2Host, int ec2Port,
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

            // Complete ECDH: derive shared secret using EC2's ephemeral public key
            byte[] serverPubBytes = Base64.decode(resp.getString("session_pub"), Base64.NO_WRAP);
            java.security.PublicKey serverPub = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(serverPubBytes));

            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(serverPub, true);
            byte[] sharedSecret = ka.generateSecret();

            // Derive 16-byte AES-128 key: SHA-256(shared_secret)[:16]
            byte[] aesKey = Arrays.copyOf(
                    MessageDigest.getInstance("SHA-256").digest(sharedSecret), 16);

            String token = resp.getString("session_token");
            Log.i(TAG, "Handshake OK — session token + AES key derived");
            return new HandshakeResult(token, aesKey);
        }
    }

    // -------------------------------------------------------------------------
    // AES-128-GCM helpers
    // Format: [12-byte random IV][ciphertext + 16-byte GCM tag]
    // -------------------------------------------------------------------------

    private byte[] encrypt(byte[] plaintext) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] out = new byte[12 + ciphertext.length];
        System.arraycopy(iv, 0, out, 0, 12);
        System.arraycopy(ciphertext, 0, out, 12, ciphertext.length);
        return out;
    }

    private byte[] decrypt(byte[] data) throws Exception {
        byte[] iv         = Arrays.copyOfRange(data, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(data, 12, data.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(ciphertext);
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
                    byte[] encrypted = Base64.decode(frame.getString("data"), Base64.NO_WRAP);
                    byte[] data = decrypt(encrypted);
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
                byte[] plaintext = Arrays.copyOf(data, length);
                byte[] encrypted = encrypt(plaintext);
                JSONObject frame = new JSONObject();
                frame.put("type",    "relay");
                frame.put("session", sessionToken);
                frame.put("data",    Base64.encodeToString(encrypted, Base64.NO_WRAP));
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
