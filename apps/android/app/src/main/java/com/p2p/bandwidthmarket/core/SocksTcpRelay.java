package com.p2p.bandwidthmarket.core;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;

/**
 * SocksTcpRelay handles the SOCKS5 handshake and relays data.
 * It also supports optional AES/GCM encryption for the relayed data.
 */
public class SocksTcpRelay {
    private static final String TAG = "SocksTcpRelay";
    private final String proxyHost;
    private final int proxyPort;
    private final String targetHost;
    private final int targetPort;
    private Socket socket;
    private InputStream in;
    private OutputStream out;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private RelayCallback callback;
    private final SecretKey sessionKey;
    private final String sessionToken;

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

    public SocksTcpRelay(String proxyHost, int proxyPort, String targetHost, int targetPort, SecretKey sessionKey, String sessionToken) {
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.sessionKey = sessionKey;
        this.sessionToken = sessionToken;
    }

    public void connect(RelayCallback callback) {
        this.callback = callback;
        executor.execute(() -> {
            try {
                socket = new Socket();
                socket.setSoTimeout(0); // 30s read timeout
                socket.connect(new InetSocketAddress(proxyHost, proxyPort), 5000);
                in = socket.getInputStream();
                out = socket.getOutputStream();
                Log.d(TAG, "TCP connected to proxy " + proxyHost + ":" + proxyPort + " for " + targetHost + ":" + targetPort);

                if (performSocks5Handshake()) {
                    Log.i(TAG, "SOCKS5 handshake OK → " + targetHost + ":" + targetPort);

                    // NEW: Send session token and destination info
                    if (sessionKey != null && sessionToken != null) {
                        // 1. Send the 8-byte token UNENCRYPTED first so server can find the key
                        out.write(sessionToken.getBytes());

                        // 2. Send the destination header ENCRYPTED
                        byte[] hostBytes = targetHost.getBytes();
                        ByteBuffer header = ByteBuffer.allocate(4 + hostBytes.length + 4);
                        header.putInt(hostBytes.length);
                        header.put(hostBytes);
                        header.putInt(targetPort);
                        send(header.array(), header.position());
                    }

                    startRelaying();
                } else {
                    Log.e(TAG, "SOCKS5 handshake FAILED for " + targetHost + ":" + targetPort);
                    close();
                }
            } catch (IOException e) {
                Log.e(TAG, "Relay connection failed: " + e.getMessage());
                close();
            }
        });
    }

    private boolean performSocks5Handshake() throws IOException {
        // 1. Greeting
        out.write(new byte[]{0x05, 0x01, 0x00});
        byte[] response = new byte[2];
        if (in.read(response) != 2 || response[0] != 0x05 || response[1] != 0x00) return false;

        // 2. Connection Request
        ByteBuffer buffer = ByteBuffer.allocate(256);
        buffer.put((byte) 0x05); // VER
        buffer.put((byte) 0x01); // CMD (CONNECT)
        buffer.put((byte) 0x00); // RSV
        if (isIpv4(targetHost)) {
            buffer.put((byte) 0x01); // ATYP (IPv4)
            String[] parts = targetHost.split("\\.");
            for (String part : parts) {
                buffer.put((byte) Integer.parseInt(part));
            }
        } else {
            buffer.put((byte) 0x03); // ATYP (Domain Name)
            byte[] hostBytes = targetHost.getBytes();
            buffer.put((byte) hostBytes.length);
            buffer.put(hostBytes);
        }
        buffer.putShort((short) targetPort);
        
        out.write(buffer.array(), 0, buffer.position());
        
        response = new byte[10]; 
        int read = in.read(response);
        return read >= 2 && response[1] == 0x00;
    }

    private void startRelaying() {
        Thread reader = new Thread(() -> {
            try {
                if (sessionKey != null) {
                    while (true) {
                        byte[] lenBuf = new byte[4];
                        if (!readFully(in, lenBuf)) break;
                        int len = ByteBuffer.wrap(lenBuf).getInt();
                        if (len <= 0 || len > 65536) throw new IOException("Invalid frame length: " + len);

                        byte[] encrypted = new byte[len];
                        if (!readFully(in, encrypted)) break;

                        byte[] decrypted = KeyManager.decrypt(encrypted, sessionKey);
                        if (callback != null) callback.onDataReceived(decrypted, decrypted.length);
                    }
                } else {
                    byte[] buffer = new byte[16384];
                    int length;
                    while ((length = in.read(buffer)) != -1) {
                        byte[] chunk = java.util.Arrays.copyOf(buffer, length);
                        if (callback != null) callback.onDataReceived(chunk, length);
                    }
                }
            } catch (Exception e) {
                Log.d(TAG, "Relay closed: " + e.getMessage());
            } finally {
                close();
            }
        }, "relay-reader");
        reader.setDaemon(true);
        reader.start();
    }

    private boolean readFully(InputStream in, byte[] b) throws IOException {
        int n = 0;
        while (n < b.length) {
            int count = in.read(b, n, b.length - n);
            if (count < 0) return false;
            n += count;
        }
        return true;
    }

    public void send(byte[] data, int length) {
        executor.execute(() -> {
            try {
                if (out != null) {
                    byte[] payload = java.util.Arrays.copyOf(data, length);
                    if (sessionKey != null) {
                        payload = KeyManager.encrypt(payload, sessionKey);
                        ByteBuffer framed = ByteBuffer.allocate(4 + payload.length);
                        framed.putInt(payload.length);
                        framed.put(payload);
                        out.write(framed.array());
                    } else {
                        out.write(payload);
                    }
                    out.flush();
                }
            } catch (Exception e) {
                Log.e(TAG, "Failed to send data: " + e.getMessage());
                close();
            }
        });
    }

    public void close() {
        try {
            if (socket != null) socket.close();
        } catch (IOException ignored) {}
        if (callback != null) callback.onClosed();
        executor.shutdownNow();
    }

    private boolean isIpv4(String host) {
        try {
            String[] parts = host.split("\\.");
            if (parts.length != 4) return false;
            for (String part : parts) {
                int val = Integer.parseInt(part);
                if (val < 0 || val > 255) return false;
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
