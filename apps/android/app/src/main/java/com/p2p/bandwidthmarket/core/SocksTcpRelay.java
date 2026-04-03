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

/**
 * SocksTcpRelay handles the SOCKS5 handshake and relays data.
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

    public SocksTcpRelay(String proxyHost, int proxyPort, String targetHost, int targetPort) {
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        this.targetHost = targetHost;
        this.targetPort = targetPort;
    }

    public void connect(RelayCallback callback) {
        this.callback = callback;
        executor.execute(() -> {
            try {
                socket = new Socket();
                if (protector != null) protector.protect(socket);
                socket.connect(new InetSocketAddress(proxyHost, proxyPort), 5000);
                in = socket.getInputStream();
                out = socket.getOutputStream();

                if (performSocks5Handshake()) {
                    startRelaying();
                } else {
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
        
        response = new byte[10]; // Success response is 10 bytes for IPv4
        int read = in.read(response);
        return read >= 2 && response[1] == 0x00;
    }

    private void startRelaying() {
        executor.execute(() -> {
            byte[] buffer = new byte[16384];
            try {
                int length;
                while ((length = in.read(buffer)) != -1) {
                    if (callback != null) callback.onDataReceived(buffer, length);
                }
            } catch (IOException e) {
                Log.d(TAG, "Relay closed: " + e.getMessage());
            } finally {
                close();
            }
        });
    }

    public void send(byte[] data, int length) {
        executor.execute(() -> {
            try {
                if (out != null) {
                    out.write(data, 0, length);
                    out.flush();
                }
            } catch (IOException e) {
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
