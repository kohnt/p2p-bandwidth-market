package com.p2p.bandwidthmarket.core;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A simple SOCKS5 Proxy Server implementation that tracks bytes transferred.
 */
public class ProxyServer {
    private static final String TAG = "ProxyServer";
    private final int port;
    private ServerSocket serverSocket;
    private boolean running = false;
    private ExecutorService threadPool;
    private final AtomicLong totalBytesTransferred = new AtomicLong(0);
    private long byteLimit = Long.MAX_VALUE;

    public interface ProxyCallback {
        void onBytesTransferred(long bytes);
    }

    private ProxyCallback callback;

    public ProxyServer(int port) {
        this.port = port;
    }

    public synchronized void start(ProxyCallback callback) {
        if (running) return;
        
        this.callback = callback;
        this.running = true;
        this.threadPool = Executors.newCachedThreadPool();
        
        this.threadPool.execute(() -> {
            try {
                serverSocket = new ServerSocket(port);
                serverSocket.setReuseAddress(true);
                Log.i(TAG, "Proxy Server started on port " + port);
                while (running) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        if (running) {
                            threadPool.execute(() -> handleClient(clientSocket));
                        } else {
                            clientSocket.close();
                        }
                    } catch (IOException e) {
                        if (running) Log.e(TAG, "Accept error: " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                Log.e(TAG, "Proxy Server failed to start: " + e.getMessage());
            } finally {
                stop();
            }
        });
    }

    public synchronized void stop() {
        if (!running) return;
        
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            Log.e(TAG, "Error closing proxy server: " + e.getMessage());
        }
        
        if (threadPool != null) {
            threadPool.shutdownNow();
            threadPool = null;
        }
        Log.i(TAG, "Proxy Server stopped");
    }

    private boolean preAuthMode = true;
    private final java.util.Set<String> ec2Whitelist = new java.util.HashSet<>(java.util.Arrays.asList("ec2.amazonaws.com", "1.2.3.4")); // Example IPs
    private final java.util.Set<String> authorizedClients = new java.util.HashSet<>();

    public void setPreAuthMode(boolean enabled) {
        this.preAuthMode = enabled;
    }

    public void authorizeClient(String ip) {
        authorizedClients.add(ip);
        Log.i(TAG, "Client authorized: " + ip);
    }

    public void setByteLimit(long limit) {
        this.byteLimit = limit;
        Log.i(TAG, "Byte limit set to: " + limit);
    }

    private void handleClient(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();
        try (InputStream in = clientSocket.getInputStream();
             OutputStream out = clientSocket.getOutputStream()) {
            
            byte[] buf = new byte[1024];
            int read = in.read(buf);
            if (read < 2 || buf[0] != 0x05) return;
            
            out.write(new byte[]{0x05, 0x00});
            
            read = in.read(buf);
            if (read < 4) return;
            
            byte cmd = buf[1];
            int addrType = buf[3];
            int offset = 4;
            String host;
            int targetPort;

            if (addrType == 0x01) { // IPv4
                host = String.format("%d.%d.%d.%d", buf[offset] & 0xFF, buf[offset+1] & 0xFF, buf[offset+2] & 0xFF, buf[offset+3] & 0xFF);
                offset += 4;
            } else if (addrType == 0x03) { // Domain Name
                int len = buf[offset] & 0xFF;
                host = new String(buf, offset + 1, len);
                offset += len + 1;
            } else {
                return;
            }
            targetPort = ((buf[offset] & 0xFF) << 8) | (buf[offset+1] & 0xFF);

            // Pre-auth whitelist check
            if (preAuthMode && !authorizedClients.contains(clientIp)) {
                boolean isWhitelisted = false;
                for (String entry : ec2Whitelist) {
                    if (host.contains(entry)) {
                        isWhitelisted = true;
                        break;
                    }
                }
                if (!isWhitelisted) {
                    Log.w(TAG, "Blocked unauthorized request from " + clientIp + " to " + host);
                    return;
                }
            }

            if (cmd == 0x01) { // CONNECT
                handleConnect(host, targetPort, in, out);
            } else if (cmd == 0x03) { // UDP ASSOCIATE
                handleUdpAssociate(out);
            }

        } catch (IOException e) {
            Log.e(TAG, "Proxy connection error: " + e.getMessage());
        } finally {
            try { clientSocket.close(); } catch (IOException ignored) {}
        }
    }

    private void handleConnect(String host, int targetPort, InputStream in, OutputStream out) throws IOException {
        Log.d(TAG, "TCP Proxy to " + host + ":" + targetPort);
        try (Socket targetSocket = new Socket()) {
            try {
                targetSocket.connect(new java.net.InetSocketAddress(host, targetPort), 10000);
            } catch (IOException e) {
                Log.e(TAG, "Connection failed to " + host + ": " + e.getMessage());
                out.write(new byte[]{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); // 0x04 = Host unreachable
                return;
            }
            
            out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
            InputStream targetIn = targetSocket.getInputStream();
            OutputStream targetOut = targetSocket.getOutputStream();
            
            Thread t = new Thread(() -> {
                try { pipe(in, targetOut); } catch (IOException ignored) {}
            });
            t.start();
            
            try {
                pipe(targetIn, out);
            } catch (IOException e) {
                Log.d(TAG, "Pipe closed: " + e.getMessage());
            } finally {
                t.interrupt();
            }
        }
    }

    private void handleUdpAssociate(OutputStream out) throws IOException {
        Log.d(TAG, "UDP Associate requested");
        // In a real SOCKS5 server, we'd open a UDP socket and return its port.
        // For the demo, we'll return a success response and simplify the relay.
        out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
        // SOCKS5 UDP relay logic would go here
    }

    private void pipe(InputStream src, OutputStream dest) throws IOException {
        byte[] buffer = new byte[16384];
        int bytesRead;
        while (running && (bytesRead = src.read(buffer)) != -1) {
            long current = totalBytesTransferred.addAndGet(bytesRead);
            if (current > byteLimit) {
                Log.w(TAG, "Byte limit exceeded! (" + current + " > " + byteLimit + ")");
                stop(); // Immediate kill for all connections in this session
                throw new IOException("Byte limit exceeded");
            }
            dest.write(buffer, 0, bytesRead);
            if (callback != null) callback.onBytesTransferred(bytesRead);
        }
    }

    public long getTotalBytesTransferred() {
        return totalBytesTransferred.get();
    }
}
