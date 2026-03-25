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
    private final ExecutorService threadPool = Executors.newCachedThreadPool();
    private final AtomicLong totalBytesTransferred = new AtomicLong(0);

    public interface ProxyCallback {
        void onBytesTransferred(long bytes);
    }

    private ProxyCallback callback;

    public ProxyServer(int port) {
        this.port = port;
    }

    public void start(ProxyCallback callback) {
        this.callback = callback;
        running = true;
        threadPool.execute(() -> {
            try {
                serverSocket = new ServerSocket(port);
                Log.i(TAG, "Proxy Server started on port " + port);
                while (running) {
                    Socket clientSocket = serverSocket.accept();
                    threadPool.execute(() -> handleClient(clientSocket));
                }
            } catch (IOException e) {
                if (running) {
                    Log.e(TAG, "Proxy Server error: " + e.getMessage());
                }
            }
        });
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException e) {
            Log.e(TAG, "Error closing proxy server: " + e.getMessage());
        }
        threadPool.shutdownNow();
    }

    private void handleClient(Socket clientSocket) {
        try (InputStream in = clientSocket.getInputStream();
             OutputStream out = clientSocket.getOutputStream()) {
            
            byte[] buf = new byte[1024];
            int read = in.read(buf);
            if (read < 2 || buf[0] != 0x05) return;
            
            out.write(new byte[]{0x05, 0x00});
            
            read = in.read(buf);
            if (read < 4 || buf[1] != 0x01) return; // Command: Connect

            String host;
            int port;
            int addrType = buf[3];
            int offset = 4;

            if (addrType == 0x01) { // IPv4
                host = String.format("%d.%d.%d.%d", buf[offset] & 0xFF, buf[offset+1] & 0xFF, buf[offset+2] & 0xFF, buf[offset+3] & 0xFF);
                offset += 4;
            } else if (addrType == 0x03) { // Domain Name
                int len = buf[offset] & 0xFF;
                host = new String(buf, offset + 1, len);
                offset += len + 1;
            } else {
                return; // Unsupported address type
            }

            port = ((buf[offset] & 0xFF) << 8) | (buf[offset+1] & 0xFF);

            Log.d(TAG, "Proxying to " + host + ":" + port);

            try (Socket targetSocket = new Socket(host, port)) {
                out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); // Success response
                
                InputStream targetIn = targetSocket.getInputStream();
                OutputStream targetOut = targetSocket.getOutputStream();

                threadPool.execute(() -> {
                    try { pipe(in, targetOut); } catch (IOException ignored) {}
                });
                pipe(targetIn, out);
            }

        } catch (IOException e) {
            Log.e(TAG, "Proxy connection error: " + e.getMessage());
        } finally {
            try { clientSocket.close(); } catch (IOException ignored) {}
        }
    }

    private void pipe(InputStream src, OutputStream dest) throws IOException {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while (running && (bytesRead = src.read(buffer)) != -1) {
            dest.write(buffer, 0, bytesRead);
            long total = totalBytesTransferred.addAndGet(bytesRead);
            if (callback != null) callback.onBytesTransferred(bytesRead);
        }
    }

    public long getTotalBytesTransferred() {
        return totalBytesTransferred.get();
    }
}
