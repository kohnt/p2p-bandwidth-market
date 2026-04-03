package com.p2p.bandwidthmarket.core;

import android.content.Intent;
import android.net.Network;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * MarketVpnService intercepts device traffic and forwards it to a SOCKS5 proxy.
 */
public class MarketVpnService extends VpnService implements Runnable {
    private static final String TAG = "MarketVpnService";
    private Thread thread;
    private ParcelFileDescriptor vpnInterface;
    private boolean running = false;
    private String proxyHost = "127.0.0.1";
    private int proxyPort = 1080;
    private static volatile Network underlyingNetwork;

    public static void setUnderlyingNetwork(Network network) {
        underlyingNetwork = network;
        Log.i("MarketVpnService", "Underlying network set: " + network);
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
            Log.i(TAG, "Underlying network at start: " + underlyingNetwork);
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
        long seq = 1000;
        long ack = 1000;
        String srcAddr;
        int srcPort;
        String dstAddr;
        int dstPort;
    }

    private final java.util.Map<String, SessionState> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.Map<String, String> ipToDomain = new java.util.concurrent.ConcurrentHashMap<>();
    private int nextFakeIp = 1;

    @Override
    public void run() {
        try {
            setupVpn();
            
            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
            
            ByteBuffer buffer = ByteBuffer.allocate(32768);
            
            while (running) {
                int length = in.read(buffer.array());
                if (length > 0) {
                    IpPacketParser.PacketInfo info = IpPacketParser.parse(buffer, length);
                    if (info != null) {
                        if (info.protocol == 6) { // TCP
                            handleTcpPacket(info, buffer, out);
                        } else if (info.protocol == 17 && info.destinationPort == 53) { // UDP DNS
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

    private void handleTcpPacket(IpPacketParser.PacketInfo info, ByteBuffer buffer, FileOutputStream out) throws IOException {
        String key = info.destinationAddress + ":" + info.destinationPort + "<-" + info.sourcePort;
        SessionState state = sessions.get(key);

        if (state == null) {
            state = new SessionState();
            state.srcAddr = "10.0.0.2"; // Local TUN address
            state.srcPort = info.sourcePort;
            
            String targetHost = ipToDomain.getOrDefault(info.destinationAddress, info.destinationAddress);
            state.dstAddr = info.destinationAddress;
            state.dstPort = info.destinationPort;
            
            state.relay = new SocksTcpRelay(proxyHost, proxyPort, targetHost, info.destinationPort);
            state.relay.setProtector(socket -> {
                if (underlyingNetwork != null) {
                    try {
                        underlyingNetwork.bindSocket(socket);
                        return true;
                    } catch (IOException e) {
                        Log.e(TAG, "bindSocket failed: " + e.getMessage());
                    }
                }
                boolean ok = protect(socket);
                Log.d(TAG, "protect() fallback = " + ok);
                return ok;
            });
            sessions.put(key, state);
            
            final SessionState finalState = state;
            state.relay.connect(new SocksTcpRelay.RelayCallback() {
                @Override
                public void onDataReceived(byte[] data, int length) {
                    try {
                        byte[] response = PacketUtils.createTcpPacket(
                            finalState.dstAddr, finalState.dstPort,
                            finalState.srcAddr, finalState.srcPort,
                            finalState.ack, finalState.seq,
                            (byte) 0x10, // ACK flag
                            data
                        );
                        out.write(response);
                        finalState.ack += length;
                    } catch (IOException e) {
                        Log.e(TAG, "Error writing to TUN: " + e.getMessage());
                    }
                }

                @Override
                public void onClosed() {
                    sessions.remove(key);
                }
            });
        }

        if (info.payloadLength > 0) {
            byte[] data = new byte[info.payloadLength];
            buffer.position(info.payloadOffset);
            buffer.get(data);
            state.relay.send(data, info.payloadLength);
            state.seq += info.payloadLength;
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
                out.write(packet);
                Log.d(TAG, "DNS Fake Response: " + domain + " -> " + fakeIp);
            }
        }
    }

    private void setupVpn() {
        Builder builder = new Builder();
        builder.setMtu(1400);
        builder.addAddress("10.0.0.2", 32);
        builder.addRoute("0.0.0.0", 0);
        builder.addDnsServer("8.8.8.8");
        builder.setSession("P2P Bandwidth Market");
        if (underlyingNetwork != null) {
            builder.setUnderlyingNetworks(new Network[]{underlyingNetwork});
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
}
