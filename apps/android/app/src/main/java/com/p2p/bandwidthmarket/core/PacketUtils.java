package com.p2p.bandwidthmarket.core;

import java.nio.ByteBuffer;

/**
 * PacketUtils provides utility functions for crafting raw IP/TCP packets.
 */
public class PacketUtils {
    public static int calculateChecksum(byte[] buf, int offset, int length) {
        int sum = 0;
        int i = offset;
        while (length > 1) {
            sum += ((buf[i] & 0xFF) << 8) | (buf[i + 1] & 0xFF);
            i += 2;
            length -= 2;
        }
        if (length > 0) {
            sum += (buf[i] & 0xFF) << 8;
        }
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return ~sum & 0xFFFF;
    }

    public static byte[] createTcpPacket(String srcAddr, int srcPort, String dstAddr, int dstPort, long seq, long ack, byte flags, byte[] payload) {
        int payloadLen = payload != null ? payload.length : 0;
        int ipHeaderLen = 20;
        int tcpHeaderLen = 20;
        int totalLen = ipHeaderLen + tcpHeaderLen + payloadLen;
        
        byte[] packet = new byte[totalLen];
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        
        // --- IP Header ---
        buffer.put((byte) 0x45); // Version 4, IHL 5 (20 bytes)
        buffer.put((byte) 0x00); // TOS
        buffer.putShort((short) totalLen);
        buffer.putShort((short) 0x0000); // ID
        buffer.putShort((short) 0x4000); // Flags: DF
        buffer.put((byte) 64); // TTL
        buffer.put((byte) 6); // Protocol: TCP
        buffer.putShort((short) 0); // Placeholder for Checksum
        
        String[] srcParts = srcAddr.split("\\.");
        for (String part : srcParts) buffer.put((byte) Integer.parseInt(part));
        String[] dstParts = dstAddr.split("\\.");
        for (String part : dstParts) buffer.put((byte) Integer.parseInt(part));
        
        // IP Checksum
        int ipChecksum = calculateChecksum(packet, 0, ipHeaderLen);
        buffer.putShort(10, (short) ipChecksum);
        
        // --- TCP Header ---
        buffer.position(ipHeaderLen);
        buffer.putShort((short) srcPort);
        buffer.putShort((short) dstPort);
        buffer.putInt((int) seq);
        buffer.putInt((int) ack);
        buffer.put((byte) 0x50); // Data offset (5 words = 20 bytes)
        buffer.put(flags);
        buffer.putShort((short) 65535); // Window size
        buffer.putShort((short) 0); // Placeholder for Checksum
        buffer.putShort((short) 0); // Urgent pointer
        
        // Payload
        if (payload != null) {
            buffer.position(ipHeaderLen + tcpHeaderLen);
            buffer.put(payload);
        }
        
        // TCP Checksum (Pseudo-header + TCP Header + Payload)
        byte[] pseudoHeader = new byte[12 + tcpHeaderLen + payloadLen];
        ByteBuffer pseudoBuffer = ByteBuffer.wrap(pseudoHeader);
        for (String part : srcParts) pseudoBuffer.put((byte) Integer.parseInt(part));
        for (String part : dstParts) pseudoBuffer.put((byte) Integer.parseInt(part));
        pseudoBuffer.put((byte) 0);
        pseudoBuffer.put((byte) 6); // Protocol
        pseudoBuffer.putShort((short) (tcpHeaderLen + payloadLen));
        
        pseudoBuffer.put(packet, ipHeaderLen, tcpHeaderLen);
        if (payload != null) {
            pseudoBuffer.put(payload);
        }
        
        int tcpChecksum = calculateChecksum(pseudoHeader, 0, pseudoHeader.length);
        buffer.putShort(ipHeaderLen + 16, (short) tcpChecksum);
        
        return packet;
    }
    public static String parseDnsQuery(byte[] payload) {
        if (payload == null || payload.length < 12) return null;
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        buffer.position(12); // Skip header
        
        StringBuilder domain = new StringBuilder();
        int len;
        while ((len = buffer.get() & 0xFF) > 0) {
            for (int i = 0; i < len; i++) {
                domain.append((char) buffer.get());
            }
            domain.append('.');
        }
        if (domain.length() > 0) {
            domain.setLength(domain.length() - 1);
        }
        return domain.toString();
    }

    public static byte[] createDnsResponse(byte[] query, String fakeIp) {
        if (query == null || query.length < 12) return null;
        
        ByteBuffer queryBuffer = ByteBuffer.wrap(query);
        short id = queryBuffer.getShort();
        
        // Find end of QNAME
        int pos = 12;
        while (query[pos] != 0) pos += (query[pos] & 0xFF) + 1;
        int questionLen = pos + 1 - 12 + 4;
        
        int totalLen = 12 + questionLen + 16; // Header + Question + Answer (Offset, Type, Class, TTL, Len, IP)
        byte[] response = new byte[totalLen];
        ByteBuffer buffer = ByteBuffer.wrap(response);
        
        // Header
        buffer.putShort(id);
        buffer.putShort((short) 0x8180); // Response, No Error
        buffer.putShort((short) 1); // QDCOUNT
        buffer.putShort((short) 1); // ANCOUNT
        buffer.putShort((short) 0); // NSCOUNT
        buffer.putShort((short) 0); // ARCOUNT
        
        // Question
        buffer.put(query, 12, questionLen);
        
        // Answer
        buffer.putShort((short) 0xC00C); // Pointer to QNAME
        buffer.putShort((short) 1); // Type A
        buffer.putShort((short) 1); // Class IN
        buffer.putInt(60); // TTL
        buffer.putShort((short) 4); // RDLENGTH
        String[] parts = fakeIp.split("\\.");
        for (String part : parts) buffer.put((byte) Integer.parseInt(part));
        
        return response;
    }

    public static byte[] createUdpPacket(String srcAddr, int srcPort, String dstAddr, int dstPort, byte[] payload) {
        int payloadLen = payload != null ? payload.length : 0;
        int ipHeaderLen = 20;
        int udpHeaderLen = 8;
        int totalLen = ipHeaderLen + udpHeaderLen + payloadLen;
        
        byte[] packet = new byte[totalLen];
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        
        buffer.put((byte) 0x45);
        buffer.put((byte) 0x00);
        buffer.putShort((short) totalLen);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0x4000);
        buffer.put((byte) 64);
        buffer.put((byte) 17); // UDP
        buffer.putShort((short) 0);
        
        String[] srcParts = srcAddr.split("\\.");
        for (String part : srcParts) buffer.put((byte) Integer.parseInt(part));
        String[] dstParts = dstAddr.split("\\.");
        for (String part : dstParts) buffer.put((byte) Integer.parseInt(part));
        
        int ipChecksum = calculateChecksum(packet, 0, ipHeaderLen);
        buffer.putShort(10, (short) ipChecksum);
        
        buffer.position(ipHeaderLen);
        buffer.putShort((short) srcPort);
        buffer.putShort((short) dstPort);
        buffer.putShort((short) (udpHeaderLen + payloadLen));
        buffer.putShort((short) 0); // UDP Checksum (optional/0)
        
        if (payload != null) {
            buffer.position(ipHeaderLen + udpHeaderLen);
            buffer.put(payload);
        }
        
        return packet;
    }
}
