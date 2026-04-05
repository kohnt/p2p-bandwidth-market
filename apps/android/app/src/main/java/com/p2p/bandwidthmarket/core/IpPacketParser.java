package com.p2p.bandwidthmarket.core;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * IpPacketParser parses raw byte buffers into usable IP/TCP/UDP information.
 */
public class IpPacketParser {
    public static class PacketInfo {
        public int protocol; // TCP=6, UDP=17
        public String destinationAddress;
        public int destinationPort;
        public int sourcePort;
        public int payloadOffset;
        public int payloadLength;
        public byte tcpFlags;  // TCP flags byte (offset 13 in TCP header)
        public long tcpSeq;    // TCP sequence number from the packet
    }

    public static PacketInfo parse(ByteBuffer buffer, int length) {
        if (length < 20) return null; // Minimum IPv4 header length

        PacketInfo info = new PacketInfo();
        
        // Byte 0: Version (4 bits) + IHL (4 bits)
        byte versionIhl = buffer.get(0);
        int version = (versionIhl >> 4) & 0x0F;
        int ihl = (versionIhl & 0x0F) * 4;
        
        if (version != 4) return null; // Only IPv4 for now

        // Byte 9: Protocol
        info.protocol = buffer.get(9) & 0xFF;

        // Bytes 12-15: Source Address (optional)
        // Bytes 16-19: Destination Address
        byte[] destAddr = new byte[4];
        buffer.position(16);
        buffer.get(destAddr);
        try {
            info.destinationAddress = InetAddress.getByAddress(destAddr).getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }

        // Parse TCP/UDP headers
        if (info.protocol == 6) { // TCP
            if (length < ihl + 20) return null; // Minimum TCP header
            buffer.position(ihl);
            info.sourcePort = buffer.getShort() & 0xFFFF;
            info.destinationPort = buffer.getShort() & 0xFFFF;
            info.tcpSeq = buffer.getInt() & 0xFFFFFFFFL; // sequence number (bytes ihl+4..ihl+7)
            // TCP header length is 4 bits in byte 12
            int dataOffset = ((buffer.get(ihl + 12) >> 4) & 0x0F) * 4;
            info.tcpFlags = buffer.get(ihl + 13);
            info.payloadOffset = ihl + dataOffset;
            info.payloadLength = length - info.payloadOffset;
        } else if (info.protocol == 17) { // UDP
            if (length < ihl + 8) return null; // UDP header
            buffer.position(ihl);
            info.sourcePort = buffer.getShort() & 0xFFFF;
            info.destinationPort = buffer.getShort() & 0xFFFF;
            info.payloadOffset = ihl + 8;
            info.payloadLength = (buffer.getShort() & 0xFFFF) - 8;
        } else {
            return null; // Unsupported protocol
        }

        return info;
    }
}
