package com.p2p.bandwidthmarket.protocol;

/**
 * Base class for tokens used in the bandwidth market.
 */
public class Token {
    private String id;
    private long value; // e.g., bytes of bandwidth
    private long expiry;

    public Token(String id, long value, long expiry) {
        this.id = id;
        this.value = value;
        this.expiry = expiry;
    }

    public String getId() { return id; }
    public long getValue() { return value; }
    public long getExpiry() { return expiry; }
}
