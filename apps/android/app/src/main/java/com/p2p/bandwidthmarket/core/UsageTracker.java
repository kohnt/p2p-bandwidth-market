package com.p2p.bandwidthmarket.core;

import java.util.Locale;

public class UsageTracker {
    private long bytesUsed = 0;

    public void addBytes(long bytes) {
        bytesUsed += bytes;
    }

    public long getBytesUsed() {
        return bytesUsed;
    }

    public void reset() {
        bytesUsed = 0;
    }

    public String getFormattedUsage() {
        if (bytesUsed < 1024) return bytesUsed + " B";
        int exp = (int) (Math.log(bytesUsed) / Math.log(1024));
        char pre = "KMGTPE".charAt(exp - 1);
        return String.format(Locale.US, "%.1f %cB", bytesUsed / Math.pow(1024, exp), pre);
    }
}
