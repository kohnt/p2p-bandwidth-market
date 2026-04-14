package com.p2p.bandwidthmarket.core;

import android.util.Log;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.LongSupplier;

/**
 * SessionController monitors usage and terminates sessions when quotas are exhausted.
 */
public class SessionController {
    private static final String TAG = "SessionController";
    private final ProxyServer proxyServer;
    private final UsageTracker usageTracker;
    private long quotaBytes = 0;
    private boolean sessionActive = false;
    private Timer monitorTimer;
    private LongSupplier bytesSupplier;
    private Runnable onTerminate;

    public SessionController(ProxyServer proxyServer, UsageTracker usageTracker) {
        this.proxyServer = proxyServer;
        this.usageTracker = usageTracker;
    }

    public void startSession(long quotaBytes) {
        startSession(quotaBytes, usageTracker::getBytesUsed, null);
    }

    public void startSession(long quotaBytes, LongSupplier bytesSupplier, Runnable onTerminate) {
        this.quotaBytes = quotaBytes;
        this.sessionActive = true;
        this.bytesSupplier = bytesSupplier;
        this.onTerminate = onTerminate;
        usageTracker.reset();

        monitorTimer = new Timer();
        monitorTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                checkQuota();
            }
        }, 1000, 1000); // Poll every 1 second as per metering-spec.md

        Log.i(TAG, "Session started with quota: " + quotaBytes + " bytes");
    }

    private void checkQuota() {
        if (!sessionActive) return;

        long used = bytesSupplier.getAsLong();
        if (used >= quotaBytes) {
            Log.w(TAG, "Quota exhausted! Terminating session. Used: " + used + " / " + quotaBytes);
            terminateSession();
        }
    }

    public void terminateSession() {
        sessionActive = false;
        if (monitorTimer != null) {
            monitorTimer.cancel();
            monitorTimer = null;
        }
        proxyServer.stop(); // Hard kill for the demo
        if (onTerminate != null) {
            onTerminate.run();
            onTerminate = null;
        }
        Log.i(TAG, "Session terminated");
    }

    public boolean isSessionActive() {
        return sessionActive;
    }
}
