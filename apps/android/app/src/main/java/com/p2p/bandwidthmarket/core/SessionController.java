package com.p2p.bandwidthmarket.core;

import android.util.Log;
import java.util.Timer;
import java.util.TimerTask;

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

    public SessionController(ProxyServer proxyServer, UsageTracker usageTracker) {
        this.proxyServer = proxyServer;
        this.usageTracker = usageTracker;
    }

    public void startSession(long quotaBytes) {
        this.quotaBytes = quotaBytes;
        this.sessionActive = true;
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
        
        long used = usageTracker.getBytesUsed();
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
        Log.i(TAG, "Session terminated");
    }

    public boolean isSessionActive() {
        return sessionActive;
    }
}
