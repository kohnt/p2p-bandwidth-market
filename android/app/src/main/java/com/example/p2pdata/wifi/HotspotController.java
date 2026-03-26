package com.example.p2pdata.wifi;

import android.content.Context;
import android.net.wifi.WifiManager;
import android.os.Build;

public class HotspotController {
    public interface Callback {
        void onStarted(String ssid, String password);
        void onFailed(String reason);
    }

    private WifiManager.LocalOnlyHotspotReservation reservation;

    public void startLocalOnlyHotspot(Context context, Callback cb) {
        if (Build.VERSION.SDK_INT < 26) {
            cb.onFailed("Not supported");
            return;
        }
        WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        try {
            wifi.startLocalOnlyHotspot(new WifiManager.LocalOnlyHotspotCallback() {
                @Override
                public void onStarted(WifiManager.LocalOnlyHotspotReservation r) {
                    reservation = r;
                    if (r.getWifiConfiguration() != null) {
                        String ssid = r.getWifiConfiguration().SSID;
                        String pass = r.getWifiConfiguration().preSharedKey;
                        cb.onStarted(ssid, pass);
                    } else {
                        cb.onFailed("No configuration");
                    }
                }

                @Override
                public void onFailed(int reason) {
                    cb.onFailed("Failed: " + reason);
                }
            }, null);
        } catch (Exception e) {
            cb.onFailed("Exception");
        }
    }

    public void stop() {
        if (reservation != null) {
            try {
                reservation.close();
            } catch (Exception ignored) {
            }
            reservation = null;
        }
    }
}
