package com.p2p.bandwidthmarket.core;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.wifi.SoftApConfiguration;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import androidx.annotation.NonNull;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class HotspotManager {
    private static final String TAG = "HotspotManager";
    private final WifiManager wifiManager;
    private WifiManager.LocalOnlyHotspotReservation hotspotReservation;

    public interface HotspotCallback {
        void onStarted(String ssid, String passphrase);
        void onStopped();
        void onFailure(int errorCode);
    }

    public HotspotManager(Context context) {
        this.wifiManager = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
    }

    @SuppressLint("MissingPermission")
    public void startHotspot(final HotspotCallback callback) {
        if (wifiManager == null) {
            callback.onFailure(-1);
            return;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            wifiManager.startLocalOnlyHotspot(new WifiManager.LocalOnlyHotspotCallback() {
                @Override
                public void onStarted(WifiManager.LocalOnlyHotspotReservation reservation) {
                    super.onStarted(reservation);
                    hotspotReservation = reservation;

                    String ssid;
                    String passphrase;

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        SoftApConfiguration config = reservation.getSoftApConfiguration();
                        ssid = config.getSsid();
                        passphrase = config.getPassphrase();
                    } else {
                        WifiConfiguration config = reservation.getWifiConfiguration();
                        assert config != null;
                        ssid = config.SSID;
                        passphrase = config.preSharedKey;
                    }

                    Log.d(TAG, "Hotspot started: " + ssid);
                    callback.onStarted(ssid, passphrase);
                }

                @Override
                public void onStopped() {
                    super.onStopped();
                    hotspotReservation = null;
                    Log.d(TAG, "Hotspot stopped");
                    callback.onStopped();
                }

                @Override
                public void onFailed(int reason) {
                    super.onFailed(reason);
                    Log.e(TAG, "Hotspot failed: " + reason);
                    callback.onFailure(reason);
                }
            }, new Handler(Looper.getMainLooper()));
        }
    }

    public void stopHotspot() {
        if (hotspotReservation != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                hotspotReservation.close();
            }
            hotspotReservation = null;
        }
    }

    public boolean isHotspotActive() {
        return hotspotReservation != null;
    }

    /**
     * Gets the IP address of the Hotspot interface (usually starting with "ap" or "wlan").
     */
    public String getIpAddress() {
        String apIp = null;           // ap0, softap0 — dedicated hotspot interface
        String hotspotSubnetIp = null; // 192.168.49.x or 192.168.43.x — known hotspot subnets
        String gatewayIp = null;      // any non-cellular .1 address — hotspot gateway heuristic
        String wlanFallback = null;   // seller's upstream WiFi IP — last resort

        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface intf = interfaces.nextElement();
                String name = intf.getName().toLowerCase();
                Enumeration<InetAddress> addrs = intf.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    Log.d(TAG, "Interface " + name + " → " + addr.getHostAddress());
                    if (addr.isLoopbackAddress() || !(addr instanceof Inet4Address)) continue;
                    String ip = addr.getHostAddress();
                    if (name.startsWith("ap") || name.startsWith("softap") || name.startsWith("wlan_ap")) {
                        apIp = ip;
                    } else if (ip.startsWith("192.168.49.") || ip.startsWith("192.168.43.")) {
                        hotspotSubnetIp = ip;
                    } else if (!name.startsWith("wlan") && !name.startsWith("swlan")
                            && !name.startsWith("rmnet") && !name.startsWith("dummy")
                            && ip.endsWith(".1")) {
                        // Hotspot gateways are almost always the .1 of their subnet.
                        // This catches Huawei/OEM devices that use non-standard interface names.
                        gatewayIp = ip;
                    } else if ((name.startsWith("wlan") || name.startsWith("swlan")) && wlanFallback == null) {
                        wlanFallback = ip;
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error getting IP: " + e.getMessage());
        }

        if (apIp != null) { Log.i(TAG, "Hotspot IP (ap iface): " + apIp); return apIp; }
        if (hotspotSubnetIp != null) { Log.i(TAG, "Hotspot IP (subnet match): " + hotspotSubnetIp); return hotspotSubnetIp; }
        if (gatewayIp != null) { Log.i(TAG, "Hotspot IP (gateway heuristic): " + gatewayIp); return gatewayIp; }
        if (wlanFallback != null) { Log.i(TAG, "Hotspot IP (wlan fallback): " + wlanFallback); return wlanFallback; }
        Log.w(TAG, "Hotspot IP: using hardcoded default 192.168.49.1");
        return "192.168.49.1";
    }
}
