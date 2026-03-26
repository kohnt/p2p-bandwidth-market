package com.example.p2pdata.wifi;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.os.Build;

public class WifiConnector {
    public interface Callback {
        void onConnected();
        void onFailed(String reason);
    }

    public void connect(Context context, String ssid, String password, Callback cb) {
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                WifiNetworkSpecifier spec = new WifiNetworkSpecifier.Builder()
                        .setSsid(ssid)
                        .setWpa2Passphrase(password)
                        .build();
                NetworkRequest request = new NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                        .setNetworkSpecifier(spec)
                        .build();
                ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
                cm.requestNetwork(request, new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(Network network) {
                        if (Build.VERSION.SDK_INT >= 23) {
                            cm.bindProcessToNetwork(network);
                        }
                        cb.onConnected();
                    }

                    @Override
                    public void onUnavailable() {
                        cb.onFailed("Unavailable");
                    }

                    @Override
                    public void onLost(Network network) {
                    }
                });
            } catch (Exception e) {
                cb.onFailed("Exception");
            }
        } else {
            try {
                WifiManager wm = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
                if (!wm.isWifiEnabled()) {
                    wm.setWifiEnabled(true);
                }
                WifiConfiguration conf = new WifiConfiguration();
                conf.SSID = "\"" + ssid + "\"";
                conf.preSharedKey = "\"" + password + "\"";
                conf.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
                int netId = wm.addNetwork(conf);
                if (netId == -1) {
                    cb.onFailed("Add network failed");
                    return;
                }
                wm.disconnect();
                boolean enabled = wm.enableNetwork(netId, true);
                boolean reconnected = wm.reconnect();
                if (enabled && reconnected) {
                    cb.onConnected();
                } else {
                    cb.onFailed("Connect failed");
                }
            } catch (Exception e) {
                cb.onFailed("Exception");
            }
        }
    }
}
