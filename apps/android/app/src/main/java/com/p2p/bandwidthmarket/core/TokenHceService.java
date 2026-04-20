package com.p2p.bandwidthmarket.core;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TokenHceService extends HostApduService {
    private static final String TAG = "TokenHceService";
    private static String cachedSsid = "OFFLINE";
    private static String cachedPassphrase = "OFFLINE";
    private static String cachedSellerToken = "";
    private static HotspotManager hotspotManager;

    public static void setHotspotConfig(String ssid, String passphrase, String sellerToken, HotspotManager manager) {
        cachedSsid = ssid;
        cachedPassphrase = passphrase;
        cachedSellerToken = sellerToken;
        hotspotManager = manager;
    }

    private static final byte[] SELECT_AID_COMMAND = {
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x07,
        (byte) 0xF0, (byte) 0x39, (byte) 0x41, (byte) 0x48, (byte) 0x14, (byte) 0x81, (byte) 0x00, (byte) 0x00
    };

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        if (isSelectAid(commandApdu)) {
            Log.d(TAG, "AID Selected");
            return new byte[]{(byte) 0x90, (byte) 0x00};
        }

        String message = new String(commandApdu, StandardCharsets.UTF_8);
        if ("GET_CONFIG".equals(message)) {
            // Format: SSID:passphrase:sellerToken:proxyIp
            // Buyer uses proxyIp:8080 as a SOCKS5 bootstrap to reach EC2
            // (LocalOnlyHotspot blocks direct internet; seller's proxy relays it).
            String ip = hotspotManager != null ? hotspotManager.getIpAddress() : "0.0.0.0";
            String config = cachedSsid + ":" + cachedPassphrase + ":" + cachedSellerToken + ":" + ip;
            Log.d(TAG, "Sending Config: " + config);
            return config.getBytes(StandardCharsets.UTF_8);
        }

        return "UNKNOWN_COMMAND".getBytes(StandardCharsets.UTF_8);
    }

    private boolean isSelectAid(byte[] commandApdu) {
        return commandApdu.length >= SELECT_AID_COMMAND.length &&
                Arrays.equals(Arrays.copyOf(commandApdu, SELECT_AID_COMMAND.length), SELECT_AID_COMMAND);
    }

    @Override
    public void onDeactivated(int reason) {
        Log.d(TAG, "Deactivated: " + reason);
    }
}
