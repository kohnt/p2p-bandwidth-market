package com.p2p.bandwidthmarket.core;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

public class TokenHceService extends HostApduService {
    private static final String TAG = "TokenHceService";
    private static String cachedSsid = "OFFLINE";
    private static String cachedPassphrase = "OFFLINE";
    private static HotspotManager hotspotManager;
    /** Stable for this hotspot session; buyer uses it in EC2 redeem (no Wi‑Fi secret over NFC). */
    private static String sellerId;

    public static void setHotspotConfig(String ssid, String passphrase, HotspotManager manager) {
        if (sellerId == null || sellerId.isEmpty()) {
            sellerId = UUID.randomUUID().toString();
        }
        cachedSsid = ssid;
        cachedPassphrase = passphrase;
        hotspotManager = manager;
    }

    /** Call when hotspot stops so the next session gets a fresh seller_id. */
    public static void resetSession() {
        sellerId = null;
        cachedSsid = "OFFLINE";
        cachedPassphrase = "OFFLINE";
        hotspotManager = null;
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
            if (sellerId == null || sellerId.isEmpty()) {
                sellerId = UUID.randomUUID().toString();
            }
            String tapNonce = UUID.randomUUID().toString();
            // NFC carries only handshake material; Wi‑Fi + proxy + tunnel key come from EC2 redeem.
            String handshake = sellerId + "|" + tapNonce;
            Log.d(TAG, "Sending tap handshake: " + sellerId + "|" + tapNonce);
            return handshake.getBytes(StandardCharsets.UTF_8);
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
