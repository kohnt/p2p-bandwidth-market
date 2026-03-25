package com.p2p.bandwidthmarket.core;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class TokenHceService extends HostApduService {
    private static final String TAG = "TokenHceService";
    
    // Command APDU for SELECT AID
    private static final byte[] SELECT_AID_COMMAND = {
        (byte) 0x00, // CLA
        (byte) 0xA4, // INS
        (byte) 0x04, // P1
        (byte) 0x00, // P2
        (byte) 0x07, // Lc (AID length)
        (byte) 0xF0, (byte) 0x39, (byte) 0x41, (byte) 0x48, (byte) 0x14, (byte) 0x81, (byte) 0x00, // AID: F0394148148100
        (byte) 0x00  // Le
    };

    private static final byte[] SELECT_RESPONSE_OK = {(byte) 0x90, (byte) 0x00};
    private static final byte[] SELECT_RESPONSE_FAIL = {(byte) 0x6A, (byte) 0x82};

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        if (Arrays.equals(SELECT_AID_COMMAND, commandApdu)) {
            Log.d(TAG, "AID Selected");
            return SELECT_RESPONSE_OK;
        }

        // Handle incoming token data
        String message = new String(commandApdu, StandardCharsets.UTF_8);
        Log.d(TAG, "Received APDU: " + message);
        
        // Return a response confirming receipt
        return "TOKEN_RECEIVED".getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void onDeactivated(int reason) {
        Log.d(TAG, "Deactivated: " + reason);
    }
}
