package com.p2p.bandwidthmarket.core;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class NfcReader {
    private static final String TAG = "NfcReader";
    private final NfcAdapter nfcAdapter;
    private final Activity activity;

    public interface ReaderCallback {
        void onHotspotInfoReceived(String ssid, String passphrase, String proxyIp);
        void onError(String error);
    }

    private ReaderCallback callback;

    public NfcReader(Activity activity) {
        this.activity = activity;
        this.nfcAdapter = NfcAdapter.getDefaultAdapter(activity);
    }

    public void startReading(ReaderCallback callback) {
        this.callback = callback;
        if (nfcAdapter != null) {
            Bundle options = new Bundle();
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            nfcAdapter.enableReaderMode(activity, tag -> {
                IsoDep isoDep = IsoDep.get(tag);
                if (isoDep != null) {
                    try {
                        isoDep.connect();
                        // 1. Select AID
                        byte[] selectCommand = {
                            (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x07,
                            (byte) 0xF0, (byte) 0x39, (byte) 0x41, (byte) 0x48, (byte) 0x14, (byte) 0x81, (byte) 0x00, (byte) 0x00
                        };
                        isoDep.transceive(selectCommand);

                        // 2. Request Hotspot Info
                        byte[] getCommand = "GET_CONFIG".getBytes(StandardCharsets.UTF_8);
                        byte[] response = isoDep.transceive(getCommand);

                        String result = new String(response, StandardCharsets.UTF_8);
                        Log.d(TAG, "Received from Seller: " + result);

                        // Parse format: SSID:password:proxyIp
                        String[] parts = result.split(":");
                        if (parts.length >= 3) {
                            if (this.callback != null) {
                                this.callback.onHotspotInfoReceived(parts[0], parts[1], parts[2]);
                            }
                        }

                        isoDep.close();
                    } catch (IOException e) {
                        Log.e(TAG, "NFC Transceive error: " + e.getMessage());
                        if (this.callback != null) this.callback.onError(e.getMessage());
                    }
                }
            }, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, options);
        }
    }

    public void stopReading() {
        if (nfcAdapter != null) {
            nfcAdapter.disableReaderMode(activity);
        }
    }
}
