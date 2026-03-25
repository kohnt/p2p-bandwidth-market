package com.p2p.bandwidthmarket.core;

import android.app.Activity;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class NfcReader implements NfcAdapter.ReaderCallback {
    private static final String TAG = "NfcReader";
    private final NfcAdapter nfcAdapter;
    private final Activity activity;

    public interface ReaderCallback {
        void onTokenSent(String response);
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
            nfcAdapter.enableReaderMode(activity, this, 
                NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, options);
        }
    }

    public void stopReading() {
        if (nfcAdapter != null) {
            nfcAdapter.disableReaderMode(activity);
        }
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep != null) {
            try {
                isoDep.connect();
                // 1. Select AID
                byte[] selectCommand = {
                    (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x07,
                    (byte) 0xF0, (byte) 0x39, (byte) 0x41, (byte) 0x48, (byte) 0x14, (byte) 0x81, (byte) 0x00, (byte) 0x00
                };
                byte[] response = isoDep.transceive(selectCommand);
                
                // 2. Send Token
                byte[] tokenCommand = "TOKEN_12345".getBytes(StandardCharsets.UTF_8);
                response = isoDep.transceive(tokenCommand);
                
                String result = new String(response, StandardCharsets.UTF_8);
                Log.d(TAG, "Response from Seller: " + result);
                if (callback != null) callback.onTokenSent(result);
                
                isoDep.close();
            } catch (IOException e) {
                Log.e(TAG, "NFC Transceive error: " + e.getMessage());
                if (callback != null) callback.onError(e.getMessage());
            }
        }
    }
}
