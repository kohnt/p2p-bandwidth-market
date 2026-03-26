package com.example.p2pdata;

import android.content.Intent;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.nio.charset.Charset;
import java.util.Locale;

public class MainActivity extends AppCompatActivity {
    private NfcAdapter nfcAdapter;
    private TextView statusText;
    private Button btnEnableNfc;
    private Button btnEnableSharing;

    private final NfcAdapter.ReaderCallback readerCallback = new NfcAdapter.ReaderCallback() {
        @Override
        public void onTagDiscovered(Tag tag) {
            String text = readTextFromTag(tag);
            runOnUiThread(() -> {
                if (text != null) {
                    statusText.setText("Tag: " + text);
                } else {
                    statusText.setText("Tag detected");
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        statusText = findViewById(R.id.status_text);
        btnEnableNfc = findViewById(R.id.btn_enable_nfc);
        btnEnableSharing = findViewById(R.id.btn_enable_sharing);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        updateNfcStatus();

        btnEnableNfc.setOnClickListener(v -> {
            if (nfcAdapter == null) {
                statusText.setText("NFC not supported");
                return;
            }
            if (!nfcAdapter.isEnabled()) {
                startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
            } else {
                statusText.setText("NFC is already on");
            }
        });

        btnEnableSharing.setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT < 29) {
                try {
                    startActivity(new Intent(Settings.ACTION_NFCSHARING_SETTINGS));
                } catch (Exception e) {
                    showInfoDialog("Sharing settings not available on this device.");
                }
            } else {
                showInfoDialog("NFC peer-to-peer is not available on this Android version. The app will use NFC to initiate and then switch to a nearby connection for data transfer.");
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateNfcStatus();
        if (nfcAdapter != null) {
            int flags = NfcAdapter.FLAG_READER_NFC_A
                    | NfcAdapter.FLAG_READER_NFC_B
                    | NfcAdapter.FLAG_READER_NFC_F
                    | NfcAdapter.FLAG_READER_NFC_V
                    | NfcAdapter.FLAG_READER_NFC_BARCODE
                    | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;
            nfcAdapter.enableReaderMode(this, readerCallback, flags, null);
            if (Build.VERSION.SDK_INT < 29) {
                NdefMessage msg = createBootstrapNdefMessage();
                try {
                    nfcAdapter.setNdefPushMessage(msg, this);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) {
            nfcAdapter.disableReaderMode(this);
            if (Build.VERSION.SDK_INT < 29) {
                try {
                    nfcAdapter.setNdefPushMessage(null, this);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private void updateNfcStatus() {
        if (nfcAdapter == null) {
            statusText.setText("NFC not supported");
        } else if (!nfcAdapter.isEnabled()) {
            statusText.setText("NFC is off");
        } else {
            statusText.setText("NFC is on");
        }
    }

    private void showInfoDialog(String message) {
        new AlertDialog.Builder(this)
                .setTitle("Sharing")
                .setMessage(message)
                .setPositiveButton("OK", null)
                .show();
    }

    private NdefMessage createBootstrapNdefMessage() {
        String payload = "p2p:init";
        NdefRecord textRecord = createTextRecord(payload, Locale.ENGLISH);
        return new NdefMessage(new NdefRecord[]{textRecord});
    }

    private static NdefRecord createTextRecord(String text, Locale locale) {
        byte[] langBytes = locale.getLanguage().getBytes(Charset.forName("US-ASCII"));
        byte[] textBytes = text.getBytes(Charset.forName("UTF-8"));
        int langLength = langBytes.length;
        int textLength = textBytes.length;
        byte[] payload = new byte[1 + langLength + textLength];
        payload[0] = (byte) langLength;
        System.arraycopy(langBytes, 0, payload, 1, langLength);
        System.arraycopy(textBytes, 0, payload, 1 + langLength, textLength);
        return new NdefRecord(NdefRecord.TNF_WELL_KNOWN, NdefRecord.RTD_TEXT, new byte[0], payload);
    }

    private String readTextFromTag(Tag tag) {
        try {
            Ndef ndef = Ndef.get(tag);
            if (ndef == null) return null;
            ndef.connect();
            NdefMessage message = ndef.getNdefMessage();
            ndef.close();
            if (message == null || message.getRecords().length == 0) return null;
            NdefRecord record = message.getRecords()[0];
            if (record.getTnf() == NdefRecord.TNF_WELL_KNOWN && java.util.Arrays.equals(record.getType(), NdefRecord.RTD_TEXT)) {
                byte[] payload = record.getPayload();
                int langLength = payload[0] & 0x3F;
                int textLength = payload.length - 1 - langLength;
                return new String(payload, 1 + langLength, textLength, Charset.forName("UTF-8"));
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}
