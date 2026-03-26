package com.example.p2pdata.ui;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.example.p2pdata.R;
import com.example.p2pdata.model.BootstrapPayload;
import com.example.p2pdata.nfc.NfcBootstrap;
import com.example.p2pdata.wifi.WifiConnector;

public class RequesterActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {
    private TextView status;
    private NfcAdapter nfcAdapter;
    private WifiConnector connector;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_requester);
        status = findViewById(R.id.requester_status);
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        connector = new WifiConnector();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter != null) {
            int flags = NfcAdapter.FLAG_READER_NFC_A
                    | NfcAdapter.FLAG_READER_NFC_B
                    | NfcAdapter.FLAG_READER_NFC_F
                    | NfcAdapter.FLAG_READER_NFC_V
                    | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK;
            nfcAdapter.enableReaderMode(this, this, flags, null);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) {
            nfcAdapter.disableReaderMode(this);
        }
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        BootstrapPayload p = NfcBootstrap.parseFromTag(tag);
        if (p == null) {
            runOnUiThread(() -> status.setText(R.string.connect_status_failed));
            return;
        }
        runOnUiThread(() -> status.setText(R.string.connect_status_connecting));
        connector.connect(this, p.ssid, p.password, new WifiConnector.Callback() {
            @Override
            public void onConnected() {
                runOnUiThread(() -> status.setText(R.string.connect_status_connected));
            }

            @Override
            public void onFailed(String reason) {
                runOnUiThread(() -> {
                    status.setText(R.string.connect_status_failed);
                    new AlertDialog.Builder(RequesterActivity.this)
                            .setMessage("Failed to connect. SSID: " + p.ssid)
                            .setPositiveButton("OK", null)
                            .show();
                });
            }
        });
    }
}
