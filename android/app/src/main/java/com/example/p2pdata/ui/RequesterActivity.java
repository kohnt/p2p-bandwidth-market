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
    private String lastSsid;
    private String lastPassword;

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
                    | NfcAdapter.FLAG_READER_NFC_V;
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
        if (p == null || p.ssid == null || p.ssid.isEmpty() || p.password == null || p.password.isEmpty()) {
            runOnUiThread(this::showCredentialsDialog);
            return;
        }
        lastSsid = p.ssid;
        lastPassword = p.password;
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
                    showCredentialsDialog();
                });
            }
        });
    }

    private void showCredentialsDialog() {
        android.view.View view = getLayoutInflater().inflate(R.layout.dialog_hotspot_credentials, null);
        android.widget.EditText ssidInput = view.findViewById(R.id.input_ssid);
        android.widget.EditText passInput = view.findViewById(R.id.input_password);
        if (lastSsid != null) ssidInput.setText(lastSsid);
        if (lastPassword != null) passInput.setText(lastPassword);
        new AlertDialog.Builder(this)
                .setTitle(R.string.enter_hotspot_info)
                .setMessage(R.string.manual_connect_prompt)
                .setView(view)
                .setPositiveButton(R.string.connect_now, (d, w) -> {
                    String ssid = ssidInput.getText() != null ? ssidInput.getText().toString().trim() : "";
                    String pw = passInput.getText() != null ? passInput.getText().toString().trim() : "";
                    if (ssid.isEmpty() || pw.isEmpty()) {
                        status.setText(R.string.invalid_credentials);
                        return;
                    }
                    lastSsid = ssid;
                    lastPassword = pw;
                    status.setText(R.string.connect_status_connecting);
                    connector.connect(this, ssid, pw, new WifiConnector.Callback() {
                        @Override
                        public void onConnected() {
                            runOnUiThread(() -> status.setText(R.string.connect_status_connected));
                        }

                        @Override
                        public void onFailed(String reason) {
                            runOnUiThread(() -> status.setText(R.string.connect_status_failed));
                        }
                    });
                })
                .setNegativeButton(R.string.cancel, null)
                .show();
    }
}
