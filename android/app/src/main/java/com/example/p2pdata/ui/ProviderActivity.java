package com.example.p2pdata.ui;

import android.content.Intent;
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.example.p2pdata.R;
import com.example.p2pdata.model.BootstrapPayload;
import com.example.p2pdata.nfc.NfcBootstrap;
import com.example.p2pdata.wifi.HotspotController;

public class ProviderActivity extends AppCompatActivity {
    private TextView status;
    private Button openSettingsBtn;
    private HotspotController hotspotController;
    private NfcAdapter nfcAdapter;
    private String currentSsid;
    private String currentPass;
    private boolean launchedSettings = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_provider);
        status = findViewById(R.id.provider_status);
        openSettingsBtn = findViewById(R.id.btn_open_hotspot_settings);
        hotspotController = new HotspotController();
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        openSettingsBtn.setOnClickListener(v -> {
            try {
                launchedSettings = true;
                startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS));
            } catch (Exception e) {
                showInfo("Open settings manually.");
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (launchedSettings && (currentSsid == null || currentPass == null)) {
            showCredentialsDialog();
        } else {
            enableNfcShare();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null && Build.VERSION.SDK_INT < 29) {
            try {
                java.lang.reflect.Method setNdefPushMessage = nfcAdapter.getClass().getMethod("setNdefPushMessage", NdefMessage.class, android.app.Activity.class, android.app.Activity[].class);
                setNdefPushMessage.invoke(nfcAdapter, null, this, new android.app.Activity[0]);
            } catch (Throwable ignored) {
            }
        }
    }

    private void enableNfcShare() {
        if (nfcAdapter == null) return;
        if (currentSsid == null || currentPass == null) return;
        BootstrapPayload p = new BootstrapPayload();
        p.version = 1;
        p.role = "provider";
        p.ssid = currentSsid;
        p.password = currentPass;
        p.security = "WPA2";
        p.band = "2.4";
        p.ts = System.currentTimeMillis() / 1000L;
        NdefMessage msg = NfcBootstrap.createMessage(p);
        if (Build.VERSION.SDK_INT < 29) {
            try {
                java.lang.reflect.Method setNdefPushMessage = nfcAdapter.getClass().getMethod("setNdefPushMessage", NdefMessage.class, android.app.Activity.class, android.app.Activity[].class);
                setNdefPushMessage.invoke(nfcAdapter, msg, this, new android.app.Activity[0]);
            } catch (Throwable ignored) {
            }
        }
    }

    private void showCredentialsDialog() {
        android.view.View view = getLayoutInflater().inflate(R.layout.dialog_hotspot_credentials, null);
        android.widget.EditText ssidInput = view.findViewById(R.id.input_ssid);
        android.widget.EditText passInput = view.findViewById(R.id.input_password);
        new AlertDialog.Builder(this)
                .setTitle(R.string.enter_hotspot_info)
                .setView(view)
                .setPositiveButton(R.string.start_sharing, (d, w) -> {
                    String ssid = ssidInput.getText() != null ? ssidInput.getText().toString().trim() : "";
                    String pw = passInput.getText() != null ? passInput.getText().toString().trim() : "";
                    if (ssid.isEmpty() || pw.isEmpty()) {
                        showInfo(getString(R.string.invalid_credentials));
                        return;
                    }
                    currentSsid = ssid;
                    currentPass = pw;
                    status.setText(R.string.waiting_for_tap);
                    enableNfcShare();
                })
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    private void showInfo(String message) {
        new AlertDialog.Builder(this)
                .setMessage(message)
                .setPositiveButton("OK", null)
                .show();
    }
}
