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
    private TextView ssidText;
    private TextView passText;
    private Button startBtn;
    private Button openSettingsBtn;
    private HotspotController hotspotController;
    private NfcAdapter nfcAdapter;
    private String currentSsid;
    private String currentPass;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_provider);
        status = findViewById(R.id.provider_status);
        ssidText = findViewById(R.id.provider_ssid);
        passText = findViewById(R.id.provider_password);
        startBtn = findViewById(R.id.btn_start_hotspot);
        openSettingsBtn = findViewById(R.id.btn_open_hotspot_settings);
        hotspotController = new HotspotController();
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        startBtn.setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT >= 26) {
                status.setText(R.string.hotspot_status_waiting);
                hotspotController.startLocalOnlyHotspot(this, new HotspotController.Callback() {
                    @Override
                    public void onStarted(String ssid, String password) {
                        currentSsid = ssid;
                        currentPass = password;
                        status.setText(R.string.hotspot_ready);
                        ssidText.setText(ssid);
                        passText.setText(password);
                        enableNfcShare();
                    }

                    @Override
                    public void onFailed(String reason) {
                        showInfo("Hotspot failed. Use system settings instead.");
                    }
                });
            } else {
                showInfo("Local-only hotspot not supported. Use system settings.");
            }
        });

        openSettingsBtn.setOnClickListener(v -> {
            try {
                startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS));
            } catch (Exception e) {
                showInfo("Open settings manually.");
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        enableNfcShare();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null && Build.VERSION.SDK_INT < 29) {
            try {
                nfcAdapter.setNdefPushMessage(null, this);
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
                nfcAdapter.setNdefPushMessage(msg, this);
            } catch (Throwable ignored) {
            }
        }
    }

    private void showInfo(String message) {
        new AlertDialog.Builder(this)
                .setMessage(message)
                .setPositiveButton("OK", null)
                .show();
    }
}
