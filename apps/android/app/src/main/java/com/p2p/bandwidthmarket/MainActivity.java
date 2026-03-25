package com.p2p.bandwidthmarket;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import com.p2p.bandwidthmarket.core.HotspotManager;
import com.p2p.bandwidthmarket.core.NfcReader;
import com.p2p.bandwidthmarket.core.ProxyServer;
import com.p2p.bandwidthmarket.core.UsageTracker;

public class MainActivity extends AppCompatActivity {
    private static final int PERMISSION_REQUEST_CODE = 1001;
    private HotspotManager hotspotManager;
    private ProxyServer proxyServer;
    private UsageTracker usageTracker;
    private NfcReader nfcReader;
    private TextView statusText;
    private TextView usageText;
    private Button actionButton;
    private Button modeButton;
    private boolean isSellerMode = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        hotspotManager = new HotspotManager(this);
        proxyServer = new ProxyServer(1080);
        usageTracker = new UsageTracker();
        nfcReader = new NfcReader(this);
        
        statusText = findViewById(R.id.textView2);
        usageText = findViewById(R.id.textView_usage);
        actionButton = findViewById(R.id.button_hotspot);
        modeButton = findViewById(R.id.button_mode);

        modeButton.setOnClickListener(v -> toggleMode());

        actionButton.setOnClickListener(v -> {
            if (hotspotManager.isHotspotActive()) {
                stopHotspot();
            } else {
                checkPermissionsAndStartHotspot();
            }
        });
    }

    private void toggleMode() {
        isSellerMode = !isSellerMode;
        if (isSellerMode) {
            modeButton.setText("Switch to Buyer Mode");
            actionButton.setText("Start Hotspot");
            statusText.setText("Seller Mode Active");
            nfcReader.stopReading();
        } else {
            modeButton.setText("Switch to Seller Mode");
            actionButton.setText("Scan NFC to Buy");
            statusText.setText("Buyer Mode Active");
            stopHotspot();
        }
    }

    private void checkPermissionsAndStartHotspot() {
        if (isSellerMode) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, PERMISSION_REQUEST_CODE);
            } else {
                startHotspot();
            }
        } else {
            startNfcReading();
        }
    }

    private void startNfcReading() {
        statusText.setText("Waiting for NFC Tag...");
        nfcReader.startReading(new NfcReader.ReaderCallback() {
            @Override
            public void onTokenSent(String response) {
                runOnUiThread(() -> {
                    statusText.setText("Token Sent! Response: " + response);
                    Toast.makeText(MainActivity.this, "Transaction Successful", Toast.LENGTH_SHORT).show();
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> statusText.setText("NFC Error: " + error));
            }
        });
    }

    private void startHotspot() {
        statusText.setText("Starting Hotspot...");
        hotspotManager.startHotspot(new HotspotManager.HotspotCallback() {
            @Override
            public void onStarted(String ssid, String passphrase) {
                statusText.setText("Hotspot Active\nSSID: " + ssid + "\nPass: " + passphrase);
                actionButton.setText("Stop Hotspot");
                startProxy();
            }

            @Override
            public void onStopped() {
                statusText.setText("Hotspot Stopped");
                actionButton.setText("Start Hotspot");
                stopProxy();
            }

            @Override
            public void onFailure(int errorCode) {
                statusText.setText("Failed to start hotspot (" + errorCode + ")");
                Toast.makeText(MainActivity.this, "Hotspot Error: " + errorCode, Toast.LENGTH_SHORT).show();
            }
        });
    }

    private void startProxy() {
        usageTracker.reset();
        proxyServer.start(bytes -> runOnUiThread(() -> {
            usageTracker.addBytes(bytes);
            usageText.setText("Usage: " + usageTracker.getFormattedUsage());
        }));
    }

    private void stopProxy() {
        proxyServer.stop();
        usageText.setText("Usage: 0 B");
    }

    private void stopHotspot() {
        hotspotManager.stopHotspot();
        stopProxy();
        statusText.setText("Hotspot Stopped");
        actionButton.setText("Start Hotspot");
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE && grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            startHotspot();
        }
    }
}
