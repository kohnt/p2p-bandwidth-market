package com.p2p.bandwidthmarket;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.net.NetworkRequest;
import android.net.ConnectivityManager;
import android.net.Network;
import android.os.Build;
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
import com.p2p.bandwidthmarket.core.TokenHceService;

import java.util.ArrayList;
import java.util.List;

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
            if (isSellerMode) {
                if (hotspotManager.isHotspotActive()) {
                    stopHotspot();
                } else {
                    checkPermissionsAndStartHotspot();
                }
            } else {
                startNfcReading();
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
        List<String> permissionsNeeded = new ArrayList<>();
        
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissionsNeeded.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ActivityCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                permissionsNeeded.add(Manifest.permission.NEARBY_WIFI_DEVICES);
            }
        }

        if (!permissionsNeeded.isEmpty()) {
            ActivityCompat.requestPermissions(this, permissionsNeeded.toArray(new String[0]), PERMISSION_REQUEST_CODE);
        } else {
            startHotspot();
        }
    }

    private void startNfcReading() {
        statusText.setText("Waiting for Seller's NFC...");
        nfcReader.startReading(new NfcReader.ReaderCallback() {
            @Override
            public void onHotspotInfoReceived(String ssid, String passphrase, String proxyIp) {
                runOnUiThread(() -> {
                    statusText.setText("Connecting to: " + ssid + "\nProxy: " + proxyIp);
                    connectToWifi(ssid, passphrase);
                    // In a real app, you'd also save the proxyIp to use in the system settings or a browser.
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> statusText.setText("NFC Error: " + error));
            }
        });
    }

    private void connectToWifi(String ssid, String passphrase) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            WifiNetworkSpecifier specifier = new WifiNetworkSpecifier.Builder()
                    .setSsid(ssid)
                    .setWpa2Passphrase(passphrase)
                    .build();

            NetworkRequest request = new NetworkRequest.Builder()
                    .addTransportType(android.net.NetworkCapabilities.TRANSPORT_WIFI)
                    .setNetworkSpecifier(specifier)
                    .build();

            ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            connectivityManager.requestNetwork(request, new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(@NonNull Network network) {
                    super.onAvailable(network);
                    connectivityManager.bindProcessToNetwork(network);
                    runOnUiThread(() -> {
                        statusText.setText("Connected to Hotspot!");
                        Toast.makeText(MainActivity.this, "WiFi Connected", Toast.LENGTH_SHORT).show();
                    });
                }
            });
        } else {
            runOnUiThread(() -> Toast.makeText(this, "Manual WiFi connection required on this Android version", Toast.LENGTH_LONG).show());
        }
    }

    private void startHotspot() {
        statusText.setText("Starting Hotspot...");
        hotspotManager.startHotspot(new HotspotManager.HotspotCallback() {
            @Override
            public void onStarted(String ssid, String passphrase) {
                String ip = hotspotManager.getIpAddress();
                TokenHceService.setHotspotConfig(ssid, passphrase, ip);
                statusText.setText("Hotspot Active\nSSID: " + ssid + "\nPass: " + passphrase + "\nProxy IP: " + ip + "\nWaiting for Buyer Tap...");
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
        if (requestCode == PERMISSION_REQUEST_CODE) {
            boolean allGranted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            if (allGranted) {
                startHotspot();
            } else {
                Toast.makeText(this, "Permissions required to start hotspot", Toast.LENGTH_SHORT).show();
            }
        }
    }
}
