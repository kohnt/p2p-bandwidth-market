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
    private HotspotManager hotspotManager;
    private ProxyServer proxyServer;
    private UsageTracker usageTracker;
    private NfcReader nfcReader;
    private com.p2p.bandwidthmarket.core.SessionController sessionController;
    private TextView statusText;
    private TextView usageText;
    private TextView throughputText;
    private TextView quotaText;
    private Button actionButton;
    private Button modeButton;
    private Button purchaseButton;
    private boolean isSellerMode = true;
    private String currentProxyIp;
    private android.net.Network currentNetwork;
    private volatile boolean hotspotNetworkCaptured = false;
    private static final int VPN_REQUEST_CODE = 1002;
    private static final int PERMISSION_REQUEST_CODE = 1001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        hotspotManager = new HotspotManager(this);
        proxyServer = new ProxyServer(8080);
        usageTracker = new UsageTracker();
        nfcReader = new NfcReader(this);
        sessionController = new com.p2p.bandwidthmarket.core.SessionController(proxyServer, usageTracker);
        
        statusText = findViewById(R.id.textView_throughput);
        usageText = findViewById(R.id.textView_usage);
        throughputText = findViewById(R.id.textView_throughput);
        quotaText = findViewById(R.id.textView_quota);
        actionButton = findViewById(R.id.button_hotspot);
        modeButton = findViewById(R.id.button_mode);
        purchaseButton = findViewById(R.id.button_purchase);

        modeButton.setOnClickListener(v -> toggleMode());
        purchaseButton.setOnClickListener(v -> simulatePurchase());

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
        
        startMetricsUpdater();
        startWifiMonitor();
    }

    private void startWifiMonitor() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkRequest req = new NetworkRequest.Builder()
                .addTransportType(android.net.NetworkCapabilities.TRANSPORT_WIFI)
                .build();
        cm.registerNetworkCallback(req, new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(@NonNull Network network) {
                if (!hotspotNetworkCaptured) {
                    currentNetwork = network;
                    com.p2p.bandwidthmarket.core.MarketVpnService.setUnderlyingNetwork(network);
                    cm.bindProcessToNetwork(network);
                    android.util.Log.i("MainActivity", "WiFi network captured: " + network);
                }
            }
        });
    }

    private void toggleMode() {
        isSellerMode = !isSellerMode;
        if (isSellerMode) {
            modeButton.setText("Switch to Buyer Mode");
            actionButton.setText("Start Hotspot");
            statusText.setText("Seller Mode Active");
            purchaseButton.setVisibility(android.view.View.GONE);
            nfcReader.stopReading();
        } else {
            modeButton.setText("Switch to Seller Mode");
            actionButton.setText("Scan NFC to Buy");
            statusText.setText("Buyer Mode Active");
            purchaseButton.setVisibility(android.view.View.VISIBLE);
            stopHotspot();
        }
    }

    private void startMetricsUpdater() {
        android.os.Handler handler = new android.os.Handler(android.os.Looper.getMainLooper());
        handler.post(new Runnable() {
            long lastBytes = 0;
            @Override
            public void run() {
                long currentBytes = usageTracker.getBytesUsed();
                long diff = currentBytes - lastBytes;
                lastBytes = currentBytes;
                
                throughputText.setText(String.format("Speed: %.1f KB/s", diff / 1024.0));
                usageText.setText("Usage: " + usageTracker.getFormattedUsage());
                
                handler.postDelayed(this, 1000);
            }
        });
    }

    private void simulatePurchase() {
        statusText.setText("Purchasing 10MB Token via EC2...");
        // Simulation of "Stage 0" Bootstrap
        // In reality, this would be an HTTP request to EC2 via the proxy
        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
            statusText.setText("Token Minted! Upgrading Proxy...");
            // Notify seller to authorize our IP
            proxyServer.authorizeClient("10.0.0.2"); // TUN local address
            proxyServer.setPreAuthMode(false); // For demo, let everyone through
            sessionController.startSession(10 * 1024 * 1024); // 10MB
            quotaText.setText("Quota: 10 MB");
            Toast.makeText(this, "Purchase Successful!", Toast.LENGTH_SHORT).show();
            startVpn();
        }, 2000);
    }

    private void startVpn() {
        android.content.Intent intent = android.net.VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE);
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, android.content.Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            android.content.Intent intent = new android.content.Intent(this, com.p2p.bandwidthmarket.core.MarketVpnService.class);
            intent.putExtra("PROXY_HOST", currentProxyIp != null ? currentProxyIp : "192.168.43.1");
            intent.putExtra("PROXY_PORT", 8080);
            startService(intent);
            statusText.setText("VPN Active - Tunneling through P2P");
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
        hotspotNetworkCaptured = false;
        statusText.setText("Waiting for Seller's NFC...");
        nfcReader.startReading(new NfcReader.ReaderCallback() {
            @Override
            public void onHotspotInfoReceived(String ssid, String passphrase, String proxyIp) {
                runOnUiThread(() -> {
                    currentProxyIp = proxyIp;
                    statusText.setText("Found Seller!\nSSID: " + ssid + "\nConnecting to hotspot...");
                    // Delay so activity is fully resumed before showing the system WiFi dialog
                    new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() ->
                        connectToWifi(ssid, passphrase), 1000);
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
            android.net.wifi.WifiManager wifiManager = (android.net.wifi.WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            android.net.wifi.WifiNetworkSuggestion suggestion = new android.net.wifi.WifiNetworkSuggestion.Builder()
                    .setSsid(ssid)
                    .setWpa2Passphrase(passphrase)
                    .build();
            wifiManager.addNetworkSuggestions(java.util.Arrays.asList(suggestion));
            runOnUiThread(() -> statusText.setText("Connecting to hotspot...\nIf not auto-connected, join \"" + ssid + "\" in WiFi Settings, then tap Purchase"));
        }
    }

    private void startHotspot() {
        statusText.setText("Starting Hotspot...");
        hotspotManager.startHotspot(new HotspotManager.HotspotCallback() {
            @Override
            public void onStarted(String ssid, String passphrase) {
                statusText.setText("Hotspot starting, detecting IP...");
                actionButton.setText("Stop Hotspot");
                startProxy();
                // Register manager so NFC tap always does a fresh IP scan
                TokenHceService.setHotspotConfig(ssid, passphrase, hotspotManager);
                // Still delay UI update so the displayed IP has time to appear
                new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                    String ip = hotspotManager.getIpAddress();
                    statusText.setText("Hotspot Active\nSSID: " + ssid + "\nPass: " + passphrase + "\nProxy IP: " + ip + "\nWaiting for Buyer Tap...");
                }, 2000);
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
        proxyServer.setPreAuthMode(false); // WiFi password is the gate for now
        proxyServer.start(bytes -> runOnUiThread(() -> {
            usageTracker.addBytes(bytes);
        }));
    }

    private void stopProxy() {
        proxyServer.stop();
        sessionController.terminateSession();
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
