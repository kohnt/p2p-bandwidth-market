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
import android.widget.EditText;
import android.widget.RadioGroup;
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
    private TextView statusText;   // short one-line state chip
    private TextView usageText;    // bytes used in usage card
    private TextView speedText;    // KB/s in usage card
    private TextView quotaText;
    private TextView infoText;     // verbose details panel
    private android.view.View infoLayout;
    private android.view.View dataAmountLayout;
    private RadioGroup radioGroupData;
    private EditText editTextCustomMb;
    private Button actionButton;
    private Button modeButton;
    private Button purchaseButton;
    private boolean isSellerMode = true;
    private String currentSellerToken;  // received via NFC (buyer) or locally generated (seller)
    private String currentProxyIp;      // seller's hotspot IP — bootstrap SOCKS5 proxy for buyer
    private android.net.Network currentNetwork;
    private com.p2p.bandwidthmarket.core.SellerRelayClient sellerRelayClient;
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

        // Generate a stable seller token once per install and persist it.
        android.content.SharedPreferences prefs = getPreferences(MODE_PRIVATE);
        String storedToken = prefs.getString("seller_token", null);
        if (storedToken == null) {
            storedToken = java.util.UUID.randomUUID().toString();
            prefs.edit().putString("seller_token", storedToken).apply();
        }
        currentSellerToken = storedToken;

        statusText   = findViewById(R.id.textView_status);
        usageText    = findViewById(R.id.textView_usage);
        speedText    = findViewById(R.id.textView_speed);
        quotaText    = findViewById(R.id.textView_quota);
        infoText         = findViewById(R.id.textView_info);
        infoLayout       = findViewById(R.id.layout_info);
        dataAmountLayout = findViewById(R.id.layout_data_amount);
        radioGroupData   = findViewById(R.id.radioGroup_data);
        editTextCustomMb = findViewById(R.id.editText_custom_mb);
        actionButton     = findViewById(R.id.button_hotspot);
        modeButton       = findViewById(R.id.button_mode);
        purchaseButton   = findViewById(R.id.button_purchase);

        radioGroupData.setOnCheckedChangeListener((group, checkedId) -> {
            boolean isCustom = checkedId == R.id.radio_custom;
            editTextCustomMb.setVisibility(isCustom ? android.view.View.VISIBLE : android.view.View.GONE);
            if (!isCustom) {
                purchaseButton.setText("Purchase " + selectedDataLabel() + " Token");
            }
        });
        editTextCustomMb.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence s, int st, int c, int a) {}
            public void onTextChanged(CharSequence s, int st, int b, int c) {
                String label = s.toString().isEmpty() ? "?" : s.toString() + " MB";
                purchaseButton.setText("Purchase " + label + " Token");
            }
            public void afterTextChanged(android.text.Editable s) {}
        });

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

    private void setInfo(String text) {
        infoText.setText(text);
        infoLayout.setVisibility(text == null || text.isEmpty()
                ? android.view.View.GONE : android.view.View.VISIBLE);
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
            statusText.setText("Seller Mode");
            dataAmountLayout.setVisibility(android.view.View.GONE);
            purchaseButton.setVisibility(android.view.View.GONE);
            setInfo(null);
            nfcReader.stopReading();
        } else {
            modeButton.setText("Switch to Seller Mode");
            actionButton.setText("Scan NFC to Buy");
            statusText.setText("Buyer Mode");
            dataAmountLayout.setVisibility(android.view.View.VISIBLE);
            purchaseButton.setVisibility(android.view.View.VISIBLE);
            purchaseButton.setText("Purchase " + selectedDataLabel() + " Token");
            setInfo(null);
            stopHotspot();
        }
    }

    /** Returns a display label for the currently selected data amount. */
    private String selectedDataLabel() {
        int id = radioGroupData.getCheckedRadioButtonId();
        if (id == R.id.radio_10mb)  return "10 MB";
        if (id == R.id.radio_25mb)  return "25 MB";
        if (id == R.id.radio_50mb)  return "50 MB";
        if (id == R.id.radio_100mb) return "100 MB";
        String custom = editTextCustomMb.getText().toString().trim();
        return custom.isEmpty() ? "?" : custom + " MB";
    }

    /** Returns quota in bytes for the currently selected data amount, or -1 if invalid. */
    private long selectedQuotaBytes() {
        int id = radioGroupData.getCheckedRadioButtonId();
        if (id == R.id.radio_10mb)  return 10L  * 1024 * 1024;
        if (id == R.id.radio_25mb)  return 25L  * 1024 * 1024;
        if (id == R.id.radio_50mb)  return 50L  * 1024 * 1024;
        if (id == R.id.radio_100mb) return 100L * 1024 * 1024;
        // Custom
        try {
            double mb = Double.parseDouble(editTextCustomMb.getText().toString().trim());
            if (mb <= 0) return -1;
            return (long) (mb * 1024 * 1024);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private void startMetricsUpdater() {
        android.os.Handler handler = new android.os.Handler(android.os.Looper.getMainLooper());
        handler.post(new Runnable() {
            long lastBytes = 0;
            @Override
            public void run() {
                long currentBytes = isSellerMode
                        ? usageTracker.getBytesUsed()
                        : com.p2p.bandwidthmarket.core.MarketVpnService.getBytesRelayed();
                long diff = currentBytes - lastBytes;
                lastBytes = currentBytes;

                usageText.setText(formatBytes(currentBytes));
                speedText.setText(String.format("%.1f KB/s", diff / 1024.0));

                handler.postDelayed(this, 1000);
            }
        });
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char pre = "KMGTPE".charAt(exp - 1);
        return String.format(java.util.Locale.US, "%.1f %cB", bytes / Math.pow(1024, exp), pre);
    }

    private void simulatePurchase() {
        long quotaBytes = selectedQuotaBytes();
        if (quotaBytes <= 0) {
            Toast.makeText(this, "Please enter a valid data amount", Toast.LENGTH_SHORT).show();
            return;
        }
        String label = selectedDataLabel();
        statusText.setText("Purchasing...");
        setInfo("Minting " + label + " token via EC2...");
        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
            proxyServer.authorizeClient("10.0.0.2"); // TUN local address
            proxyServer.setPreAuthMode(false);
            sessionController.startSession(
                quotaBytes,
                com.p2p.bandwidthmarket.core.MarketVpnService::getBytesRelayed,
                () -> runOnUiThread(() -> {
                    stopVpnService();
                    statusText.setText("Quota Exhausted");
                    quotaText.setText("0 MB");
                    setInfo(label + " quota used — session ended.");
                    Toast.makeText(this, label + " quota used — session ended", Toast.LENGTH_LONG).show();
                })
            );
            quotaText.setText(label);
            statusText.setText("Token Ready");
            setInfo("Token minted. Starting VPN...");
            Toast.makeText(this, "Purchase Successful!", Toast.LENGTH_SHORT).show();
            startVpn();
        }, 2000);
    }

    private void stopVpnService() {
        android.content.Intent intent = new android.content.Intent(this, com.p2p.bandwidthmarket.core.MarketVpnService.class);
        intent.setAction("STOP");
        startService(intent);
    }

    private void startVpn() {
        com.p2p.bandwidthmarket.core.MarketVpnService.resetBytesRelayed();
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
            intent.putExtra("SELLER_TOKEN", currentSellerToken);
            intent.putExtra("BOOTSTRAP_PROXY_HOST", currentProxyIp);
            startService(intent);
            statusText.setText("VPN Active");
            setInfo("Tunneling through EC2 relay (seller: " + currentSellerToken + ")");
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
        statusText.setText("Waiting for NFC...");
        setInfo(null);
        nfcReader.startReading(new NfcReader.ReaderCallback() {
            @Override
            public void onHotspotInfoReceived(String ssid, String passphrase, String sellerToken, String proxyIp) {
                runOnUiThread(() -> {
                    currentSellerToken = sellerToken;
                    currentProxyIp = proxyIp;
                    statusText.setText("Seller Found");
                    setInfo("SSID: " + ssid + "\nConnecting to hotspot...");
                    new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() ->
                        connectToWifi(ssid, passphrase), 1000);
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    statusText.setText("NFC Error");
                    setInfo(error);
                });
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
            runOnUiThread(() -> {
                statusText.setText("Connecting...");
                setInfo("SSID: " + ssid + "\nPassword: " + passphrase + "\n\nIf not auto-connected, join this network in WiFi Settings, then tap Purchase.");
            });
        }
    }

    private void startHotspot() {
        statusText.setText("Starting...");
        setInfo(null);
        hotspotManager.startHotspot(new HotspotManager.HotspotCallback() {
            @Override
            public void onStarted(String ssid, String passphrase) {
                actionButton.setText("Stop Hotspot");
                startProxy();
                TokenHceService.setHotspotConfig(ssid, passphrase, currentSellerToken, hotspotManager);
                startSellerRelay();
                new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() -> {
                    String ip = hotspotManager.getIpAddress();
                    statusText.setText("Hotspot Active");
                    setInfo("SSID: " + ssid + "\nPassword: " + passphrase + "\nProxy IP: " + ip + "\n\nWaiting for buyer NFC tap...");
                }, 2000);
            }

            @Override
            public void onStopped() {
                statusText.setText("Idle");
                setInfo(null);
                actionButton.setText("Start Hotspot");
                stopProxy();
            }

            @Override
            public void onFailure(int errorCode) {
                statusText.setText("Failed");
                setInfo("Could not start hotspot (error " + errorCode + ")");
            }
        });
    }

    private void startProxy() {
        usageTracker.reset();
        proxyServer.setPreAuthMode(false);
        proxyServer.start(bytes -> runOnUiThread(() -> usageTracker.addBytes(bytes)));
    }

    private void stopProxy() {
        proxyServer.stop();
        sessionController.terminateSession();
    }

    private void stopHotspot() {
        hotspotManager.stopHotspot();
        stopProxy();
        stopSellerRelay();
        statusText.setText("Idle");
        setInfo(null);
        actionButton.setText("Start Hotspot");
    }

    private void startSellerRelay() {
        stopSellerRelay();
        sellerRelayClient = new com.p2p.bandwidthmarket.core.SellerRelayClient(
            com.p2p.bandwidthmarket.core.MarketVpnService.EC2_HOST,
            com.p2p.bandwidthmarket.core.MarketVpnService.EC2_PORT,
            currentSellerToken
        );
        sellerRelayClient.start();
    }

    private void stopSellerRelay() {
        if (sellerRelayClient != null) {
            sellerRelayClient.stop();
            sellerRelayClient = null;
        }
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
