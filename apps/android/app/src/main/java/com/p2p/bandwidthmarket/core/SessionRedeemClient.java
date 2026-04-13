package com.p2p.bandwidthmarket.core;

import android.os.Handler;
import android.os.Looper;
import android.util.Base64;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

/**
 * Buyer-side redeem call to EC2 after an NFC tap ({@code seller_id|tap_nonce}).
 * Sends an ephemeral EC P-256 public key (DER, Base64) for a future ECDH-wrapped payload;
 * if the server only uses TLS, it may ignore {@code buyer_ecdh_pub_b64}.
 */
public final class SessionRedeemClient {

    private SessionRedeemClient() {}

    public static final class RedeemResult {
        public final String ssid;
        public final String wifiPassphrase;
        public final String proxyIp;
        /** Raw key bytes as Base64, or empty if server omits it until tunnel layer is wired. */
        public final String sharedSessionKeyBase64;

        public RedeemResult(String ssid, String wifiPassphrase, String proxyIp, String sharedSessionKeyBase64) {
            this.ssid = ssid;
            this.wifiPassphrase = wifiPassphrase;
            this.proxyIp = proxyIp;
            this.sharedSessionKeyBase64 = sharedSessionKeyBase64 != null ? sharedSessionKeyBase64 : "";
        }
    }

    public interface RedeemCallback {
        void onSuccess(RedeemResult result);

        void onError(String message);
    }

    public static void redeemAsync(String redeemUrl, String sellerId, String tapNonce, RedeemCallback callback) {
        Handler main = new Handler(Looper.getMainLooper());
        new Thread(() -> {
            try {
                RedeemResult r = redeem(redeemUrl, sellerId, tapNonce);
                main.post(() -> callback.onSuccess(r));
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : "Redeem failed";
                main.post(() -> callback.onError(msg));
            }
        }, "session-redeem").start();
    }

    static RedeemResult redeem(String redeemUrl, String sellerId, String tapNonce) throws Exception {
        if (redeemUrl == null || redeemUrl.trim().isEmpty()) {
            throw new IllegalStateException("Set ec2_redeem_url in res/values/strings.xml");
        }

        String buyerPubB64 = generateEphemeralEcPublicKeyDerBase64();

        JSONObject body = new JSONObject();
        body.put("seller_id", sellerId);
        body.put("tap_nonce", tapNonce);
        body.put("buyer_ecdh_pub_b64", buyerPubB64);

        HttpURLConnection conn = (HttpURLConnection) new URL(redeemUrl.trim()).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(20000);
        byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload);
        }

        int code = conn.getResponseCode();
        InputStream stream = code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream();
        String responseStr = readFully(stream);
        if (code < 200 || code >= 300) {
            throw new IllegalStateException("HTTP " + code + ": " + responseStr);
        }

        JSONObject json = new JSONObject(responseStr);
        String ssid = json.optString("ssid", "");
        String pass = json.optString("wifi_passphrase", "");
        if (pass.isEmpty()) {
            pass = json.optString("wifi_password", "");
        }
        String proxyIp = json.optString("proxy_ip", "");
        String sk = json.optString("shared_session_key", "");

        if (ssid.isEmpty() || pass.isEmpty()) {
            throw new IllegalStateException("Redeem JSON missing ssid or wifi_passphrase");
        }
        if (proxyIp.isEmpty()) {
            throw new IllegalStateException("Redeem JSON missing proxy_ip");
        }

        return new RedeemResult(ssid, pass, proxyIp, sk);
    }

    private static String readFully(InputStream is) throws Exception {
        if (is == null) {
            return "";
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }

    private static String generateEphemeralEcPublicKeyDerBase64() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        return Base64.encodeToString(kp.getPublic().getEncoded(), Base64.NO_WRAP);
    }
}
