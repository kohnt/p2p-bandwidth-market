package com.example.p2pdata.model;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class BootstrapPayload {
    public String role;
    public String ssid;
    public String password;
    public String security;
    public String band;
    public int version;
    public long ts;
    public String sig;

    public String toJson() {
        try {
            JSONObject o = new JSONObject();
            o.put("v", version);
            o.put("role", role);
            o.put("ssid", ssid);
            o.put("pw", password);
            o.put("sec", security);
            o.put("band", band);
            o.put("ts", ts);
            String base = o.toString();
            String s = checksum(base);
            JSONObject wrap = new JSONObject();
            wrap.put("p", base);
            wrap.put("sig", s);
            return wrap.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static BootstrapPayload fromJson(String json) {
        try {
            JSONObject wrap = new JSONObject(json);
            String base = wrap.getString("p");
            String sig = wrap.optString("sig", "");
            String expect = checksum(base);
            if (!expect.equals(sig)) return null;
            JSONObject o = new JSONObject(base);
            BootstrapPayload p = new BootstrapPayload();
            p.version = o.getInt("v");
            p.role = o.getString("role");
            p.ssid = o.getString("ssid");
            p.password = o.getString("pw");
            p.security = o.getString("sec");
            p.band = o.getString("band");
            p.ts = o.getLong("ts");
            p.sig = sig;
            return p;
        } catch (Exception e) {
            return null;
        }
    }

    private static String checksum(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            sb.append(String.format("%02x", d[i]));
        }
        return sb.toString();
    }
}
