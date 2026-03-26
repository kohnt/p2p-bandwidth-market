package com.example.p2pdata;

import com.example.p2pdata.model.BootstrapPayload;

import org.junit.Assert;
import org.junit.Test;

public class BootstrapPayloadTest {
    @Test
    public void testSerializeDeserialize() {
        BootstrapPayload p = new BootstrapPayload();
        p.version = 1;
        p.role = "provider";
        p.ssid = "TestSSID";
        p.password = "TestPass123";
        p.security = "WPA2";
        p.band = "2.4";
        p.ts = 123456789L;
        String json = p.toJson();
        BootstrapPayload q = BootstrapPayload.fromJson(json);
        Assert.assertNotNull(q);
        Assert.assertEquals(p.ssid, q.ssid);
        Assert.assertEquals(p.password, q.password);
        Assert.assertEquals(p.role, q.role);
        Assert.assertEquals(p.version, q.version);
    }
}
