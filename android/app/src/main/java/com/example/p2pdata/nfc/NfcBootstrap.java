package com.example.p2pdata.nfc;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.Tag;
import android.nfc.tech.Ndef;

import com.example.p2pdata.model.BootstrapPayload;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

public class NfcBootstrap {
    public static NdefMessage createMessage(BootstrapPayload payload) {
        String text = payload.toJson();
        byte[] lang = Locale.ENGLISH.getLanguage().getBytes(StandardCharsets.US_ASCII);
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        byte[] p = new byte[1 + lang.length + data.length];
        p[0] = (byte) lang.length;
        System.arraycopy(lang, 0, p, 1, lang.length);
        System.arraycopy(data, 0, p, 1 + lang.length, data.length);
        NdefRecord r = new NdefRecord(NdefRecord.TNF_WELL_KNOWN, NdefRecord.RTD_TEXT, new byte[0], p);
        return new NdefMessage(new NdefRecord[]{r});
    }

    public static BootstrapPayload parseFromTag(Tag tag) {
        try {
            Ndef ndef = Ndef.get(tag);
            if (ndef == null) return null;
            ndef.connect();
            NdefMessage msg = ndef.getNdefMessage();
            ndef.close();
            if (msg == null || msg.getRecords().length == 0) return null;
            NdefRecord r = msg.getRecords()[0];
            if (r.getTnf() == NdefRecord.TNF_WELL_KNOWN && Arrays.equals(r.getType(), NdefRecord.RTD_TEXT)) {
                byte[] payload = r.getPayload();
                int langLength = payload[0] & 0x3F;
                int textLength = payload.length - 1 - langLength;
                String json = new String(payload, 1 + langLength, textLength, StandardCharsets.UTF_8);
                return BootstrapPayload.fromJson(json);
            }
        } catch (Exception ignored) {
        }
        return null;
    }
}
