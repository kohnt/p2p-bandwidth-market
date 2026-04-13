package com.p2p.bandwidthmarket.core;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyManager {

    private static final String KEY_ALIAS = "clientECKey";

    /** 1️Generate EC Key Pair and store in Android Keystore */
    public static KeyPair generateECKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
        )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
                .build();

        kpg.initialize(spec);
        return kpg.generateKeyPair();
    }

    /** 2️Retrieve EC Key Pair from Keystore */
    public static KeyPair getECKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        // Try to get the private key
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);

        // Try to get the certificate and public key safely
        java.security.cert.Certificate cert = keyStore.getCertificate(KEY_ALIAS);
        PublicKey publicKey = (cert != null) ? cert.getPublicKey() : null;

        // If either is missing, generate a new key pair
        if (privateKey == null || publicKey == null) {
            return generateECKeyPair();
        }

        // Both exist → return key pair
        return new KeyPair(publicKey, privateKey);
    }

    /** Check if user key pair exists without returning the key */
    public static boolean checkECKeyPair()throws Exception{
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();

        return privateKey != null && publicKey != null; // key doesn't exist
    }

    /**ECDH Key pair generator for session keys*/
    public static KeyPair generateSessionKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // same as your identity key

        kpg.initialize(ecSpec);
        return kpg.generateKeyPair();
    }

    /** Generate Nonce*/
    private static final SecureRandom secureRandom = new SecureRandom();

    public static String generateNonce() throws Exception {
        byte[] nonce = new byte[16]; // 128-bit nonce
        secureRandom.nextBytes(nonce);

        return android.util.Base64.encodeToString(
                nonce,
                android.util.Base64.NO_WRAP
        );
    }

    /**Create Shared secret key*/
    public static SecretKey generateSharedKey(
            PrivateKey myPrivateKey,
            PublicKey otherPublicKey
    ) throws Exception {

        // 1. Perform ECDH
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(myPrivateKey);
        keyAgreement.doPhase(otherPublicKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();

        // 2. Derive AES key using SHA-256 (simple KDF)
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(sharedSecret);

        // 3. Use first 16 bytes → AES-128 (safe and compatible)
        return new SecretKeySpec(keyBytes, 0, 16, "AES");
    }

    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {

        // 1. Generate IV (12 bytes for GCM)
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // 2. Init cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        // 3. Encrypt
        byte[] ciphertext = cipher.doFinal(plaintext);

        // 4. Combine IV + ciphertext
        byte[] output = new byte[iv.length + ciphertext.length];

        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);

        return output;
    }

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static byte[] decrypt(byte[] ciphertextWithIv, SecretKey key) throws Exception {
        // 1. Extract IV (first 12 bytes)
        byte[] iv = new byte[12];
        System.arraycopy(ciphertextWithIv, 0, iv, 0, 12);

        // 2. Extract ciphertext
        byte[] ciphertext = new byte[ciphertextWithIv.length - 12];
        System.arraycopy(ciphertextWithIv, 12, ciphertext, 0, ciphertext.length);

        // 3. Init cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        // 4. Decrypt
        return cipher.doFinal(ciphertext);
    }

    public static PublicKey loadServerPublicKeyFromBase64() throws Exception {
        //genuinely don't want to deal with this anymore. Boom server public key
        String base64Key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6kM1pNLOy72rHGCsSHl7aDb3RhQpcH2+pkqY17tx3+AppVQQzDiN3wbUr8RvAQznwQb/taYKOxG91lUntz5S0w==";

        byte[] keyBytes = android.util.Base64.decode(base64Key, android.util.Base64.DEFAULT);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        return keyFactory.generatePublic(keySpec);
    }
    public static PublicKey decodeECPublicKey(byte[] encoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static boolean verifySignature(byte[] data, byte[] sig, PublicKey pub) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(pub);
        s.update(data);
        return s.verify(sig);
    }
}