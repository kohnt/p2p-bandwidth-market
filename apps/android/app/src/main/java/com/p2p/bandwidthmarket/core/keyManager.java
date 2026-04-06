import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        PublicKey publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();

        if (privateKey == null || publicKey == null) {
            return null; // key doesn't exist
        }
        return new KeyPair(publicKey, privateKey);
    }

    /** 3️Generate AES-256 session key (GCM mode recommended) */
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
        return keyGen.generateKey();
    }

    /** 4️Sign session key with EC private key */
    public static byte[] signSessionKey(SecretKey sessionKey, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(sessionKey.getEncoded());
        return signature.sign();
    }
}