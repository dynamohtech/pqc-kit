package com.example.billing;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** Sample code for pqc-kit tests. Not meant to be run. */
public class PaymentCrypto {

    private static final String SIGNING_ALG = "SHA256withRSA";
    private static final int RSA_BITS = 3072;

    public KeyPair rsaKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(RSA_BITS);
        return kpg.generateKeyPair();
    }

    public KeyPair ecKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp384r1"));
        return gen.generateKeyPair();
    }

    public KeyPair pqKeys() throws Exception {
        // Java 24+: ML-KEM (JEP 496)
        return KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
    }

    public byte[] sign(KeyPair kp, byte[] data) throws Exception {
        Signature s = Signature.getInstance(SIGNING_ALG);
        s.initSign(kp.getPrivate());
        s.update(data);
        return s.sign();
    }

    public byte[] legacySign(KeyPair kp, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA1withDSA");
        s.initSign(kp.getPrivate());
        return s.sign();
    }

    public byte[] encryptCard(byte[] key, byte[] pan) throws Exception {
        Cipher c = Cipher.getInstance("AES"); // defaults to ECB
        return c.doFinal(pan);
    }

    public byte[] encryptToken(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return c.doFinal(data);
    }

    public byte[] wrapForBank(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        return c.doFinal(data);
    }

    public byte[] mac(byte[] data) throws Exception {
        return Mac.getInstance("HmacSHA256").doFinal(data);
    }

    public byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public SecretKeyFactory pbe() throws Exception {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    }

    public void tls(SSLSocket socket) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        socket.setEnabledProtocols(new String[] {"TLSv1.1", "TLSv1.2"});
    }
}
