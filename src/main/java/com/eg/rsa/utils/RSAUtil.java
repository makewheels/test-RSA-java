package com.eg.rsa.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

public class RSAUtil {

    public static byte[] encrypt(byte[] data, PublicKey publicKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (keyPairGenerator == null) {
            return null;
        }
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws IllegalBlockSizeException,
            InvalidKeyException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        KeyPair keyPair = RSAUtil.generateKeyPair();
        if (keyPair == null)
            return;
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String message = "Hello World";

        Base64.Encoder base64Encoder = Base64.getEncoder();

        System.out.println("Public key:");
        System.out.println(base64Encoder.encodeToString(publicKey.getEncoded()));
        System.out.println("Private key:");
        System.out.println(base64Encoder.encodeToString(privateKey.getEncoded()));
        System.out.println("message: " + message);
        byte[] encrypt = encrypt(message.getBytes(), publicKey);
        System.out.println("encrypt: " + base64Encoder.encodeToString(encrypt));

        byte[] decrypt = decrypt(encrypt, privateKey);
        System.out.println("decrypt: " + new String(decrypt));

    }
}
