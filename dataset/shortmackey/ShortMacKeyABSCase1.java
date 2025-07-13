package com.androidseclab.cryptoapibench.shortmackey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

class ShortMacKey1 {
    private final SecretKey key;

    public ShortMacKey1(SecretKey defaultKey) {
        key = defaultKey;
    }

    public void go(SecretKey passedKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        passedKey = key;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey key1 = keyGenerator.generateKey();

        byte[] ivBytes = new byte[16];
        SecureRandom random1 = new SecureRandom();
        random1.nextBytes(ivBytes);
        IvParameterSpec parameterSpec = new IvParameterSpec(ivBytes);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key1, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);
        mac.update(cipherBytes);
        byte[] macBytes = mac.doFinal();

        byte[] result = new byte[cipherBytes.length + macBytes.length];
        System.arraycopy(cipherBytes, 0, result, 0, cipherBytes.length);
        System.arraycopy(macBytes, 0, result, cipherBytes.length, macBytes.length);

        System.out.println(Arrays.toString(result));
    }
}

public class ShortMacKeyABSCase1 {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        String passwordStr = "password";
        char[] password = passwordStr.toCharArray();

        byte[] saltBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(saltBytes);
        PBEKeySpec keySpec = new PBEKeySpec(password, saltBytes, 1000, 256);

        SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKeyFactory keyFactory2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey defaultKey = keyFactory1.generateSecret(keySpec);
        SecretKey passedKey = keyFactory2.generateSecret(keySpec);

        ShortMacKey1 case1 = new ShortMacKey1(defaultKey);
        case1.go(passedKey);
    }
}