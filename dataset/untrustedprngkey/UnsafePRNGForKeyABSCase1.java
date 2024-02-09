package com.androidseclab.cryptoapibench.untrustedprngkey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

class UnsafePRNGForKey1 {
    private final SecretKey key;

    public UnsafePRNGForKey1(SecretKey defaultKey) {
        key = defaultKey;
    }

    public void go(SecretKey passedKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        passedKey = key;

        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        IvParameterSpec parameterSpec = new IvParameterSpec(ivBytes);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, passedKey, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(Arrays.toString(cipherBytes));
    }
}

public class UnsafePRNGForKeyABSCase1 {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] keyBytes = new byte[16];
        Random random1 = new Random();
        random1.nextBytes(keyBytes);
        SecretKeySpec defaultKey = new SecretKeySpec(keyBytes, "AES");

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey passedKey = keyGenerator.generateKey();

        UnsafePRNGForKey1 case2 = new UnsafePRNGForKey1(defaultKey);
        case2.go(passedKey);
    }
}