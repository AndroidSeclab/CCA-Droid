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

public class ShortMacKeyABMC1 {
    public void go(SecretKey key2) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
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
        mac.init(key2);
        mac.update(cipherBytes);
        byte[] macBytes = mac.doFinal();

        byte[] result = new byte[cipherBytes.length + macBytes.length];
        System.arraycopy(cipherBytes, 0, result, 0, cipherBytes.length);
        System.arraycopy(macBytes, 0, result, cipherBytes.length, macBytes.length);

        System.out.println(Arrays.toString(result));
    }
}