package com.androidseclab.cryptoapibench.untrustedprngkey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class UnsafePRNGForKeyABMC1 {
    public void go(byte[] keyBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        IvParameterSpec parameterSpec = new IvParameterSpec(ivBytes);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(Arrays.toString(cipherBytes));
    }
}