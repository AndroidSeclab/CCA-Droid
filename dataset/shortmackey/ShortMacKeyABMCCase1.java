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

public class ShortMacKeyABMCCase1 {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        String passwordStr = "password";
        char[] password = passwordStr.toCharArray();

        byte[] saltBytes = new byte[16];
        SecureRandom random2 = new SecureRandom();
        random2.nextBytes(saltBytes);

        PBEKeySpec keySpec = new PBEKeySpec(password, saltBytes, 1000, 256);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        SecretKey key2 = keyFactory.generateSecret(keySpec);

        ShortMacKeyABMC1 case1 = new ShortMacKeyABMC1();
        case1.go(key2);
    }
}