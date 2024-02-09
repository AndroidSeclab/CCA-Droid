package com.androidseclab.cryptoapibench.staticsalts;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class StaticSaltsABICase5 {
    private static final String SALT_STR = "12345";
    private static String saltStr1;
    private static String saltStr2;

    private static void go1() {
        saltStr1 = SALT_STR;
    }

    private static void go2() {
        saltStr2 = saltStr1;
    }

    private static void go3() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException {
        String passwordStr = "Secret Password";
        char[] password = passwordStr.toCharArray();

        byte saltByte = Byte.parseByte(saltStr2);
        byte[] saltBytes1 = new byte[]{saltByte};

        byte[] saltBytes2 = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(saltBytes2);

        PBEKeySpec keySpec = new PBEKeySpec(password, saltBytes1, 1000);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEwithHmacSHA512AndAES_256");
        SecretKey key = keyFactory.generateSecret(keySpec);
        PBEParameterSpec parameterSpec = new PBEParameterSpec(saltBytes2, 1000);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("PBEwithHmacSHA512AndAES_256");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(Arrays.toString(cipherBytes));
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        go1();
        go2();

        go3();
    }
}