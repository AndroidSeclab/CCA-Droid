package com.androidseclab.cryptoapibench.untrustedprngkey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

public class UnsafePRNGForKeyABICase2 {
    private static final byte[] KEY_BYTES;
    private static byte[] keyBytes1;
    private static byte[] keyBytes2;

    static {
        byte[] keyBytes = new byte[16];
        Random random = new Random();
        random.nextBytes(keyBytes);
        KEY_BYTES = keyBytes;
    }

    private static void go1() {
        keyBytes1 = KEY_BYTES;
    }

    private static void go2() {
        keyBytes2 = keyBytes1;
    }

    private static void go3() throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes2, "AES");

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

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        go1();
        go2();

        go3();
    }
}