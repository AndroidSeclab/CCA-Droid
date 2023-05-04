package com.androidseclab.cryptoapibench.untrustedprngiv;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class UnsafePRNGForIVABICase2 {
    private static final byte[] IV_BYTES;
    private static byte[] ivBytes1;
    private static byte[] ivBytes2;

    static {
        byte[] ivBytes = new byte[16];
        Random random = new Random();
        random.nextBytes(ivBytes);
        IV_BYTES = ivBytes;
    }

    private static void go1() {
        ivBytes1 = IV_BYTES;
    }

    private static void go2() {
        ivBytes2 = ivBytes1;
    }

    private static void go3() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey key = keyGenerator.generateKey();

        IvParameterSpec parameterSpec = new IvParameterSpec(ivBytes2);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(Arrays.toString(cipherBytes));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidAlgorithmParameterException {
        go1();
        go2();

        go3();
    }
}
