package com.androidseclab.cryptoapibench.ecbcrypto;

import javax.crypto.*;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class EcbInSymmCryptoABICase5 {
    private static final byte[] PLAIN_BYTES = new byte[32];
    private static byte[] plainBytes1;
    private static byte[] plainBytes2;

    private static void go1() {
        plainBytes1 = PLAIN_BYTES;
    }

    private static void go2() {
        plainBytes2 = plainBytes1;
    }

    private static void go3() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey key = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherBytes = cipher.doFinal(plainBytes2);

        System.out.println(Arrays.toString(cipherBytes));
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
        go1();
        go2();

        go3();
    }
}