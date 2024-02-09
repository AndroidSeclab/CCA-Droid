package com.androidseclab.cryptoapibench.insecureasymmetricpadding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;

public class InsecurePaddingABICase3 {
    private static final String ALGORITHM = "RSA";
    private static String algorithm1;
    private static String algorithm2;

    private static void go2() {
        algorithm1 = ALGORITHM;
    }

    private static void go3() {
        algorithm2 = algorithm1;
    }

    private static void go1() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance(algorithm2);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        go2();
        go3();

        go1();
    }
}