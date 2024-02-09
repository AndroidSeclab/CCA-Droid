package com.androidseclab.cryptoapibench.insecureasymmetricpadding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;

public class InsecurePaddingABICase6 {
    private static void go1(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        go2(algorithm);
    }

    private static void go2(String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        String algorithm = "RSA/ECB/PKCS1Padding";

        go1(algorithm);
    }
}