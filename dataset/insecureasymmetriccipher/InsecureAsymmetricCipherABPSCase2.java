package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

public class InsecureAsymmetricCipherABPSCase2 {
    private static void go(int choice) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, NoSuchProviderException, InvalidAlgorithmParameterException {
        int keySize;
        if (choice > 1) {
            keySize = 2048;
        } else {
            keySize = 1024;
        }

        RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(parameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-1andMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidAlgorithmParameterException, NoSuchProviderException {
        int choice = 2;

        go(choice);
    }
}