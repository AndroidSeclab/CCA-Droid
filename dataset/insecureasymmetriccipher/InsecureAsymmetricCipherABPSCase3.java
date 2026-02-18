package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class InsecureAsymmetricCipherABPSCase3 {
    private static void go(int choice) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        PublicKey publicKey;

        if (choice > 1) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
        } else {
            Base64.Decoder decoder = Base64.getDecoder();

            String publicKeyStr = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL5FIup9TSdTkPjvdWQ/0YqgbasfXDwd+wFWzwBaC6TlpNiffLVAcZqAlPkCobnPO4TZtPh1Lop3ns3SZJQmmMcCAwEAAQ==";
            byte[] encodedKey1 = decoder.decode(publicKeyStr);

            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey1);
            KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
            publicKey = keyFactory1.generatePublic(x509EncodedKeySpec);
        }

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-1andMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        int choice = 2;

        go(choice);
    }
}