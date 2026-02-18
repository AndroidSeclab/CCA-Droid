package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class InsecureAsymmetricCipherABICase7 {
    private static final String PUBLIC_KEY_STR = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL5FIup9TSdTkPjvdWQ/0YqgbasfXDwd+wFWzwBaC6TlpNiffLVAcZqAlPkCobnPO4TZtPh1Lop3ns3SZJQmmMcCAwEAAQ==";
    private static String publicKeyStr1;
    private static String publicKeyStr2;

    private static void go1() {
        publicKeyStr1 = PUBLIC_KEY_STR;
    }

    private static void go2() {
        publicKeyStr2 = publicKeyStr1;
    }

    private static void go3() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encodedKey = decoder.decode(publicKeyStr2);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-1andMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        go1();
        go2();

        go3();
    }
}