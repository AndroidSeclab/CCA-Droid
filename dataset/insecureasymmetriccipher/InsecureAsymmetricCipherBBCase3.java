package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class InsecureAsymmetricCipherBBCase3 {
    private static void go() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        Base64.Decoder decoder = Base64.getDecoder();
        String publicKeyStr = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL5FIup9TSdTkPjvdWQ/0YqgbasfXDwd+wFWzwBaC6TlpNiffLVAcZqAlPkCobnPO4TZtPh1Lop3ns3SZJQmmMcCAwEAAQ==";
        byte[] encodedKey = decoder.decode(publicKeyStr);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-1andMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        go();
    }
}