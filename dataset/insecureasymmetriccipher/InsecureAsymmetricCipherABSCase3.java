package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class InsecureAsymmetricCipher3 {
    private final String keyStr;

    public InsecureAsymmetricCipher3(String defaultKeyStr) {
        keyStr = defaultKeyStr;
    }

    public void go(String passedKeyStr) throws UnsupportedEncodingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        passedKeyStr = keyStr;

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encodedKey = decoder.decode(passedKeyStr);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-1andMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }
}

public class InsecureAsymmetricCipherABSCase3 {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        String defaultKeyStr = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL5FIup9TSdTkPjvdWQ/0YqgbasfXDwd+wFWzwBaC6TlpNiffLVAcZqAlPkCobnPO4TZtPh1Lop3ns3SZJQmmMcCAwEAAQ==";
        String passedKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArIvpKK08Wun+lXdVyu3cxV+5VjBunwSojcMaDvrQZ0SAVWgmf3OtJtHM+3BVQyq1jIg8HBpJC3q4sh7i9zfEzbKZBFdnlXn2L7khhyI3sDt5ycIUdD3w5Q5/0Yi9Oe2mgWaGgt0rl1RnT/rxfSTbRkCj1Go/cYTkboxVg/BzUwL45PeU4Y9nsTXpEkMFrL/sEDrIvPwgIUSCiyAe3lDIfqgGKUaS5tUh2rmKFMLYk1b1yFuG/jMwSi9CjeKO/HpDM/mLh0Tj4Qgg5RP3M6iuZyTcraHAUS9wKuAQgepulNOIuarIsIh8r2WgUO+ODjOh2wBgQW+njoDHQ9UMhyA3XwIDAQAB";

        InsecureAsymmetricCipher3 case4 = new InsecureAsymmetricCipher3(defaultKeyStr);
        case4.go(passedKeyStr);
    }
}