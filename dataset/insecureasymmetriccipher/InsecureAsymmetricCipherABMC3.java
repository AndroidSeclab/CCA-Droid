package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class InsecureAsymmetricCipherABMC3 {
    public void go(String publicKeyStr) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encodedKey = decoder.decode(publicKeyStr);
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
}