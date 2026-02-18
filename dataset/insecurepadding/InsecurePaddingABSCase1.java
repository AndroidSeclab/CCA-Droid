package com.androidseclab.cryptoapibench.insecureasymmetricpadding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;

class InsecurePadding1 {
    private final String algorithm;

    public InsecurePadding1(String defaultAlgorithm) {
        algorithm = defaultAlgorithm;
    }

    public void go(String passedAlgorithm) throws UnsupportedEncodingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        passedAlgorithm = algorithm;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance(passedAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }
}

public class InsecurePaddingABSCase1 {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        String defaultAlgorithm = "RSA";
        String passedAlgorithm = "RSA/ECB/OAEPwithSHA-1andMGF1Padding";

        InsecurePadding1 case1 = new InsecurePadding1(defaultAlgorithm);
        case1.go(passedAlgorithm);
    }
}