package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

class InsecureAsymmetricCipher2 {
    private final int keySize;

    public InsecureAsymmetricCipher2(int defaultKeySize) {
        keySize = defaultKeySize;
    }

    public void go(int passedKeySize) throws UnsupportedEncodingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        passedKeySize = keySize;

        RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(passedKeySize, RSAKeyGenParameterSpec.F4);
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
}

public class InsecureAsymmetricCipherABSCase2 {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        int defaultKeySize = 1024;
        int passedKeySize = 2048;

        InsecureAsymmetricCipher2 case3 = new InsecureAsymmetricCipher2(defaultKeySize);
        case3.go(passedKeySize);
    }
}