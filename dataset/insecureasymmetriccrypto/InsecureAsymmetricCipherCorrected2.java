package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

public class InsecureAsymmetricCipherCorrected2 {
    private static void go() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        RSAKeyGenParameterSpec parameterSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(parameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-1andMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(plainBytes);

        System.out.println(new String(result));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidAlgorithmParameterException, NoSuchProviderException {
        go();
    }
}