package com.androidseclab.cryptoapibench.insecureasymmetriccrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

public class InsecureAsymmetricCipherABMC2 {
    public void go(int keySize) throws IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException {
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
}