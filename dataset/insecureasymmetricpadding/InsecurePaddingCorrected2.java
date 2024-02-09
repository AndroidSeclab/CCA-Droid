package com.androidseclab.cryptoapibench.insecureasymmetricpadding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.IOException;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;

public class InsecurePaddingCorrected2 {
    private static void go() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Encrypt message
        PublicKey publicKey = keyPair.getPublic();

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        OAEPParameterSpec parameterSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(new String(cipherBytes));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidAlgorithmParameterException {
        go();
    }
}