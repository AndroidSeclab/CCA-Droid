package com.androidseclab.cryptoapibench.insecureoperationmode;

import javax.crypto.*;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class InsecureOperationModeBBCase1 {
    private static void go() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey key = keyGenerator.generateKey();

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] result = cipher.doFinal(plainBytes);

        System.out.println(Arrays.toString(result));
    }


    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidAlgorithmParameterException {
        go();
    }
}