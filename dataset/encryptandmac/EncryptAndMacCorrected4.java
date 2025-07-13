package com.androidseclab.cryptoapibench.encryptandmac;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class EncryptAndMacCorrected4 {
    private static void go() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator1 = KeyGenerator.getInstance("AES");
        SecretKey key1 = keyGenerator1.generateKey();

        byte[] ivBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        IvParameterSpec parameterSpec = new IvParameterSpec(ivBytes);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key1, parameterSpec);

        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(byteOutputStream, cipher);
        cipherOutputStream.write(plainBytes);
        cipherOutputStream.close();
        byte[] cipherBytes = byteOutputStream.toByteArray();

        KeyGenerator keyGenerator2 = KeyGenerator.getInstance("HmacSHA1");
        SecretKey key2 = keyGenerator2.generateKey();

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key2);
        byte[] macBytes = mac.doFinal(cipherBytes);

        byte[] result = new byte[cipherBytes.length + macBytes.length];
        System.arraycopy(cipherBytes, 0, result, 0, cipherBytes.length);
        System.arraycopy(macBytes, 0, result, cipherBytes.length, macBytes.length);

        System.out.println(Arrays.toString(result));
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidAlgorithmParameterException {
        go();
    }
}