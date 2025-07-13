package com.androidseclab.cryptoapibench.untrustedprngiv;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

class UnsafePRNGForIV1 {
    private final byte[] ivBytes;

    public UnsafePRNGForIV1(byte[] defaultIVBytes) {
        ivBytes = defaultIVBytes;
    }

    public void go(byte[] passedSaltBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        passedSaltBytes = ivBytes;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey key = keyGenerator.generateKey();

        IvParameterSpec parameterSpec = new IvParameterSpec(passedSaltBytes);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(Arrays.toString(cipherBytes));
    }
}

public class UnsafePRNGForIVABSCase1 {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] defaultIVBytes = new byte[16];
        Random random1 = new Random();
        random1.nextBytes(defaultIVBytes);

        byte[] passedIVBytes = new byte[16];
        SecureRandom random2 = new SecureRandom();
        random2.nextBytes(passedIVBytes);

        UnsafePRNGForIV1 case2 = new UnsafePRNGForIV1(defaultIVBytes);
        case2.go(passedIVBytes);
    }
}