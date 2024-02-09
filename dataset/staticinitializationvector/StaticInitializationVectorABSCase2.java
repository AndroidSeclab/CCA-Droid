package com.androidseclab.cryptoapibench.staticinitializationvector;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

class StaticInitializationVector2 {
    private final byte[] ivBytes;

    public StaticInitializationVector2(byte[] defaultIVBytes) {
        ivBytes = defaultIVBytes;
    }

    public void go(byte[] passedIVBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        passedIVBytes = ivBytes;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey key = keyGenerator.generateKey();

        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, passedIVBytes);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(Arrays.toString(cipherBytes));
    }
}

public class StaticInitializationVectorABSCase2 {
    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        String defaultIVStr = "abcde";
        byte[] defaultIVBytes = defaultIVStr.getBytes();
        byte[] passedIVBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(passedIVBytes);

        StaticInitializationVector2 case2 = new StaticInitializationVector2(defaultIVBytes);
        case2.go(passedIVBytes);
    }
}