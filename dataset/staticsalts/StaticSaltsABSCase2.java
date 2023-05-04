package com.androidseclab.cryptoapibench.staticsalts;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

class CryptoStaticSalts2 {
    private final byte[] saltBytes;

    public CryptoStaticSalts2(byte[] defaultSaltBytes) {
        saltBytes = defaultSaltBytes;
    }

    public void go(byte[] passedSaltBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        passedSaltBytes = saltBytes;

        String passwordStr = "Secret Password";
        char[] password = passwordStr.toCharArray();

        byte[] saltBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(saltBytes);

        PBEKeySpec keySpec = new PBEKeySpec(password, passedSaltBytes, 1000);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEwithHmacSHA512AndAES_256");
        SecretKey key = keyFactory.generateSecret(keySpec);
        PBEParameterSpec parameterSpec = new PBEParameterSpec(saltBytes, 1000);

        String message = "Secret Message";
        byte[] plainBytes = message.getBytes();

        Cipher cipher = Cipher.getInstance("PBEwithHmacSHA512AndAES_256");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        System.out.println(Arrays.toString(cipherBytes));
    }
}

public class StaticSaltsABSCase2 {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] defaultSaltBytes = {(byte) 0xaa};
        byte[] passedSaltBytes = {(byte) 0xbb};

        CryptoStaticSalts2 case2 = new CryptoStaticSalts2(defaultSaltBytes);
        case2.go(passedSaltBytes);
    }
}