package com.androidseclab.cryptoapibench.untrustedprngkey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class UnsafePRNGForKeyABMCCase1 {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] keyBytes = new byte[16];
        Random random = new Random();
        random.nextBytes(keyBytes);

        UnsafePRNGForKeyABMC1 case2 = new UnsafePRNGForKeyABMC1();
        case2.go(keyBytes);
    }
}