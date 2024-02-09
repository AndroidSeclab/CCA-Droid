package com.androidseclab.cryptoapibench.shortmackey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class ShortMacKeyABMCCase2 {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        byte[] keyBytes = new byte[15];
        SecureRandom random = new SecureRandom();
        random.nextBytes(keyBytes);

        ShortMacKeyABMC2 case2 = new ShortMacKeyABMC2();
        case2.go(keyBytes);
    }
}