package com.androidseclab.cryptoapibench.staticsalts;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class StaticSaltsABMCCase2 {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] saltBytes = {(byte) 0xa2};

        StaticSaltsABMC2 case2 = new StaticSaltsABMC2();
        case2.go(saltBytes);
    }
}