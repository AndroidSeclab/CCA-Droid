package com.androidseclab.cryptoapibench.untrustedprngiv;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

public class UnsafePRNGForIVABMCCase1 {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] ivBytes = new byte[16];
        Random random = new Random();
        random.nextBytes(ivBytes);

        UnsafePRNGForIVABMC1 case2 = new UnsafePRNGForIVABMC1();
        case2.go(ivBytes);
    }
}
