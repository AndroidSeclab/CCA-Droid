package com.androidseclab.cryptoapibench.staticinitializationvector;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class StaticInitializationVectorABMCCase2 {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        String ivStr = "abcde";
        byte[] ivBytes = ivStr.getBytes();

        StaticInitializationVectorABMC2 case2 = new StaticInitializationVectorABMC2();
        case2.go(ivBytes);
    }
}