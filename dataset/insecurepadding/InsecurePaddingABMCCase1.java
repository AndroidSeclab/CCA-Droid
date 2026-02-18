package com.androidseclab.cryptoapibench.insecureasymmetricpadding;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class InsecurePaddingABMCCase1 {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        String algorithm = "RSA";

        InsecurePaddingABMC1 case1 = new InsecurePaddingABMC1();
        case1.go(algorithm);
    }
}