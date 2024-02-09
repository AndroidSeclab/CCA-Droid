package com.androidseclab.cryptoapibench.ecbcrypto;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class EcbInSymmCryptoABMCase2 {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] plainBytes = new byte[32];

        EcbInSymmCryptoABMC2 case2 = new EcbInSymmCryptoABMC2();
        case2.go(plainBytes);
    }
}