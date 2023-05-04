
# **CCA-Droid - Check Cryptographic API misuses related to CCA in Android apps**

*CCA-Droid* is a brand-new static analysis tool  to Check Cryptographic API misuses related to CCA in Android apps using more sophisticated cryptographic API misuse rules and backward program slicing techniques achieving a high code coverage.

This repository contains the *CCA-Droid* program implemented in Java and the dataset used in the paper submited to **CCS 2023**. Please refer to our paper for the details of the design and empirical results.

<br>

## Prerequisites

We confirmed that CCA-Droid runs on a 64-bit Ubuntu 18.04.5 LTS with openjdk 11.0.17 and 64-bit Windows 11 system with Java 11.0.17.

* Install Java >= 11.0.17

- ANDROID_SDK_HOME: Set the valid Android SDK installation path as the environment variable.

* To access the CCA-Droid source code, clone this repository using the following command:
  ```bash
  git clone https://github.com/AndroidSeclab/CCA-Droid.git
  ```
* Once the repository is cloned, navigate to the CCA-Droid directory. Then compile the source code and build the JAR file by running the below command:
  ```bash
   cd CCA-Droid
   ./gradlew clean assemble
  ```

* The compiled JAR file will be located at `build/libs/CCA-Droid.jar` within the CCA-Droid directory.

<br>

## How to run analysis using CCA-Droid

Performing app analysis using CCA-Droid is very simple. Just use the following command:
```bash
java -jar <CCA-Droid_jar_path> <apk_file_path> 
```
Once the analysis is complete, the results will be displayed in the console. However, depending on the size of the file and the number of rule violations detected, the analysis output can be lengthy and difficult to review. Thus, we recommend that you redirect the output to a file using the following command:

```bash
java -jar <CCA-Droid_jar_path> <apk_file_path> >> result.txt 
```

This will save the analysis results in a `result.txt` file that you can open with your preferred text editor for easier viewing and analysis.

<br>


## A DIY example: Performing app security analysis using CCA-Droid
In this example, we'll show you how to use CCA-Droid to analyze a sample app and interpret the results. Please follow these steps:
1. Place the CCA-Droid.jar file, which can be built following the straightforward instructions outlined in the [Prerequisites](https://github.com/AndroidSeclab/CCA-Droid#prerequisites) section, and the included sample.apk in the same folder for easy access.
2.  To start the analysis, open a terminal and enter the following command, as described in the [How to run analysis using CCA-Droid](https://github.com/AndroidSeclab/CCA-Droid#how-to-run-analysis-using-cca-droid) section:
    ```bash
    java -jar ./CCA-Droid.jar ./sample.apk >> result.txt
    ```

3. Once the analysis completes, open the `result.txt` file to examine the detailed analysis results.

   ```
   [*] Rule id : 9
   [*] Rule description : This slice uses short size RSA key
   [*] Caller : <org.cryptoapi.bench.insecureasymmetriccrypto.InsecureAsymmetricCipherABICase2: void main(java.lang.String[])>
   [*] Slicing signature : <java.security.KeyPairGenerator: void initialize(int)>
   [*] Parameter number : [0]
   [*] Target lines:
   Line{unit=$i0 = 1024, callerName=<org.cryptoapi.bench.insecureasymmetriccrypto.InsecureAsymmetricCipherABICase2: void go3()>, lineNumber=1}
   ```

4.  Each line means:

    `[*] Rule id`  : the number assigned to the detected rule

    `[*] Description`  : a brief description of the rule

    `[*] Caller`  : the method signature that calls the targeted cryptographic API

    `[*] Slicing signature`  : the method signature of the cryptographic API

    `[*] Parameter number`  : the parameter number of the cryptographic API (-1 means it's a local variable of the slicing signature)

    `[*] Target lines`  : the lines of code in Jimple related to the rule

5. Superb! CCA-Droid has identified that the sample app violates Rule-09. Please refer to our paper to learn how to fix this issue, and use CCA-Droid to diagnose other apps to ensure their security. Now, use CCA-Droid to diagnose your app's security and keep it secure!

<br>

## Dataset

We provide the extended [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench) dataset, which is used in our experiments in Sections 5.1 and 5.2. This dataset contains test cases that are relevant to the rules discussed in Section 2 (as shown in the below table), organized into separate folders for each rule. The bolded dataset represents additional test cases we provide for CCA analysis beyond those included in the CryptoAPI-Bench dataset.

| **Rule No.** | **Threat model** |                                        **Rule Description**                                         |                                                                      **Dataset**                                                                                                      |
|:------------:|:----------------:|:---------------------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|    Rule-01   |        CPA       |                           Do not use weak symmetric encryption algorithms                           |                           [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/brokencrypto)                            |
|    Rule-02   |        CPA       |                             Do not use the ECB mode with > 1 data block                             |                   [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/ecbcrypto) and **_ecbcrypto_**                   |
|    Rule-03   |        CPA       |                                     Do not use a hardcoded key                                      | [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/predictablecryptographickey) and **_predictablecryptographickey_** |
|    Rule-04   |        CPA       |                            Do not use a constant salt for key derivation                            |                 [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/staticsalts) and **_staticsalts_**                 |
|    Rule-05   |        CPA       |                      Do not use fewer than 1,000 iterations for key derivation                      |                           [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/pbeiteration)                            |
|    Rule-06   |        CPA       |                                 Do not use a constant seed for PRNG                                 |                         [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/predictableseeds)                          |
|    Rule-07   |        CPA       |                            Do not use an insecure PRNG for generating IV                            |                                                                                 **_untrustedprngiv_**                                                                                 |
|    Rule-08   |        CPA       |                    Do not use an insecure PRNG for generating an encryption key                     |                                                                                **_untrustedprngkey_**                                                                                 |
|    Rule-09   |        CPA       |                 Do not use a short key for RSA (< 2048 bits) or ECIES (< 256 bits)                  |    [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto) and **_insecureasymmetriccrypto_**    |
|    Rule-10   |        CPA       |                                           Do not reuse IV                                           |  [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/staticinitializationvector) and **_staticinitializationvector_**  |
|    Rule-11   |        CCA       |                             Do not use insecure padding schemes for RSA                             |                                                                            **_insecureasymmetricpadding_**                                                                            |
|    Rule-12   |        CCA       |                       Do not use Encrypt-and-MAC for authenticated encryption                       |                                                                                  **_encryptandmac_**                                                                                  |
|    Rule-13   |        CCA       | Do not use traditional block cipher modes of operation without MAC or GCM/CCM for authenticated enc |                                                                              **_insecureoperationmode_**                                                                              |
|    Rule-14   |        CCA       |                   Do not use a short key (< 128 bits) for MAC in Encrypt-then-MAC                   |                                                                                   **_shortmackey_**                                                                                   | 