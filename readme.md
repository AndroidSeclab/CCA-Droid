
# **CCA-Droid: Checking Cryptographic API Misuse Related to Chosen Plaintext and Ciphertext Attacks in Android Apps**

*CCA-Droid* is a brand-new static analysis tool to Check Cryptographic API misuses related to Chosen Plaintext and Ciphertext attacks in Android apps using more sophisticated cryptographic API misuse rules and backward program slicing techniques achieving a high code coverage.

This repository contains the *CCA-Droid* program implemented in Java and the dataset.

<br>

## Build CCA-Droid

We confirmed that CCA-Droid runs on a 64-bit Ubuntu 18.04.5 LTS with openjdk 11.0.17 and 64-bit Windows 11 system with Java 11.0.17.

* Install Java >= 11.0.17

* To access the CCA-Droid source code in the anonymous artifact repository, download the repository as a ZIP file.
  
* Extract the ZIP file and navigate to the CCA-Droid directory. Then compile the source code and build the JAR file by running the below command:
  ```bash
   cd CCA-Droid
   ./gradlew clean assemble
  ```

* The compiled JAR file will be located at build/libs/CCA-Droid-<version>-SNAPSHOT.jar within the CCA-Droid directory.
(Example: build/libs/CCA-Droid-240923-SNAPSHOT.jar)

<br>

## Configure misuse detection rules

To check cryptographic misuses in the app via CCA-Droid, CCA-Droid requires setting detection rules.

Each rule file mentioned in Section 2 is located in the `rule` folder. The meaning of each field in each rule file is as follows.

`slicingSignatures` : The method signature and parameter number that can be the slicing criteria to detect cryptographic misuses

`ruleID` : The number assigned to the rule

`description` : A brief description of the rule

`conditions` :  Describe detailed conditions for detection. The `insecure` field contains conditions for detecting misuse, and the `secure` field contains conditions for preventing false positives. Each condition field contains four subfields (`targetSchemeType`, `targetAlgorithms`, `targetSignatures`, and `targetConstant`).

`targetAlgorithms` : The crypto algorithms(e.g., DES) to find in the slices

`targetConstantRegex` : A regular expression used to search for a specific constant within slices

`targetConstantLength` : An expression-based condition (e.g., x<16) that defines the expected or required length of the constant found in the slices

`targetConstantSize` : An expression-based condition (e.g., x>=32) that defines the expected or required size (typically in bytes) of the constant found in the slices

`targetSignatures` : The method signatures to find in the slices

`targetSchemeTypes` : The authenticated encryption type(e.g., Encrypt-then-MAC) to find in the slices

<br>

## A DIY example: Performing app security analysis using CCA-Droid
In this example, we'll show you how to use CCA-Droid to analyze a sample app and interpret the results. Please follow these steps:
1. Place the generated JAR file (build/libs/CCA-Droid-<version>-SNAPSHOT.jar) and the rule folder in the project directory.
2. To start the analysis, open a terminal in the project root directory and enter the following command:
    ```bash
    java -jar build/libs/CCA-Droid-<version>-SNAPSHOT.jar -p /path/to/Android/Sdk/platforms -i dataset/sample.apk -r rule > result.txt
    ```
	
	**Option descriptions:**
	- -`p` : Path to the Android SDK platforms directory (e.g., /home/user/Android/Sdk/platforms)
	
	- `-i` : Input APK file to be analyzed
	
	- `-r` : Rule directory or file that defines detection logic
	
	- `> result.txt` : Redirects the output to result.txt

3. Once the analysis completes, open the `result.txt` file to examine the detailed analysis results.

   ```
   [*] Rule ID: 10-1
   [*] Description: This method uses a hardcoded IV
   [*] Caller name: <com.androidseclab.cryptoapibench.Crypto1: javax.crypto.spec.IvParameterSpec getIV(int)>
   [*] Target statement: <javax.crypto.spec.IvParameterSpec: void <init>(byte[])>
   [*] Target lines:
   <com.androidseclab.cryptoapibench.Crypto1: javax.crypto.spec.IvParameterSpec getIV(int)>:
   $r2 = "this_is_iv"
   ```

4.  Each line means:

    `[*] Rule ID`  : the number assigned to the detected rule

    `[*] Description`  : a brief description of the rule

    `[*] Caller name`  : the method signature that calls the targeted cryptographic API

    `[*] Target statement`  : the method signature of the cryptographic API

    `[*] Target lines`  : the lines of code in Jimple related to the rule

5. Awesome! CCA-Droid has identified that the sample app violates Rule-10. Please refer to our paper to learn how to fix this issue, and use CCA-Droid to diagnose other apps to ensure their security. Now, use CCA-Droid to diagnose your app's security and keep it secure!

<br>

## Dataset

We provide the extended [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench) dataset, which is used in our experiments in Sections 5.1 and 5.2. This dataset contains test cases that are relevant to the rules discussed in Section 2 (as shown in the below table), organized into separate folders for each rule. The bolded dataset represents additional test cases we provide for CCA analysis beyond those included in the CryptoAPI-Bench dataset.

| **Rule No.** | **Threat model** |                                            **Rule Description**                                            |                                                                      **Dataset**                                                                                                      |
|:------------:|:----------------:|:----------------------------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|    Rule-01   |        CPA       |                              Do not use weak symmetric encryption algorithms                               |                           [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/brokencrypto)                            |
|    Rule-02   |        CPA       |                                Do not use the ECB mode with > 1 data block                                 |                   [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/ecbcrypto) and **_ecbcrypto_**                   |
|    Rule-03   |        CPA       |                                         Do not use a hardcoded key                                         | [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/predictablecryptographickey) and **_predictablecryptographickey_** |
|    Rule-04   |        CPA       |                               Do not use a constant salt for key derivation                                |                 [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/staticsalts) and **_staticsalts_**                 |
|    Rule-05   |        CPA       |                         Do not use fewer than 1,000 iterations for key derivation                          |                           [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/pbeiteration)                            |
|    Rule-06   |        CPA       |                                    Do not use a constant seed for PRNG                                     |                         [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/predictableseeds)                          |
|    Rule-07   |        CPA       |                               Do not use an insecure PRNG for generating IV                                |                                                                                 **_untrustedprngiv_**                                                                                 |
|    Rule-08   |        CPA       |                        Do not use an insecure PRNG for generating an encryption key                        |                                                                                **_untrustedprngkey_**                                                                                 |
|    Rule-09   |        CPA       |                     Do not use a short key for RSA (< 2048 bits) or ECIES (< 256 bits)                     |    [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto) and **_insecureasymmetriccrypto_**    |
|    Rule-10   |        CPA       |                                              Do not reuse IV                                               |  [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/tree/master/src/main/java/org/cryptoapi/bench/staticinitializationvector) and **_staticinitializationvector_**  |
|    Rule-11   |        CCA       |                                Do not use insecure padding schemes for RSA                                 |                                                                            **_insecureasymmetricpadding_**                                                                            |
|    Rule-12   |        CCA       |                          Do not use Encrypt-and-MAC for authenticated encryption                           |                                                                                  **_encryptandmac_**                                                                                  |
|    Rule-13   |        CCA       | Do not use traditional block cipher modes of operation without MAC or GCM/CCM for authenticated encryption |                                                                              **_insecureoperationmode_**                                                                              |
|    Rule-14   |        CCA       |                      Do not use a short key (< 128 bits) for MAC in Encrypt-then-MAC                       |                                                                                   **_shortmackey_**                                                                                   | 
