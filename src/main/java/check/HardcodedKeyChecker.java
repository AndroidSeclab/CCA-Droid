package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

import static utils.SootUnit.getClassName;

public class HardcodedKeyChecker extends BaseChecker {

    public HardcodedKeyChecker() {
        checkerName = getClass().getName();
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.spec.PBEKeySpec - void <init>() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.spec.PBEKeySpec: void <init>(char[])>");
        criterion1.setTargetParamNums("0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.spec.PBEKeySpec: void <init>(char[],byte[],int)>");
        criterion2.setTargetParamNums("0");
        list.add(criterion2);

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.spec.PBEKeySpec: void <init>(char[],byte[],int,int)>");
        criterion3.setTargetParamNums("0");
        list.add(criterion3);

        /* javax.crypto.spec.DESKeySpec - void <init>() */

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<javax.crypto.spec.DESKeySpec: void <init>(byte[])>");
        criterion4.setTargetParamNums("0");
        list.add(criterion4);

        SlicingCriterion criterion5 = new SlicingCriterion();
        criterion5.setTargetStatement1("<javax.crypto.spec.DESKeySpec: void <init>(byte[],int)>");
        criterion5.setTargetParamNums("0");
        list.add(criterion5);

        /* javax.crypto.spec.SecretKeySpec - void <init>() */

        SlicingCriterion criterion6 = new SlicingCriterion();
        criterion6.setTargetStatement1("<javax.crypto.spec.SecretKeySpec: void <init>(byte[],java.lang.String)>");
        criterion6.setTargetParamNums("0");
        list.add(criterion6);

        SlicingCriterion criterion7 = new SlicingCriterion();
        criterion7.setTargetStatement1("<javax.crypto.spec.SecretKeySpec: void <init>(byte[],int,int,java.lang.String)>");
        criterion7.setTargetParamNums("0");
        list.add(criterion7);

        /* java.security.spec.PKCS8EncodedKeySpec - void <init>() */

        SlicingCriterion criterion8 = new SlicingCriterion();
        criterion8.setTargetStatement1("<java.security.spec.PKCS8EncodedKeySpec: void <init>(byte[])>");
        criterion8.setTargetParamNums("0");
        list.add(criterion8);

        /* <javax.crypto.Cipher - init() */

        SlicingCriterion criterion9 = new SlicingCriterion();
        criterion9.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key)>");
        criterion9.setTargetParamNums("1");
        list.add(criterion9);

        SlicingCriterion criterion10 = new SlicingCriterion();
        criterion10.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.AlgorithmParameters)>");
        criterion10.setTargetParamNums("1");
        list.add(criterion10);

        SlicingCriterion criterion11 = new SlicingCriterion();
        criterion11.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec)>");
        criterion11.setTargetParamNums("1");
        list.add(criterion11);

        SlicingCriterion criterion12 = new SlicingCriterion();
        criterion12.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec,java.security.SecureRandom)>");
        criterion12.setTargetParamNums("1");
        list.add(criterion12);

        SlicingCriterion criterion13 = new SlicingCriterion();
        criterion13.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.AlgorithmParameters,java.security.SecureRandom)>");
        criterion13.setTargetParamNums("1");
        list.add(criterion13);

        SlicingCriterion criterion14 = new SlicingCriterion();
        criterion14.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.SecureRandom)>");
        criterion14.setTargetParamNums("1");
        list.add(criterion14);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        String targetStatement = slicingCriterion.getTargetStatement1();
        String className = getClassName(targetStatement);
        boolean isKeySpec = className.endsWith("KeySpec");

        if (isKeySpec) {
            ArrayList<ArrayList<Line>> slices = slicesMap.get("0");
            for (ArrayList<Line> s : slices) {
                ArrayList<Line> randomLines = findRandomLines1(s);
                if (!randomLines.isEmpty()) {
                    printResult(slicingCriterion, randomLines, false);
                    continue;
                }

                ArrayList<Line> constantSlice = findConstantArraySlice(s);
                if (!constantSlice.isEmpty()) {
                    printResult(slicingCriterion, constantSlice, true);
                    continue;
                }

                ArrayList<Line> constantLines = findConstantLines(s, "^((?!(?i)(DES|AES|RSA|HMAC)|^[0-9]$).)*$", true);
                if (!constantLines.isEmpty()) {
                    printResult(slicingCriterion, constantLines, true);
                }
            }
        } else {
            ArrayList<ArrayList<Line>> slices = slicesMap.get("1");
            for (ArrayList<Line> s : slices) {
                ArrayList<Line> randomLines = findRandomLines2(s);
                if (!randomLines.isEmpty()) {
                    printResult(slicingCriterion, randomLines, false);
                }
            }
        }
    }

    private ArrayList<Line> findRandomLines1(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<java.lang.System: long currentTimeMillis()>");
        targetSignatures.add("<java.util.Random: int nextInt()>");
        targetSignatures.add("<java.util.Random: int nextInt(int)>");
        targetSignatures.add("<java.util.Random: long nextLong()>");
        targetSignatures.add("<java.util.Random: void nextBytes(byte[])>");
        targetSignatures.add("<java.security.SecureRandom int next(int)>");
        targetSignatures.add("<java.security.SecureRandom: int nextInt()>");
        targetSignatures.add("<java.security.SecureRandom: java.util.stream.IntStream ints()>");
        targetSignatures.add("<java.security.SecureRandom: void nextBytes(byte[])>");
        targetSignatures.add("<javax.crypto.KeyAgreement: byte[] generateSecret()>");

        return findTargetSignatureLines(slice, targetSignatures);
    }

    private ArrayList<Line> findRandomLines2(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<javax.crypto.KeyGenerator: javax.crypto.SecretKey generateKey()>");
        targetSignatures.add("<java.security.KeyPairGenerator: java.security.KeyPair generateKeyPair()>");
        targetSignatures.add("<java.security.KeyPairGenerator: java.security.KeyPair genKeyPair()>");

        return findTargetSignatureLines(slice, targetSignatures);
    }

    private void printResult(SlicingCriterion slicingCriterion, ArrayList<Line> targetLines, boolean hasVulnerable) {
        if (targetLines.isEmpty()) {
            return;
        }

        LinkedHashSet<Line> tempLines = new LinkedHashSet<>(targetLines);
        if (isDuplicateLines(checkerName, tempLines)) {
            return;
        }

        String ruleId;
        String ruleDescription;
        if (hasVulnerable) {
            ruleId = "3";
            ruleDescription = "This slice uses a hardcoded key";
        } else {
            ruleId = "3-2";
            ruleDescription = "This slice uses a random key";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}