package check;

import model.Line;
import model.Pair;
import model.SlicingCriterion;

import java.math.BigInteger;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

import static java.lang.Integer.parseInt;

public class RSAKeySizeChecker extends BaseChecker {

    public RSAKeySizeChecker() {
        checkerName = getClass().getName();
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<java.security.KeyPairGenerator: void initialize(int)>");
        criterion1.setTargetParamNums("0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<java.security.KeyPairGenerator: void initialize(int,java.security.SecureRandom)>");
        criterion2.setTargetParamNums("0");
        list.add(criterion2);

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<java.security.spec.RSAKeyGenParameterSpec: void <init>(int,java.math.BigInteger)>");
        criterion3.setTargetParamNums("0");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<java.security.spec.X509EncodedKeySpec: void <init>(byte[])>");
        criterion4.setTargetParamNums("0");
        list.add(criterion4);

        SlicingCriterion criterion5 = new SlicingCriterion();
        criterion5.setTargetStatement1("<java.security.spec.PKCS8EncodedKeySpec: void <init>(byte[])>");
        criterion5.setTargetParamNums("0");
        list.add(criterion5);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("0");
        for (ArrayList<Line> s : slices) {
            Pair<ArrayList<Line>, Integer> pair1 = findKeySize(s);
            if (pair1 != null) {
                ArrayList<Line> targetLines = pair1.getKey();
                int keySize = pair1.getValue();
                if (keySize == 0) {
                    continue;
                }

                boolean hasVulnerable = keySize < 2048;
                printResult(slicingCriterion, targetLines, keySize, hasVulnerable);
                continue;
            }

            Pair<ArrayList<Line>, Integer> pair2 = findStringKey(s);
            if (pair2 != null) {
                ArrayList<Line> targetLines = pair2.getKey();
                int keySize = pair2.getValue();
                if (keySize == 0) {
                    continue;
                }

                boolean hasVulnerable = keySize < 2048;
                printResult(slicingCriterion, targetLines, keySize, hasVulnerable);
                continue;
            }

            Pair<ArrayList<Line>, Integer> pair3 = findByteArrayKey(s);
            if (pair3 != null) {
                ArrayList<Line> targetLines = pair3.getKey();
                int keySize = pair3.getValue();
                if (keySize == 0) {
                    continue;
                }

                boolean hasVulnerable = keySize < 2048;
                printResult(slicingCriterion, targetLines, keySize, hasVulnerable);
            }
        }
    }

    private Pair<ArrayList<Line>, Integer> findKeySize(ArrayList<Line> slice) {
        ArrayList<Line> targetLines = new ArrayList<>();
        int keySize = -1;

        ArrayList<Line> constantLines = findConstantLines(slice, "[0-9]{1,10}", false);
        for (Line l : constantLines) {
            String value = extractValue(l);
            if (value == null) {
                continue;
            }

            try {
                keySize = parseInt(value);
                if (keySize % 128 != 0) {
                    continue;
                }
            } catch (NumberFormatException ignored) {
                continue;
            }

            targetLines.add(l);
            break;
        }

        return (targetLines.isEmpty()) ? null : new Pair<>(targetLines, keySize);
    }

    private Pair<ArrayList<Line>, Integer> findStringKey(ArrayList<Line> slice) {
        ArrayList<Line> targetLines = new ArrayList<>();
        int keySize = -1;

        ArrayList<Line> constantLines = findConstantLines(slice, "^((?!(?i)(DES|AES|RSA|HMAC)).)*$", false);
        for (Line l : constantLines) {
            String value = extractValue(l);
            if (value == null) {
                continue;
            }

            RSAKey key = convertStringToRSAKey(value);
            if (key == null) {
                continue;
            }

            targetLines.add(l);
            BigInteger modulus = key.getModulus();
            keySize = modulus.bitLength();
            break;
        }

        return (targetLines.isEmpty()) ? null : new Pair<>(targetLines, keySize);
    }

    private Pair<ArrayList<Line>, Integer> findByteArrayKey(ArrayList<Line> slice) {
        ArrayList<Line> targetSlice = findConstantArraySlice(slice);
        if (targetSlice.isEmpty()) {
            return null;
        }

        RSAKey key = convertArrayToRSAKey(targetSlice);
        if (key == null) {
            return null;
        }

        BigInteger modulus = key.getModulus();
        int keySize = modulus.bitLength();

        return new Pair<>(targetSlice, keySize);
    }

    private void printResult(SlicingCriterion slicingCriterion, ArrayList<Line> targetLines, int keySize, boolean hasVulnerable) {
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
            ruleId = "9";
            ruleDescription = "This slice uses short size RSA key";
        } else {
            ruleId = "9-2";
            ruleDescription = "This slice uses enough size RSA key";
        }

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("keySize", keySize);
        printResult(ruleId, ruleDescription, slicingCriterion, resultMap, tempLines);
    }
}