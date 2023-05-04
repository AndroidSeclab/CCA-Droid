package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

public class PredictableKeyChecker extends BaseChecker {

    public PredictableKeyChecker() {
        checkerName = getCheckerName(getClass());
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.Cipher - init() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key)>");
        criterion1.setTargetParamNums("1");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.SecureRandom)>");
        criterion2.setTargetParamNums("1");
        list.add(criterion2);

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec)>");
        criterion3.setTargetParamNums("1");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec,java.security.SecureRandom)>");
        criterion4.setTargetParamNums("1");
        list.add(criterion4);

        SlicingCriterion criterion5 = new SlicingCriterion();
        criterion5.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.AlgorithmParameters)>");
        criterion5.setTargetParamNums("1");
        list.add(criterion5);

        SlicingCriterion criterion6 = new SlicingCriterion();
        criterion6.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.AlgorithmParameters,java.security.SecureRandom)>");
        criterion6.setTargetParamNums("1");
        list.add(criterion6);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("1");

        for (ArrayList<Line> s : slices) {
            ArrayList<Line> insecureLines = findInsecureRandomLines(s);
            if (!insecureLines.isEmpty()) {
                printResult(slicingCriterion, insecureLines, true);
                continue;
            }

            ArrayList<Line> secureLines = findSecureRandomLines(s);
            if (!secureLines.isEmpty()) {
                printResult(slicingCriterion, secureLines, false);
            }
        }
    }

    private ArrayList<Line> findInsecureRandomLines(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<java.util.Random: void nextBytes(byte[])>");
        targetSignatures.add("<java.util.Random: int nextInt()>");
        targetSignatures.add("<android.os.SystemClock: long uptimeMillis()>");
        targetSignatures.add("<android.os.SystemClock: long elapsedRealtime()>");

        return findTargetSignatureLines(slice, targetSignatures);
    }

    private ArrayList<Line> findSecureRandomLines(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<java.security.SecureRandom: void nextBytes(byte[])>");
        targetSignatures.add("<java.security.SecureRandom: int nextInt()>");
        targetSignatures.add("<javax.crypto.KeyGenerator: javax.crypto.SecretKey generateKey()>");

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
            ruleId = "8";
            ruleDescription = "This slice uses an insecure random method for key";
        } else {
            ruleId = "8-2";
            ruleDescription = "This slice uses a secure random method for key";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}