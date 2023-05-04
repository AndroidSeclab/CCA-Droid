package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

public class PredictableIVChecker extends BaseChecker {

    public PredictableIVChecker() {
        checkerName = getCheckerName(getClass());
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.spec.IvParameterSpec - void <init> */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.spec.IvParameterSpec: void <init>(byte[])>");
        criterion1.setTargetParamNums("0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.spec.IvParameterSpec: void <init>(byte[],int,int)>");
        criterion2.setTargetParamNums("0");
        list.add(criterion2);

        /* javax.crypto.spec.GCMParameterSpec - void <init>() */

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.spec.GCMParameterSpec: void <init>(int,byte[])>");
        criterion3.setTargetParamNums("1");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<javax.crypto.spec.GCMParameterSpec: void <init>(int,byte[],int,int)>");
        criterion4.setTargetParamNums("1");
        list.add(criterion4);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("0") == null ? slicesMap.get("1") : slicesMap.get("0");
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
            ruleId = "7";
            ruleDescription = "This slice uses an insecure random method for IV";
        } else {
            ruleId = "7-2";
            ruleDescription = "This slice uses a secure random method for IV";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}