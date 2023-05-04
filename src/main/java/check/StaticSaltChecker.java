package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

public class StaticSaltChecker extends BaseChecker {

    public StaticSaltChecker() {
        checkerName = getCheckerName(getClass());
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.spec.PBEKeySpec - void <init>() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.spec.PBEKeySpec: void <init>(char[],byte[],int)>");
        criterion1.setTargetParamNums("1");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.spec.PBEKeySpec: void <init>(char[],byte[],int,int)>");
        criterion2.setTargetParamNums("1");
        list.add(criterion2);

        /* javax.crypto.spec.PBEParameterSpec - void <init>() */

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.spec.PBEParameterSpec: void <init>(byte[],int)>");
        criterion3.setTargetParamNums("0");
        list.add(criterion3);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("0") == null ? slicesMap.get("1") : slicesMap.get("0");
        for (ArrayList<Line> s : slices) {
            ArrayList<Line> randomLines = findRandomLines(s);
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
    }

    private ArrayList<Line> findRandomLines(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<java.util.Random: void nextBytes(byte[])>");
        targetSignatures.add("<java.util.Random: int nextInt()>");
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
            ruleId = "4";
            ruleDescription = "This slice uses static salt for PBE";
        } else {
            ruleId = "4-2";
            ruleDescription = "This slice uses random salt for PBE";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}