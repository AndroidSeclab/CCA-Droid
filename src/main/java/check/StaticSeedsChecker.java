package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

public class StaticSeedsChecker extends BaseChecker {

    public StaticSeedsChecker() {
        checkerName = getCheckerName(getClass());
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* java.util.Random - void <init> */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<java.util.Random: void <init>(long)>");
        criterion1.setTargetParamNums("0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<java.util.Random: void setSeed(long)>");
        criterion2.setTargetParamNums("0");
        list.add(criterion2);

        /* java.security.SecureRandom */

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<java.security.SecureRandom: void <init>(byte[])>");
        criterion3.setTargetParamNums("0");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<java.security.SecureRandom: void setSeed(long)>");
        criterion4.setTargetParamNums("0");
        list.add(criterion4);

        SlicingCriterion criterion5 = new SlicingCriterion();
        criterion5.setTargetStatement1("<java.security.SecureRandom: void setSeed(byte[])>");
        criterion5.setTargetParamNums("0");
        list.add(criterion5);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("0");
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

            ArrayList<Line> constantLines = findConstantLines(s, "^((?!(?i)(DES|AES|RSA|HMAC)).)*$", true);
            if (!constantLines.isEmpty()) {
                printResult(slicingCriterion, constantLines, true);
            }
        }
    }

    private ArrayList<Line> findRandomLines(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<java.lang.System: long nanoTime()>");
        targetSignatures.add("<java.util.Random: int nextInt()>");
        targetSignatures.add("<java.util.Random: long nextLong()>");
        targetSignatures.add("<java.util.Random: void nextBytes(byte[])>");
        targetSignatures.add("<java.security.SecureRandom: void nextBytes(byte[])>");
        targetSignatures.add("<java.security.SecureRandom: int nextInt()>");
        targetSignatures.add("<java.security.SecureRandom: long nextLong()>");

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
            ruleId = "6";
            ruleDescription = "This slice uses a static seeds";
        } else {
            ruleId = "6-2";
            ruleDescription = "This slice uses a random seeds";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}