package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

public class HardcodedIVChecker extends BaseChecker {

    public HardcodedIVChecker() {
        checkerName = getClass().getName();
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.spec.IvParameterSpec: void <init>(byte[])>");
        criterion1.setTargetParamNums("0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.spec.IvParameterSpec: void <init>(byte[],int,int)>");
        criterion2.setTargetParamNums("0");
        list.add(criterion2);

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
        ArrayList<ArrayList<Line>> slices1 = slicesMap.get("0");
        if (slices1 != null) {
            for (ArrayList<Line> s : slices1) {
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

        ArrayList<ArrayList<Line>> slices2 = slicesMap.get("1");
        if (slices2 != null) {
            for (ArrayList<Line> s : slices2) {
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
            ruleId = "10";
            ruleDescription = "This slice uses a hardcoded IV";
        } else {
            ruleId = "10-2";
            ruleDescription = "This slice uses a random IV";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}