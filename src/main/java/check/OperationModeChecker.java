package check;

import model.Line;
import model.SlicingCriterion;
import utils.Permutation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

import static java.lang.Integer.max;

public class OperationModeChecker extends BaseChecker {

    public OperationModeChecker() {
        checkerName = getClass().getName();
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.Cipher - doFinal() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.Cipher: byte[] doFinal(byte[])>");
        criterion1.setTargetParamNums("-1,0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.Cipher: int doFinal(byte[],int)>");
        criterion2.setTargetParamNums("-1,0");
        list.add(criterion2);

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.Cipher: byte[] doFinal(byte[],int,int)>");
        criterion3.setTargetParamNums("-1,0");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[])>");
        criterion4.setTargetParamNums("-1,0");
        list.add(criterion4);

        SlicingCriterion criterion5 = new SlicingCriterion();
        criterion5.setTargetStatement1("<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[],int)>");
        criterion5.setTargetParamNums("-1,0");
        list.add(criterion5);

        /* javax.crypto.CipherOutputStream - void write() */

        SlicingCriterion criterion6 = new SlicingCriterion();
        criterion6.setTargetStatement1("<javax.crypto.CipherOutputStream: void write(byte[])>");
        criterion6.setTargetParamNums("-1,0");
        list.add(criterion6);

        SlicingCriterion criterion7 = new SlicingCriterion();
        criterion7.setTargetStatement1("<javax.crypto.CipherOutputStream: void write(byte[],int,int)>");
        criterion7.setTargetParamNums("-1,0");
        list.add(criterion7);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices1 = slicesMap.get("-1"); // To use this rule, EncryptAndMacChecker is required!
        ArrayList<ArrayList<Line>> slices2 = slicesMap.get("0");
        int sliceCount1 = slices1.size();
        int sliceCount2 = slices2.size();
        int sliceCount = max(sliceCount1, sliceCount2);

        ArrayList<int[]> cases = Permutation.getAllCases(sliceCount, slicesMap.size());
        for (int[] arr : cases) {
            int i = arr[0];
            ArrayList<Line> slice1 = getSlice(slices1, i);
            ArrayList<Line> algorithmLines1 = findConstantLines(slice1, "(?i)(AES.*)", false);
            if (algorithmLines1.isEmpty()) {
                continue;
            }

            Line algorithmLine = algorithmLines1.get(0);
            String algorithm = extractValue(algorithmLine);
            ArrayList<Line> algorithmLines2 = findConstantLines(slice1, "(?i)(.*GCM.*)", false);
            if (!algorithmLines2.isEmpty()) {
                printResult(slicingCriterion, algorithmLines2, algorithm, false);
                continue;
            }

            int j = arr[1];
            ArrayList<Line> slice2 = getSlice(slices2, j);
            if (slice2.isEmpty()) {
                continue;
            }

            boolean hasVulnerable = !existsRelatedSlice(slice2);
            printResult(slicingCriterion, slice2, algorithm, hasVulnerable);
        }
    }

    private boolean existsRelatedSlice(ArrayList<Line> slice) {
        boolean flag = false;

        String encryptAndMacCheckerName = EncryptAndMACChecker.class.getName();
        ArrayList<LinkedHashSet<Line>> listOfTargetLines = targetLinesMap.get(encryptAndMacCheckerName);
        if (listOfTargetLines == null) {
            return false;
        }

        Line lastLine = slice.get(slice.size() - 1);
        for (LinkedHashSet<Line> l : listOfTargetLines) {
            if (!l.contains(lastLine)) {
                continue;
            }

            flag = true;
            break;
        }

        return flag;
    }

    private void printResult(SlicingCriterion slicingCriterion, ArrayList<Line> targetLines, String algorithm, boolean hasVulnerable) {
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
            ruleId = "13";
            ruleDescription = "This slice uses a insecure for CCA";
        } else {
            ruleId = "13-2";
            ruleDescription = "This slice uses a secure for CCA";
        }

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("algorithm", algorithm);
        printResult(ruleId, ruleDescription, slicingCriterion, resultMap, tempLines);
    }
}