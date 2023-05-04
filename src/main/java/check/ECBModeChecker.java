package check;

import model.Line;
import model.SlicingCriterion;
import soot.Unit;
import utils.Permutation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

import static java.lang.Math.max;
import static utils.SootUnit.getParamValues;
import static utils.SootUnit.isVariableStr;

public class ECBModeChecker extends BaseChecker {

    public ECBModeChecker() {
        checkerName = getCheckerName(getClass());
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
        criterion3.setTargetParamNums("-1,2");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[])>");
        criterion4.setTargetParamNums("-1,2");
        list.add(criterion4);

        SlicingCriterion criterion5 = new SlicingCriterion();
        criterion5.setTargetStatement1("<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[],int)>");
        criterion5.setTargetParamNums("-1,2");
        list.add(criterion5);

        /* javax.crypto.CipherOutputStream - void write() */

        SlicingCriterion criterion6 = new SlicingCriterion();
        criterion6.setTargetStatement1("<javax.crypto.CipherOutputStream: void write(byte[])>");
        criterion6.setTargetParamNums("-1,0");
        list.add(criterion6);

        SlicingCriterion criterion7 = new SlicingCriterion();
        criterion7.setTargetStatement1("<javax.crypto.CipherOutputStream: void write(byte[],int,int)>");
        criterion7.setTargetParamNums("-1,2");
        list.add(criterion7);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices1 = slicesMap.get("-1");
        ArrayList<ArrayList<Line>> slices2 = slicesMap.get("0") == null ? slicesMap.get("2") : slicesMap.get("0");
        if (slices1 == null || slices2 == null) {
            return;
        }

        int sliceCount1 = slices1.size();
        int sliceCount2 = slices2.size();
        int sliceCount = max(sliceCount1, sliceCount2);

        ArrayList<int[]> cases = Permutation.getAllCases(sliceCount, slicesMap.size());
        for (int[] arr : cases) {
            int i = arr[0];
            ArrayList<Line> slice1 = getSlice(slices1, i);
            ArrayList<Line> algorithmLines = findConstantLines(slice1, "(?i)AES/ECB.*", false);
            if (algorithmLines.isEmpty()) {
                continue;
            }

            ArrayList<Line> targetLines = new ArrayList<>(algorithmLines);

            int j = arr[1];
            ArrayList<Line> slice2 = getSlice(slices2, j);
            int encryptedSize;
            if (slicesMap.containsKey("0")) {
                ArrayList<Line> tempLines = findConstantLines(slice2, "^((?!(?i)(DES|AES|RSA|HMAC)|^[0-9]+$).)*$", true);
                if (tempLines.isEmpty()) {
                    continue;
                }

                Line tempLine = tempLines.get(tempLines.size() - 1);
                targetLines.add(tempLine);
                encryptedSize = getValueSize(tempLine);
            } else {
                Line lastLine = slice2.get(slice2.size() - 1);
                targetLines.add(lastLine);

                Unit lastUnit = lastLine.getUnit();
                ArrayList<String> paramValues = getParamValues(lastUnit);
                String cipherSize = paramValues.get(2);
                if (isVariableStr(cipherSize)) {
                    continue;
                }

                encryptedSize = Integer.parseInt(cipherSize);
            }

            if (encryptedSize == -1) {
                continue;
            }

            boolean hasVulnerable = encryptedSize > 16;
            printResult(slicingCriterion, targetLines, encryptedSize, hasVulnerable);
        }
    }

    private void printResult(SlicingCriterion slicingCriterion, ArrayList<Line> targetLines, int encryptedSize, boolean hasVulnerable) {
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
            ruleId = "2";
            ruleDescription = "This slice uses the ECB algorithm and encrypts at least 1 block";
        } else {
            ruleId = "2-2";
            ruleDescription = "This slice uses a ECB algorithm, but encrypts only 1 block";
        }

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("encryptedSize", encryptedSize);
        printResult(ruleId, ruleDescription, slicingCriterion, resultMap, tempLines);
    }
}