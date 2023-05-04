package check;

import model.Line;
import model.Pair;
import model.SlicingCriterion;
import soot.Unit;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;

import static check.BaseChecker.SchemeType.*;
import static utils.SootUnit.*;

public class EncryptAndMACChecker extends BaseChecker {

    public EncryptAndMACChecker() {
        checkerName = getClass().getName();
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.Mac - doFinal() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.Mac: byte[] doFinal()>");
        criterion1.setTargetStatement2("<javax.crypto.Mac: void update(byte[])>");
        criterion1.setTargetParamNums("0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.Mac: byte[] doFinal()>");
        criterion2.setTargetStatement2("<javax.crypto.Mac: void update(byte[],int,int)>");
        criterion2.setTargetParamNums("0");
        list.add(criterion2);

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.Mac: byte[] doFinal(byte[])>");
        criterion3.setTargetParamNums("0");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<javax.crypto.Mac: void doFinal(byte[],int)>");
        criterion4.setTargetStatement2("<javax.crypto.Mac: void update(byte[])>");
        criterion4.setTargetParamNums("0");
        list.add(criterion4);

        SlicingCriterion criterion5 = new SlicingCriterion();
        criterion5.setTargetStatement1("<javax.crypto.Mac: void doFinal(byte[],int)>");
        criterion5.setTargetStatement2("<javax.crypto.Mac: void update(byte[],int,int)>");
        criterion5.setTargetParamNums("0");
        list.add(criterion5);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("0");
        for (ArrayList<Line> s : slices) {
            Pair<ArrayList<Line>, SchemeType> pair1 = findMACScheme1(s);
            if (pair1 != null) {
                ArrayList<Line> targetLines = pair1.getKey();
                SchemeType schemeType = pair1.getValue();
                schemeTypeMap.put(s, schemeType);

                boolean hasVulnerable = schemeType == NotDecided || schemeType == EncryptandMAC;
                printResult(slicingCriterion, targetLines, schemeType, hasVulnerable);
                continue;
            }

            Pair<ArrayList<Line>, SchemeType> pair2 = findMACScheme2(s);
            if (pair2 != null) {
                ArrayList<Line> targetLines = pair2.getKey();
                SchemeType schemeType = pair2.getValue();
                schemeTypeMap.put(s, schemeType);

                boolean hasVulnerable = schemeType == EncryptandMAC;
                printResult(slicingCriterion, targetLines, schemeType, hasVulnerable);
                continue;
            }

            Pair<ArrayList<Line>, SchemeType> pair3 = findMACScheme3(s);
            if (pair3 != null) {
                ArrayList<Line> targetLines = pair3.getKey();
                SchemeType schemeType = pair3.getValue();
                schemeTypeMap.put(s, schemeType);

                boolean hasVulnerable = schemeType == EncryptandMAC;
                printResult(slicingCriterion, targetLines, schemeType, hasVulnerable);
            }
        }
    }

    private ArrayList<String> getCipherSignatures() {
        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<java.io.ByteArrayOutputStream: byte[] toByteArray()>");
        targetSignatures.add("<javax.crypto.Cipher: byte[] doFinal(byte[])>");
        targetSignatures.add("<javax.crypto.Cipher: int doFinal(byte[],int)>");
        targetSignatures.add("<javax.crypto.Cipher: byte[] doFinal(byte[],int,int)>");
        targetSignatures.add("<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[])>");
        targetSignatures.add("<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[],int)>");

        return targetSignatures;
    }

    private Pair<ArrayList<Line>, SchemeType> findMACScheme1(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = getCipherSignatures();
        ArrayList<Line> cipherLines = findSignatures(slice, targetSignatures);
        if (cipherLines.isEmpty()) {
            return null;
        }

        Line cipherLine = cipherLines.get(0);
        Unit cipherUnit = cipherLine.getUnit();
        String cipherCallerName = cipherLine.getCallerName();
        Line macLine = slice.get(slice.size() - 1);
        Unit macUnit = macLine.getUnit();
        String macCallerName = macLine.getCallerName();

        ArrayList<Line> targetLines = new ArrayList<>();
        targetLines.add(cipherLine);
        targetLines.add(macLine);

        if (!cipherCallerName.equals(macCallerName)) {
            return new Pair<>(targetLines, EncryptthenMAC);
        }

        ArrayList<String> cipherParamValues = getParamValues(cipherUnit);
        ArrayList<String> macParamValues = getParamValues(macUnit);

        int cipherUnitType = getUnitType(cipherUnit);
        String targetVariable;
        if ((cipherUnitType & ASSIGN) == ASSIGN) {
            targetVariable = getLeftValueStr(cipherUnit, ASSIGN);
        } else {
            targetVariable = cipherParamValues.get(0);
        }

        SchemeType schemeType = macParamValues.contains(targetVariable) ? EncryptthenMAC : EncryptandMAC;
        schemeType = (schemeType == null) ? NotDecided : schemeType;
        return new Pair<>(targetLines, schemeType);
    }

    private Pair<ArrayList<Line>, SchemeType> findMACScheme2(ArrayList<Line> slice) {
        Line cipherLine = findCipherContainedLine(slice);
        if (cipherLine == null) {
            return null;
        }

        Unit cipherUnit = cipherLine.getUnit();
        Line macLine = slice.get(slice.size() - 1);
        Unit macUnit = macLine.getUnit();

        ArrayList<Line> targetLines = new ArrayList<>();
        targetLines.add(cipherLine);
        targetLines.add(macLine);

        SchemeType schemeType;
        int cipherUnitType = getUnitType(cipherUnit);
        String targetVariable;
        if ((cipherUnitType & ASSIGN) == ASSIGN) {
            targetVariable = getLeftValueStr(cipherUnit, ASSIGN);
        } else {
            ArrayList<String> paramValues = getParamValues(cipherUnit);
            targetVariable = paramValues.get(0);
        }

        ArrayList<String> cipherParamValues = getParamValues(cipherUnit);
        schemeType = cipherParamValues.contains(targetVariable) ? EncryptthenMAC : EncryptandMAC;
        return new Pair<>(targetLines, schemeType);
    }

    private Pair<ArrayList<Line>, SchemeType> findMACScheme3(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = getCipherSignatures();
        for (String t : targetSignatures) { // To detect E&M, any checker contains doFinal criteria be required!
            ArrayList<ArrayList<Line>> slices = slicer.findSlices(t, slice);
            if (slices.isEmpty()) {
                continue;
            }

            ArrayList<Line> targetLines = new ArrayList<>();
            for (ArrayList<Line> s : slices) {
                HashSet<Line> set1 = new HashSet<>(slice);
                HashSet<Line> set2 = new HashSet<>(s);
                set1.retainAll(set2);
                if (set1.isEmpty()) {
                    continue;
                }

                targetLines.addAll(set1);
                return new Pair<>(targetLines, EncryptandMAC);
            }
        }

        return null;
    }

    private Line findCipherContainedLine(ArrayList<Line> slice) {
        ArrayList<String> targetSignatures = getCipherSignatures();

        Line cipherLine = null;
        int sliceSize = slice.size();
        for (int i = sliceSize - 1; i > -1; i--) {
            Line line = slice.get(i);
            int unitType = line.getUnitType();
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            Unit unit = line.getUnit();
            String signature = getSignature(unit);
            ArrayList<ArrayList<Line>> slices = findAssignInvokeSlices(signature);
            for (ArrayList<Line> s : slices) {
                ArrayList<Line> targetLines = findTargetSignatureLines(s, targetSignatures);
                if (targetLines.isEmpty()) {
                    continue;
                }

                cipherLine = line;
                break;
            }

            if (cipherLine != null) {
                break;
            }
        }

        return cipherLine;
    }

    private void printResult(SlicingCriterion slicingCriterion, ArrayList<Line> targetLines, SchemeType schemeType, boolean hasVulnerable) {
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
            ruleId = "12";
            ruleDescription = "This slice uses Encrypt-and-MAC scheme or cannot decide any scheme";
        } else {
            ruleId = "12-2";
            ruleDescription = "This slice is Encrypt-then-MAC";
        }

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("schemeType", schemeType);
        printResult(ruleId, ruleDescription, slicingCriterion, resultMap, tempLines);
    }
}