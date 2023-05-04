package check;

import model.Line;
import model.SlicingCriterion;
import org.graphstream.graph.Node;
import soot.Unit;

import java.util.*;

import static check.BaseChecker.SchemeType.EncryptthenMAC;
import static java.lang.Integer.parseInt;
import static utils.SootUnit.getArraySize;

public class MACKeySizeChecker extends BaseChecker {

    public MACKeySizeChecker() {
        checkerName = getClass().getName();
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.Mac: void init(java.security.Key)>");
        criterion1.setTargetParamNums("0");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.Mac: void init(java.security.Key,java.security.spec.AlgorithmParameterSpec)>");
        criterion2.setTargetParamNums("0");
        list.add(criterion2);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("0");
        for (ArrayList<Line> s : slices) {
            Node caller = slicingCriterion.getCaller();
            String callerName = caller.getId();
            ArrayList<ArrayList<Line>> tempSlices = findSlice(callerName);
            if (tempSlices.isEmpty()) {
                return;
            }

            ArrayList<Line> constantLines = findConstantLines(s, "^((?!(?i)(DES|AES|RSA|HMAC)|[0-9]+).)*$", true);
            if (!constantLines.isEmpty()) {
                for (Line l : constantLines) {
                    int keySize = getValueSize(l);
                    boolean hasVulnerable = keySize < 16;
                    printResult(slicingCriterion, constantLines, hasVulnerable);
                }
            } else {
                ArrayList<Line> constantSlice = findConstantArraySlice(s);
                if (constantSlice.isEmpty()) {
                    continue;
                }

                Line firstLine = constantSlice.get(0);
                Unit firstUnit = firstLine.getUnit();
                int keySize = parseInt(getArraySize(firstUnit));
                boolean hasVulnerable = keySize < 16;
                printResult(slicingCriterion, constantSlice, hasVulnerable);
            }
        }
    }

    private ArrayList<ArrayList<Line>> findSlice(String callerName) {
        ArrayList<String> targetStatements = new ArrayList<>();
        targetStatements.add("<javax.crypto.Mac: byte[] doFinal()>");
        targetStatements.add("<javax.crypto.Mac: void update(byte[])>");
        targetStatements.add("<javax.crypto.Mac: void update(byte[],int,int)>");
        targetStatements.add("<javax.crypto.Mac: byte[] doFinal()>");
        targetStatements.add("<javax.crypto.Mac: byte[] doFinal(byte[])>");
        targetStatements.add("<javax.crypto.Mac: void doFinal(byte[],int)>");

        ArrayList<ArrayList<Line>> slices = new ArrayList<>();
        Set<Map.Entry<ArrayList<Line>, SchemeType>> entries = schemeTypeMap.entrySet();

        for (String t : targetStatements) {
            ArrayList<ArrayList<Line>> tempSlices = slicer.findSlices(t, new ArrayList<>());
            for (ArrayList<Line> s : tempSlices) {
                Line lastLine = s.get(s.size() - 1);
                String targetCallerName = lastLine.getCallerName();
                if (!callerName.equals(targetCallerName)) {
                    continue;
                }

                for (Map.Entry<ArrayList<Line>, SchemeType> e : entries) {
                    ArrayList<Line> targetSlice = e.getKey();
                    if (!targetSlice.contains(lastLine)) {
                        continue;
                    }

                    SchemeType schemeType = e.getValue();
                    if (schemeType != EncryptthenMAC) {
                        continue;
                    }

                    slices.add(targetSlice);
                }
            }
        }

        return slices;
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
            ruleId = "14";
            ruleDescription = "This slice uses a short size key for MAC";
        } else {
            ruleId = "14-2";
            ruleDescription = "This slice uses a enough size for MAC";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}