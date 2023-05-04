package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

import static java.lang.Integer.parseInt;

public class PBEIterationChecker extends BaseChecker {

    public PBEIterationChecker() {
        checkerName = getCheckerName(getClass());
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.spec.PBEKeySpec - void <init>() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.spec.PBEKeySpec: void <init>(char[],byte[],int)>");
        criterion1.setTargetParamNums("2");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.spec.PBEKeySpec: void <init>(char[],byte[],int,int)>");
        criterion2.setTargetParamNums("2");
        list.add(criterion2);

        /* javax.crypto.spec.PBEParameterSpec - void <init>() */

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.spec.PBEParameterSpec: void <init>(byte[],int)>");
        criterion3.setTargetParamNums("1");
        list.add(criterion3);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<ArrayList<Line>> slices = slicesMap.get("1") == null ? slicesMap.get("2") : slicesMap.get("1");

        for (ArrayList<Line> s : slices) {
            ArrayList<Line> constantLines = findConstantLines(s, "[0-9]{1,10}", false);
            for (Line l : constantLines) {
                try {
                    int iterCount = parseInt(extractValue(l));
                    boolean hasVulnerable = iterCount < 1000;

                    printResult(slicingCriterion, constantLines, iterCount, hasVulnerable);
                } catch (NumberFormatException ignored) {

                }
            }
        }
    }

    private void printResult(SlicingCriterion slicingCriterion, ArrayList<Line> targetLines, int iterCount, boolean hasVulnerable) {
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
            ruleId = "5";
            ruleDescription = "This slice uses short PBE iteration count";
        } else {
            ruleId = "5-2";
            ruleDescription = "This slice uses enough PBE iteration count";
        }

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("iterCount", iterCount);
        printResult(ruleId, ruleDescription, slicingCriterion, resultMap, tempLines);
    }
}