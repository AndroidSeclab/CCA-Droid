package check;

import model.Line;
import model.SlicingCriterion;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;

public class RSAPaddingChecker extends BaseChecker {

    public RSAPaddingChecker() {
        checkerName = getCheckerName(getClass());
    }

    @Override
    public ArrayList<SlicingCriterion> getSlicingCandidates() {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        /* javax.crypto.Cipher - init() */

        SlicingCriterion criterion1 = new SlicingCriterion();
        criterion1.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key)>");
        criterion1.setTargetParamNums("-1");
        list.add(criterion1);

        SlicingCriterion criterion2 = new SlicingCriterion();
        criterion2.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.AlgorithmParameters)>");
        criterion2.setTargetParamNums("-1");
        list.add(criterion2);

        SlicingCriterion criterion3 = new SlicingCriterion();
        criterion3.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec)>");
        criterion3.setTargetParamNums("-1");
        list.add(criterion3);

        SlicingCriterion criterion4 = new SlicingCriterion();
        criterion4.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.spec.AlgorithmParameterSpec,java.security.SecureRandom)>");
        criterion4.setTargetParamNums("-1");
        list.add(criterion4);

        SlicingCriterion criterion5 = new SlicingCriterion();
        criterion5.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.AlgorithmParameters,java.security.SecureRandom)>");
        criterion5.setTargetParamNums("-1");
        list.add(criterion5);

        SlicingCriterion criterion6 = new SlicingCriterion();
        criterion6.setTargetStatement1("<javax.crypto.Cipher: void init(int,java.security.Key,java.security.SecureRandom)>");
        criterion6.setTargetParamNums("-1");
        list.add(criterion6);

        return list;
    }

    @Override
    public void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap) {
        ArrayList<String> secureClassNames = new ArrayList<>();
        secureClassNames.add("javax.crypto.spec.OAEPParameterSpec");

        ArrayList<ArrayList<Line>> slices = slicesMap.get("-1");
        for (ArrayList<Line> s : slices) {
            ArrayList<Line> algorithmLines1 = findConstantLines(s, "(?i)(RSA)|(RSA.*NoPadding)|(.*PKCS1Padding)", false);
            if (!algorithmLines1.isEmpty()) {
                printResult(slicingCriterion, algorithmLines1, true);
                continue;
            }

            ArrayList<Line> classLines = findClasses(s, secureClassNames);
            if (!classLines.isEmpty()) {
                printResult(slicingCriterion, classLines, true);
                continue;
            }

            ArrayList<Line> algorithmLines2 = findConstantLines(s, "(?i)(.*OAEP.*)", false);
            if (!algorithmLines2.isEmpty()) {
                printResult(slicingCriterion, algorithmLines2, false);
            }
        }
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
            ruleId = "11";
            ruleDescription = "This slice uses insecure padding for RSA";
        } else {
            ruleId = "11-2";
            ruleDescription = "This slice uses secure padding for RSA";
        }

        printResult(ruleId, ruleDescription, slicingCriterion, null, tempLines);
    }
}