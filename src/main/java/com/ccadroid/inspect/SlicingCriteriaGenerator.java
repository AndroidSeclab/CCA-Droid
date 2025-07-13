package com.ccadroid.inspect;

import com.ccadroid.check.RuleChecker;
import com.ccadroid.slice.CodeOptimizer;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.json.JSONArray;
import org.json.JSONObject;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;

import java.util.*;

import static com.ccadroid.check.RuleConstant.SLICING_SIGNATURES;
import static com.ccadroid.util.soot.Soot.getSootClass;
import static com.ccadroid.util.soot.Soot.hasInterface;
import static com.ccadroid.util.soot.SootUnit.*;

public class SlicingCriteriaGenerator {
    private static final ApkParser apkParser;
    private static final CodeInspector codeInspector;
    private static final CodeOptimizer codeOptimizer;
    private static final RuleChecker ruleChecker;

    static {
        apkParser = ApkParser.getInstance();
        codeInspector = CodeInspector.getInstance();
        codeOptimizer = CodeOptimizer.getInstance();
        ruleChecker = RuleChecker.getInstance();
    }

    private final HashMap<String, ArrayList<Unit>> targetUnitMap;
    private final HashMap<String, SlicingCriterion> slicingCriterionMap;
    private final List<String> targetReturnTypes;

    public SlicingCriteriaGenerator() {
        targetUnitMap = new HashMap<>();
        slicingCriterionMap = new HashMap<>();
        targetReturnTypes = Arrays.asList("java.lang.String", "javax.crypto.SecretKey", "javax.crypto.Cipher", "javax.crypto.Mac");
    }

    public static SlicingCriteriaGenerator getInstance() {
        return SingletonHolder.instance;
    }

    public ArrayList<SlicingCriterion> createSlicingCriteria() {
        ArrayList<SlicingCriterion> slicingCriteria = new ArrayList<>();
        HashMap<String, ArrayList<ArrayList<String>>> listOfCallersMap = new HashMap<>();
        ArrayList<JSONObject> rules = ruleChecker.getRules();
        ArrayList<SlicingCriterion> candidates = getSlicingCandidates(rules);
        for (SlicingCriterion c : candidates) {
            String targetSignature = c.getTargetStatement();
            if (!isCorrectSignature(targetSignature)) {
                continue;
            }

            Node callee = codeInspector.getNode(targetSignature);
            if (callee == null) {
                continue;
            }

            ArrayList<Integer> targetParamNumbers = c.getTargetParamNumbers();
            List<Edge> edges = codeInspector.getEdges(callee);

            for (Edge e : edges) {
                Node caller = e.getSourceNode();
                String callerName = caller.getId();
                String className = getClassName(callerName);
                if (apkParser.isBuiltInClassName(className)) {
                    continue;
                }

                ArrayList<ArrayList<String>> listOfCallers = listOfCallersMap.get(callerName);
                if (listOfCallers == null) {
                    listOfCallers = codeInspector.traverseCallers(callerName);
                    removeUnreachableCallers(listOfCallers);
                    listOfCallersMap.put(callerName, listOfCallers);
                }

                if (listOfCallers.isEmpty()) {
                    continue;
                }

                ArrayList<SlicingCriterion> criteria = createSlicingCriteria(callerName, targetSignature, INVOKE, targetParamNumbers);
                slicingCriteria.addAll(criteria);
            }
        }

        return slicingCriteria;
    }

    public ArrayList<SlicingCriterion> createSlicingCriteria(String callerName, String targetStatement, int targetUnitType, ArrayList<Integer> targetParamNumbers) {
        ArrayList<SlicingCriterion> slicingCriteria = new ArrayList<>();

        String targetReturnType = ((!targetStatement.isEmpty() && targetUnitType == INVOKE) || targetUnitType == ASSIGN_VARIABLE_SIGNATURE) ? getReturnType(targetStatement) : (targetUnitType == RETURN_VALUE) ? getReturnType(callerName) : null;
        if (targetReturnType != null && (targetReturnType.equals("boolean") || (!targetReturnTypes.contains(targetReturnType) && apkParser.isBuiltInClassName(targetReturnType)) || ((targetUnitType == ASSIGN_VARIABLE_SIGNATURE || targetUnitType == RETURN_VALUE) && apkParser.isDevClassName(targetReturnType)))) {
            return slicingCriteria;
        }

        ArrayList<Unit> wholeUnit = codeInspector.getWholeUnit(callerName);
        if (wholeUnit == null || wholeUnit.isEmpty()) {
            return slicingCriteria;
        }

        ArrayList<Unit> targetUnits = targetUnitMap.getOrDefault(callerName, new ArrayList<>(wholeUnit));
        if (wholeUnit.hashCode() == targetUnits.hashCode()) {
            codeOptimizer.runPointerAnalysis(callerName, targetUnits);
            codeOptimizer.removeUnreachableUnits(targetUnits);
            codeOptimizer.preModifyUnits(targetUnits);
            Collections.reverse(targetUnits);
            targetUnitMap.put(callerName, targetUnits);
        }

        int targetUnitCount = targetUnits.size();
        for (int i = targetUnitCount - 1; i > -1; i--) {
            Unit unit = targetUnits.get(i);
            String unitString = unit.toString();
            if (!(unitString.contains(targetStatement))) {
                continue;
            }

            int unitType = getUnitType(unit);
            boolean isAssign = (targetUnitType == ASSIGN_VARIABLE_SIGNATURE && (unitType == ASSIGN_SIGNATURE_VARIABLE));
            boolean isInvoke = (targetUnitType == INVOKE && (unitType & INVOKE) == INVOKE) || targetUnitType == PARAMETER;
            boolean isReturn = (targetUnitType == RETURN_VALUE && unitType == RETURN_VALUE);
            if (!isAssign && !isInvoke && !isReturn) {
                continue;
            }

            HashSet<Value> targetVariables = new HashSet<>();

            switch (unitType) {
                case ASSIGN_SIGNATURE_VARIABLE:
                case RETURN_VALUE: {
                    Value rightOp = getRightOp(unit, unitType);
                    targetVariables.add(rightOp);
                    break;
                }

                case VIRTUAL_INVOKE:
                case STATIC_INVOKE:
                case INTERFACE_INVOKE:
                case SPECIAL_INVOKE:
                case ASSIGN_VIRTUAL_INVOKE:
                case ASSIGN_STATIC_INVOKE:
                case ASSIGN_INTERFACE_INVOKE:
                case ASSIGN_SPECIAL_INVOKE: {
                    String signature = getSignature(unitString);
                    ArrayList<String> paramTypes = getParamTypes(signature);
                    ArrayList<Value> parameters = getParameters(unit, unitType);
                    if (targetParamNumbers.isEmpty() && !paramTypes.isEmpty()) {
                        continue;
                    }

                    if (targetParamNumbers.contains(-1)) {
                        Value base = getBase(unit, unitType);
                        targetVariables.add(base);
                    }

                    for (Integer j : targetParamNumbers) { // for multiple paramNumbers
                        if (j == -1) {
                            continue;
                        }

                        Value value = parameters.get(j);
                        targetVariables.add(value);
                    }

                    if (targetStatement.isEmpty()) {
                        targetStatement = signature;
                        targetParamNumbers.clear();
                    }

                    break;
                }
            }

            if (targetVariables.isEmpty()) {
                continue;
            }

            SlicingCriterion slicingCriterion = new SlicingCriterion();
            slicingCriterion.setCallerName(callerName);
            slicingCriterion.setTargetStatement(targetStatement);
            slicingCriterion.setTargetParamNumbers(targetParamNumbers);
            slicingCriterion.setTargetUnitIndex(i);
            slicingCriterion.setTargetVariables(targetVariables);
            slicingCriterion.setTargetUnits(targetUnits);

            String id = slicingCriterion.getId();
            slicingCriterionMap.put(id, slicingCriterion);
            slicingCriteria.add(slicingCriterion);
        }

        return slicingCriteria;
    }

    public SlicingCriterion getSlicingCriterion(String id) {
        return slicingCriterionMap.get(id);
    }

    public SlicingCriterion updateSlicingCriterion(SlicingCriterion slicingCriterion, int targetUnitIndex, HashSet<Value> targetVariables) {
        SlicingCriterion criterion = (SlicingCriterion) slicingCriterion.clone();
        String id = slicingCriterion.getId();

        criterion.setId(id);
        criterion.setTargetUnitIndex(targetUnitIndex);
        criterion.setTargetVariables(targetVariables);
        slicingCriterionMap.put(id, criterion);

        return criterion;
    }

    private ArrayList<SlicingCriterion> getSlicingCandidates(ArrayList<JSONObject> rules) {
        ArrayList<SlicingCriterion> candidates = new ArrayList<>();

        for (JSONObject root : rules) {
            JSONObject signatures = root.getJSONObject(SLICING_SIGNATURES);
            if (signatures == null) {
                continue;
            }

            Iterator<String> keys = signatures.keys();
            while (keys.hasNext()) {
                String signature = keys.next();
                ArrayList<Integer> paramNumbers = new ArrayList<>();
                JSONArray jsonArr = signatures.getJSONArray(signature);
                for (int i = 0; i < jsonArr.length(); i++) {
                    int paramNum = jsonArr.getInt(i);
                    paramNumbers.add(paramNum);
                }

                SlicingCriterion slicingCriterion = new SlicingCriterion();
                slicingCriterion.setTargetStatement(signature);
                slicingCriterion.setTargetParamNumbers(paramNumbers);

                candidates.add(slicingCriterion);
            }
        }

        return candidates;
    }

    private boolean isCorrectSignature(String signature) {
        String className = getClassName(signature);
        SootClass sootClass = getSootClass(className);
        List<SootMethod> methods = sootClass.getMethods();
        String methodsStr = methods.toString();

        return !sootClass.isPhantomClass() || !methodsStr.contains(signature);
    }

    private void removeUnreachableCallers(ArrayList<ArrayList<String>> listOfCallers) {
        ArrayList<ArrayList<String>> callers = new ArrayList<>();

        for (ArrayList<String> l : listOfCallers) {
            String topSignature = l.get(0);
            String className = getClassName(topSignature);

            boolean isSingleComponent = (l.size() == 1 && apkParser.isAppComponents(className));
            boolean isDevClass = apkParser.isDevClassName(className);
            boolean isRunnable = hasInterface(className, "java.lang.Runnable");

            if (isSingleComponent) {
                callers.add(l);
            } else if (!isDevClass && !isRunnable) {
                callers.add(l);
            }
        }

        listOfCallers.removeAll(callers);
    }

    private static class SingletonHolder {
        private static final SlicingCriteriaGenerator instance = new SlicingCriteriaGenerator();
    }
}