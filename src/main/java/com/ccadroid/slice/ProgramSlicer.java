package com.ccadroid.slice;

import com.ccadroid.check.RuleChecker;
import com.ccadroid.inspect.ApkParser;
import com.ccadroid.inspect.CodeInspector;
import com.ccadroid.inspect.SlicingCriteriaGenerator;
import com.ccadroid.inspect.SlicingCriterion;
import com.ccadroid.util.Argparse4j;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import org.json.JSONObject;
import soot.Unit;
import soot.Value;

import java.util.*;

import static com.ccadroid.slice.SliceConstant.*;
import static com.ccadroid.util.graph.CallGraph.INTERFACE_NAME;
import static com.ccadroid.util.soot.Soot.isEnumClass;
import static com.ccadroid.util.soot.SootUnit.*;

public class ProgramSlicer {
    private static final int UPPER_LEVEL = Argparse4j.getInt(Argparse4j.UPPER_LEVEL);
    private static final int LOWER_LEVEL = Argparse4j.getInt(Argparse4j.LOWER_LEVEL);
    private static final ApkParser apkParser;
    private static final CodeInspector codeInspector;
    private static final SlicingCriteriaGenerator slicingCriteriaGenerator;
    private static final CodeOptimizer codeOptimizer;
    private static final SliceDatabase sliceDatabase;
    private static final SliceMerger sliceMerger;
    private static final RuleChecker ruleChecker;

    static {
        apkParser = ApkParser.getInstance();
        codeInspector = CodeInspector.getInstance();
        slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
        codeOptimizer = CodeOptimizer.getInstance();
        sliceDatabase = SliceDatabase.getInstance();
        sliceMerger = SliceMerger.getInstance();
        ruleChecker = RuleChecker.getInstance();
    }

    private final Deque<SlicingCriterion> deque;
    private final HashMap<String, ArrayList<Unit>> unitsMap;
    private final HashMap<String, ArrayList<JSONObject>> contentsMap;
    private final ArrayList<Unit> gotoTargetUnits;
    private final HashMap<String, String> nodeIdMap;
    private final HashMap<String, ArrayList<Integer>> retainParamNumMap;

    public ProgramSlicer() {
        deque = new LinkedList<>();
        unitsMap = new HashMap<>();
        contentsMap = new HashMap<>();
        gotoTargetUnits = new ArrayList<>();
        nodeIdMap = new HashMap<>();
        retainParamNumMap = new HashMap<>();
    }

    public static ProgramSlicer getInstance() {
        return SingletonHolder.instance;
    }

    public void sliceStatements(SlicingCriterion slicingCriterion) {
        String leafId = slicingCriterion.getId();
        sliceMerger.addNode(leafId, leafId, 0);

        addSlicingCriterion(slicingCriterion);

        while (!deque.isEmpty()) {
            SlicingCriterion sc = deque.poll();
            sliceStatement(sc);
        }
    }

    public ArrayList<Unit> getUnits(String nodeId) {
        return unitsMap.get(nodeId);
    }

    public ArrayList<Integer> getRetainParamNumbers(String unitString) {
        return retainParamNumMap.get(unitString);
    }

    private void addSlicingCriterion(SlicingCriterion slicingCriterion) {
        if (!deque.contains(slicingCriterion)) {
            deque.add(slicingCriterion);
        }
    }

    private void sliceStatement(SlicingCriterion slicingCriterion) {
        String nodeId = slicingCriterion.getId();
        Node node = sliceMerger.getNode(nodeId);
        List<String> query1 = List.of(String.format("%s==%s", NODE_ID, nodeId), String.format("%s!=null", CALLER_NAME));
        JSONObject slice = sliceDatabase.selectOne(query1);
        if (slice == null) {
            sliceDatabase.insert(nodeId);
        } else {
            return;
        }

        String callerName = slicingCriterion.getCallerName();
        String targetStatement = slicingCriterion.getTargetStatement();
        int startUnitIndex = slicingCriterion.getTargetUnitIndex();
        ArrayList<Integer> targetParamIndexes = slicingCriterion.getTargetParamNumbers();
        Collection<Value> oldTargetVariables = slicingCriterion.getTargetVariables();
        List<Unit> targetUnits = slicingCriterion.getTargetUnits();

        ArrayList<Unit> wholeUnit = codeInspector.getWholeUnit(callerName);
        int targetUnitCount = targetUnits.size();
        Unit startUnit = targetUnits.get(startUnitIndex);
        String startUnitStr = startUnit.toString();
        int startUnitType = getUnitType(startUnit);
        if ((startUnitType & INVOKE) == INVOKE) {
            setRetainParamNumbers(startUnit, startUnitStr, startUnitType, oldTargetVariables);
        }

        int startLineNum = wholeUnit.indexOf(startUnit) + 1;
        String startUnitPattern = ((startUnitType & INVOKE) == INVOKE) ? getSignature(startUnit) : ((startUnitType & RETURN) == RETURN) ? "return" : startUnitStr;
        HashSet<Value> newTargetVariables = new HashSet<>(oldTargetVariables);
        ArrayList<Integer> newParamIndexes = new ArrayList<>();
        ArrayList<Unit> units = unitsMap.getOrDefault(nodeId, new ArrayList<>(Collections.singletonList(startUnit)));
        ArrayList<JSONObject> contents = contentsMap.getOrDefault(nodeId, new ArrayList<>());
        if (contents.isEmpty()) {
            addLine(startUnitStr, startUnitType, callerName, startLineNum, contents);
        }

        for (int i = startUnitIndex + 1; i < targetUnitCount; i++) {
            Unit unit = targetUnits.get(i);
            gotoTargetUnits.remove(unit);

            int unitType = getUnitType(unit);
            if (unitType == -1) {
                continue;
            }

            int dequeSize = deque.size();
            int lineNum = wholeUnit.indexOf(unit) + 1;
            String unitString = unit.toString();

            if (unitType == IF) {
                ArrayList<Value> conditionValues = getIfConditionValues(unit, unitType);
                HashSet<Value> retainVariables = getRetainVariables(unit, conditionValues);

                if (isLoopStatement(wholeUnit, unit, unitType) && retainVariables.isEmpty()) {
                    continue;
                }

                Unit targetUnit = getIfGotoTargetUnit(unit, unitType);
                int targetUnitIndex = wholeUnit.indexOf(targetUnit);
                int lastUnitIndex = wholeUnit.indexOf(units.get(0));
                if (targetUnitIndex < lastUnitIndex) { // ignore unit
                    continue;
                }

                addTargetVariables(conditionValues, newTargetVariables);

                units.add(0, unit);
                addLine(unitString, unitType, callerName, lineNum, contents);
                continue;
            } else if (unitType == GOTO) {
                if (isLoopStatement(wholeUnit, unit, unitType)) {
                    continue;
                }

                Unit targetUnit = getIfGotoTargetUnit(unit, unitType);
                if (gotoTargetUnits.contains(targetUnit)) {
                    continue;
                }

                int targetUnitIndex = wholeUnit.indexOf(targetUnit);
                int lastUnitIndex = wholeUnit.indexOf(units.get(0));
                if (targetUnitIndex <= lastUnitIndex) { // ignore unit
                    continue;
                }

                Unit nextUnit = wholeUnit.get(i + 1);
                Unit switchUnit = codeInspector.getSwitchUnit(nextUnit);
                if (switchUnit != null) {
                    i = targetUnits.indexOf(switchUnit);
                    continue;
                }

                gotoTargetUnits.add(targetUnit);
                units.add(0, unit);
                addLine(unitString, unitType, callerName, lineNum, contents);
                continue;
            } else if (unitType == SWITCH) {
                units.add(0, unit);
                addLine(unitString, unitType, callerName, lineNum, contents);
                continue;
            } else if ((unitType & RETURN) == RETURN) {
                if (unitString.startsWith(startUnitPattern)) {
                    continue;
                }
            }

            HashSet<Value> retainVariables = getRetainVariables(unit, newTargetVariables);
            if (retainVariables.isEmpty()) {
                continue;
            }

            switch (unitType) {
                case VIRTUAL_INVOKE:
                case STATIC_INVOKE:
                case INTERFACE_INVOKE:
                case SPECIAL_INVOKE: {
                    String signature = getSignature(unitString);
                    String className = getClassName(signature);
                    String methodName = getMethodName(signature);
                    ArrayList<Value> parameters = getParameters(unit, unitType);

                    if (className.endsWith("Exception")) {
                        continue;
                    } else if (className.equals("java.lang.Integer") && methodName.equals("<init>")) {
                        Value value = parameters.get(0);
                        retainVariables.add(value);
                    } else if (className.equals("java.lang.StringBuilder") && methodName.equals("append")) {
                        break;
                    } else if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
                        Value oldValue = parameters.get(2);
                        if (!retainVariables.contains(oldValue)) {
                            continue;
                        }

                        newTargetVariables.remove(oldValue);
                        Value newValue = parameters.get(0);
                        addTargetVariable(newTargetVariables, newValue);
                    } else if (className.equals("java.text.SimpleDateFormat") && methodName.equals("<init>")) {
                        Value value = parameters.get(0);
                        retainVariables.add(value);
                    } else if (className.equals("java.util.Map") && methodName.equals("put")) {
                        Value value = parameters.get(1);
                        addTargetVariable(newTargetVariables, value);
                    } else if ((className.equals("javax.crypto.spec.SecretKeySpec") || className.equals("javax.crypto.spec.PBEKeySpec")) && methodName.equals("<init>")) {
                        Value value = parameters.get(0); // for tracking key string
                        addTargetVariable(newTargetVariables, value);
                    } else if (className.equals("javax.crypto.Mac") && (methodName.equals("init") || methodName.equals("update"))) {
                        String targetClassName = ((startUnitType & INVOKE) == INVOKE) ? getClassName(targetStatement) : null;
                        String targetMethodName = ((startUnitType & INVOKE) == INVOKE) ? getMethodName(targetStatement) : null;
                        if (targetParamIndexes != null && targetParamIndexes.contains(-1) && targetClassName != null && targetClassName.equals("javax.crypto.Mac") && targetMethodName != null && targetMethodName.equals("doFinal")) {
                            Value value = parameters.get(0);
                            addTargetVariable(newTargetVariables, value);
                        }
                    } else if (className.equals("android.util.Log") || className.startsWith("kotlin.jvm.internal")) {
                        continue;
                    } else {
                        Value base = getBase(unit, unitType);
                        if (base != null) {
                            addTargetVariable(newTargetVariables, base);
                        }

                        handleInvokeUnit(unit, node, signature);
                    }

                    break;
                }

                case ASSIGN_VIRTUAL_INVOKE:
                case ASSIGN_STATIC_INVOKE:
                case ASSIGN_INTERFACE_INVOKE:
                case ASSIGN_SPECIAL_INVOKE: {
                    Value leftOp = getLeftOp(unit, unitType);
                    newTargetVariables.remove(leftOp);

                    String signature = getSignature(unitString);
                    String className = getClassName(signature);
                    String returnType = getReturnType(signature);
                    String methodName = getMethodName(signature);
                    ArrayList<Value> parameters = getParameters(unit, unitType);

                    if (className.equals("java.lang.String") && methodName.equals("valueOf")) {
                        Value value = parameters.get(0);
                        addTargetVariable(newTargetVariables, value);

                        if (!isVariable(value)) {
                            retainVariables.add(value);
                        }
                    } else if (className.equals("java.nio.ByteBuffer") && methodName.equals("getInt")) {
                        break;
                    } else if (className.equals("java.security.MessageDigest") && methodName.equals("digest") && !parameters.isEmpty()) {
                        Value value = parameters.get(0);
                        addTargetVariable(newTargetVariables, value);
                    } else if (className.equals("java.util.Arrays") && methodName.equals("copyOfRange")) {
                        Value value = parameters.get(0);
                        addTargetVariable(newTargetVariables, value);
                    } else if (className.contains("java.util.Base64$Decoder") && methodName.equals("decode")) {
                        Value value = parameters.get(0);
                        addTargetVariable(newTargetVariables, value);

                        if (!isVariable(value)) {
                            retainVariables.add(value);
                        }
                    } else if (className.equals("java.util.Map") && methodName.equals("get")) {
                        Value value = parameters.get(0);
                        newTargetVariables.add(value); // to add string constant
                    } else if (className.equals("javax.crypto.Cipher") && methodName.equals("update")) {
                        String targetClassName = ((startUnitType & INVOKE) == INVOKE) ? getClassName(targetStatement) : null;
                        String targetMethodName = ((startUnitType & INVOKE) == INVOKE) ? getMethodName(targetStatement) : null;

                        if (targetClassName != null && targetClassName.equals("javax.crypto.Cipher") && targetMethodName != null && targetMethodName.equals("doFinal")) {
                            Value value = parameters.get(0);
                            addTargetVariable(newTargetVariables, value);
                        }
                    } else if (className.equals("javax.crypto.spec.PBEKeySpec") && methodName.equals("getSalt")) {
                        break;
                    } else if (className.equals("javax.crypto.SecretKeyFactory") && methodName.equals("generateSecret")) {
                        Value value = parameters.get(0);
                        addTargetVariable(newTargetVariables, value);
                    } else if (className.equals("javax.crypto.Mac") && methodName.equals("doFinal") && !parameters.isEmpty()) {
                        Value value = parameters.get(0);
                        addTargetVariable(newTargetVariables, value);
                    } else if (className.equals("android.content.SharedPreferences") && methodName.equals("getString")) {
                        Value value = parameters.get(0);
                        retainVariables.add(value);
                    } else if (unitString.contains(startUnitPattern)) {
                        parameters.forEach(v -> {
                            int index = parameters.indexOf(v);
                            if (targetParamIndexes != null && targetParamIndexes.contains(index)) {
                                addTargetVariable(newTargetVariables, v);
                            }
                        });
                    } else {
                        Value base = getBase(unit, unitType);
                        if (retainVariables.contains(base)) {
                            break;
                        } else if (base == null || isLocalVariable(base)) {
                            addTargetVariables(parameters, newTargetVariables);
                        } else if (apkParser.isDevClassName(className)) {
                            addTargetVariable(newTargetVariables, base);
                        } else if (returnType.equals("int") || returnType.equals("char[]") || returnType.equals("java.lang.String") || returnType.equals("byte[]")) {
                            addTargetVariable(newTargetVariables, base);
                        }

                        handleInvokeUnit(unit, node, signature);
                    }

                    break;
                }

                case PARAMETER: {
                    int index = getParamIndex(unit, unitType);
                    newParamIndexes.add(0, index);
                    break;
                }

                case NEW_INSTANCE:
                case NEW_ARRAY:
                case ASSIGN_VARIABLE_CONSTANT: {
                    Value leftOp = getLeftOp(unit, unitType);
                    if (!retainVariables.contains(leftOp)) {
                        continue;
                    }

                    break;
                }

                case ASSIGN_VARIABLE_VARIABLE:
                case ASSIGN_VARIABLE_OPERATION:
                case CAST:
                case LENGTH_OF: {
                    Value leftOp = getLeftOp(unit, unitType);
                    if (!retainVariables.contains(leftOp)) {
                        continue;
                    }

                    if (unitType == ASSIGN_VARIABLE_VARIABLE) {
                        newTargetVariables.remove(leftOp);
                        Value rightOp = getRightOp(unit, unitType);
                        addTargetVariable(newTargetVariables, rightOp);
                    } else if (unitType == ASSIGN_VARIABLE_OPERATION) {
                        HashSet<Value> variables = getVariables(unit);
                        addTargetVariables(variables, newTargetVariables);
                        newTargetVariables.remove(leftOp);
                    } else {
                        newTargetVariables.remove(leftOp);
                        Value rightOp = getRightInternalOp(unit, unitType);
                        addTargetVariable(newTargetVariables, rightOp);
                    }

                    break;
                }

                case ASSIGN_VARIABLE_SIGNATURE: {
                    Value leftOp = getLeftOp(unit, unitType);
                    newTargetVariables.remove(leftOp);

                    String signature = getSignature(unitString);
                    handleAssignVariableSignatureUnit(node, callerName, signature);
                    break;
                }

                case RETURN_VALUE: {
                    Value rightOp = getRightOp(unit, unitType);
                    if (retainVariables.contains(rightOp)) {
                        continue; // ignore return statement
                    } else {
                        break;
                    }
                }

                default: {
                    break;
                }
            }

            units.add(0, unit);
            addLine(unitString, unitType, callerName, lineNum, contents);

            if ((unitType & INVOKE) == INVOKE) {
                setRetainParamNumbers(unit, unitString, unitType, retainVariables);
            }

            int delta = deque.size() - dequeSize; // trace variable with DFS algorithm
            if ((unitType & ASSIGN_INVOKE) == ASSIGN_INVOKE && delta > 0) {
                unitsMap.put(nodeId, units);
                contentsMap.put(nodeId, contents);

                SlicingCriterion tempCriterion = slicingCriteriaGenerator.updateSlicingCriterion(slicingCriterion, i, newTargetVariables);
                addSlicingCriterion(tempCriterion);
                return;
            }

            Unit switchUnit = codeInspector.getSwitchUnit(unit);
            if (switchUnit != null) { // Jump to switch index when now is in switch statement
                i = targetUnits.indexOf(switchUnit);
            }
        }

        checkUselessUnits(units, newParamIndexes);
        codeOptimizer.removeUselessStatement(units, contents);
        codeOptimizer.postModifyUnits(units);
        unitsMap.put(nodeId, units);

        if (!contents.isEmpty()) {
            handleParameterUnit(nodeId, callerName, newParamIndexes);
            sliceDatabase.insert(nodeId, callerName, targetStatement, startUnitIndex, targetParamIndexes, oldTargetVariables, contents);
        } else {
            sliceDatabase.delete(nodeId);
            sliceMerger.deleteNode(node);
        }
    }

    private void setRetainParamNumbers(Unit unit, String unitString, int unitType, Collection<Value> retainVariables) {
        String signature = getSignature(unitString);
        String className = getClassName(signature);
        String methodName = getMethodName(signature);
        ArrayList<Value> parameters = getParameters(unit, unitType);
        ArrayList<Integer> numbers = new ArrayList<>();

        parameters.forEach(v -> {
            if (retainVariables.contains(v) || (!apkParser.isBuiltInClassName(className) && methodName.equals("<init>")) || ruleChecker.isAlgorithm(convertToStr(v))) {
                numbers.add(parameters.indexOf(v));
            }
        });

        retainParamNumMap.put(unitString, numbers);
    }

    private void addLine(String unitString, int unitType, String callerName, int lineNumber, ArrayList<JSONObject> contents) {
        JSONObject line = new JSONObject();

        line.put(UNIT_STRING, unitString);
        line.put(UNIT_TYPE, unitType);
        line.put(CALLER_NAME, callerName);
        line.put(LINE_NUMBER, lineNumber);

        contents.add(0, line);
    }

    private HashSet<Value> getRetainVariables(Unit unit, Collection<Value> targetVariables) {
        HashSet<Value> variables = new HashSet<>();

        HashSet<Value> tempVariables = getVariables(unit);
        tempVariables.forEach(v -> {
            if (targetVariables.contains(v) && !isNumericConstant(v)) {
                variables.add(v);
            }
        });

        return variables;
    }

    private void addTargetVariables(Collection<Value> variables, HashSet<Value> targetVariables) {
        variables.forEach(v -> addTargetVariable(targetVariables, v));
    }

    private void addTargetVariable(HashSet<Value> targetVariables, Value variable) {
        targetVariables.add(variable);
    }

    private void handleInvokeUnit(Unit unit, Node parent, String calleeName) {
        String className = getClassName(calleeName);
        if (apkParser.isBuiltInClassName(className)) {
            return;
        }

        int level = sliceMerger.getLevel(parent);
        if (level == LOWER_LEVEL) {
            return;
        } else {
            level--;
        }

        ArrayList<SlicingCriterion> slicingCriteria;
        ArrayList<Integer> targetParamNumbers = new ArrayList<>();

        int unitType = getUnitType(unit);
        if ((unitType & ASSIGN) == ASSIGN) { // for ASSIGN_INVOKE unit
            slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(calleeName, "return", RETURN_VALUE, targetParamNumbers);
        } else {
            slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(calleeName, "", INVOKE, targetParamNumbers);
        }

        String parentId = parent.getId();
        for (SlicingCriterion sc : slicingCriteria) {
            String childId = sc.getId();
            Node child = sliceMerger.addNode(childId, childId, level);
            sliceMerger.addEdge(parent, child, true);
            nodeIdMap.put(childId, parentId);
        }

        slicingCriteria.forEach(this::addSlicingCriterion);
    }

    private void handleAssignVariableSignatureUnit(Node child1, String oldCallerName, String targetSignature) {
        String className = getClassName(targetSignature);
        if (apkParser.isBuiltInClassName(className)) {
            return;
        }

        Node memberVar = codeInspector.getNode(targetSignature);
        if (memberVar == null) { // for builtin system variable
            return;
        }

        Node caller1 = codeInspector.getNode(oldCallerName);
        int level = sliceMerger.getLevel(child1);
        if (level == UPPER_LEVEL) {
            return;
        }

        String childId2 = String.valueOf(targetSignature.hashCode());
        Node child2 = sliceMerger.getNode(childId2) == null ? sliceMerger.addNode(childId2, childId2, level) : sliceMerger.getNode(childId2);
        sliceMerger.addEdge(child1, child2, false);

        level++;

        List<Edge> edges = codeInspector.getEdges(memberVar);
        for (Edge e : edges) {
            Node caller2 = e.getSourceNode();
            if (caller2.equals(caller1)) {
                continue;
            }

            String callerName2 = caller2.getId();
            String className2 = getClassName(callerName2);
            if (isEnumClass(className2)) {
                continue;
            }

            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(callerName2, targetSignature, ASSIGN_VARIABLE_SIGNATURE, null);
            for (SlicingCriterion sc : slicingCriteria) {
                String parentId2 = sc.getId();
                Node parent2 = sliceMerger.addNode(parentId2, parentId2, level);
                sliceMerger.addEdge(parent2, child2, false);
            }

            slicingCriteria.forEach(this::addSlicingCriterion);
        }
    }

    private void handleParameterUnit(String childId, String calleeName, ArrayList<Integer> targetParamNumbers) {
        if (targetParamNumbers.isEmpty()) {
            return;
        }

        if (nodeIdMap.containsKey(childId)) {
            updateTargetParameters(childId, targetParamNumbers);
            return;
        }

        Node child = sliceMerger.getNode(childId);
        int level = sliceMerger.getLevel(child);
        if (level == UPPER_LEVEL) {
            return;
        } else {
            level++;
        }

        Node callee = codeInspector.getNode(calleeName);
        if (callee.hasAttribute(INTERFACE_NAME)) {
            Node newCallee = codeInspector.getInterfaceNode(callee);
            if (newCallee != null) {
                callee = newCallee;
                calleeName = callee.getId();
            }
        }

        List<Edge> edges = codeInspector.getEdges(callee);
        for (Edge e : edges) {
            if (!e.isDirected()) {
                continue;
            }

            Node caller = e.getSourceNode();
            if (!sliceMerger.isConcrete(caller)) {
                continue;
            }

            String callerName = caller.getId();
            if (callerName.equals(calleeName)) {
                continue;
            }

            String className = getClassName(callerName);
            if (!apkParser.isDevClassName(className)) {
                continue;
            }

            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(callerName, calleeName, PARAMETER, targetParamNumbers);
            for (SlicingCriterion sc : slicingCriteria) {
                String parentId = sc.getId();
                Node parent = sliceMerger.addNode(parentId, parentId, level);
                sliceMerger.addEdge(parent, child, true);
                addSlicingCriterion(sc);
            }
        }
    }

    private void updateTargetParameters(String childId, ArrayList<Integer> targetParamNumbers) {
        String parentId = nodeIdMap.get(childId);
        SlicingCriterion slicingCriterion = slicingCriteriaGenerator.getSlicingCriterion(parentId);
        if (slicingCriterion == null) {
            return;
        }

        Collection<Value> targetVariables = slicingCriterion.getTargetVariables();
        if (targetVariables.isEmpty()) {
            return;
        }

        ArrayList<Value> parameters = getTargetParameters(slicingCriterion);
        if (parameters.size() <= Collections.max(targetParamNumbers)) { // already modified
            return;
        }

        ArrayList<Value> targetParameters = new ArrayList<>(parameters);
        targetParamNumbers.forEach(i -> targetParameters.remove(parameters.get(i)));
        targetParameters.forEach(targetVariables::remove);
    }

    private ArrayList<Value> getTargetParameters(SlicingCriterion slicingCriterion) {
        int targetUnitIndex = slicingCriterion.getTargetUnitIndex();
        ArrayList<Unit> targetUnits = slicingCriterion.getTargetUnits();
        Unit targetUnit = targetUnits.get(targetUnitIndex);
        int targetUnitType = getUnitType(targetUnit);
        ArrayList<Value> parameters = getParameters(targetUnit, targetUnitType);

        return new ArrayList<>(parameters);
    }

    private void checkUselessUnits(ArrayList<Unit> units, ArrayList<Integer> targetParamIndexes) {
        if (units.size() == 1) {
            return;
        }

        ArrayList<Integer> forwardIndexes = findTargetUnitIndexes(units, true);
        ArrayList<Integer> backwardIndexes = findTargetUnitIndexes(units, false);

        for (Unit u : units) {
            int i = units.indexOf(u);
            if (!forwardIndexes.contains(i) || !backwardIndexes.contains(i)) {
                continue;
            }

            int unitType = getUnitType(u);
            int index = getParamIndex(u, unitType);
            if (index > -1) {
                targetParamIndexes.remove(Integer.valueOf(index));
            }

            units.set(i, getNopStmt());
        }
    }

    private ArrayList<Integer> findTargetUnitIndexes(ArrayList<Unit> units, boolean isForward) {
        HashSet<Value> targetVariables = new HashSet<>();
        ArrayList<Integer> targetIndexes = new ArrayList<>();

        for (int i = 0; i < units.size(); i++) {
            int index = (isForward) ? i : units.size() - 1 - i;
            Unit unit = units.get(index);
            int unitType = getUnitType(unit);
            if (unitType == GOTO) {
                continue;
            }

            HashSet<Value> variables = (unitType == IF) ? new HashSet<>(getIfConditionValues(unit, IF)) : getVariables(unit);
            if (targetVariables.isEmpty()) {
                targetVariables.addAll(variables);
            }

            HashSet<Value> retainVariables = getRetainVariables(unit, targetVariables);
            if (retainVariables.isEmpty()) {
                targetIndexes.add(index);
            } else {
                targetVariables.addAll(variables);
            }
        }

        return targetIndexes;
    }

    private static class SingletonHolder {
        private static final ProgramSlicer instance = new ProgramSlicer();
    }
}