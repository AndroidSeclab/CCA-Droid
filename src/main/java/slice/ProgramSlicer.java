package slice;

import analyze.CodeInspector;
import main.Configuration;
import model.Line;
import model.SlicingCriterion;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import soot.*;
import soot.jimple.IntConstant;
import soot.jimple.NullConstant;
import soot.jimple.internal.JAssignStmt;

import java.util.*;
import java.util.stream.Stream;

import static graph.BaseGraph.EdgeType;
import static graph.BaseGraph.EdgeType.*;
import static java.lang.Integer.parseInt;
import static java.lang.String.valueOf;
import static java.util.Collections.frequency;
import static java.util.stream.Collectors.toList;
import static utils.SootUnit.*;
import static utils.SootUnit.VariableType.ALL;
import static utils.SootUnit.VariableType.IMMEDIATE;

public class ProgramSlicer {
    private final CodeInspector codeInspector;
    private final SlicingCriteriaGenerator slicingCriteriaGenerator;
    private final SliceOptimizer sliceOptimizer;
    private final ConstraintSolver constraintSolver;
    private final SliceMerger sliceMerger;

    private final Deque<SlicingCriterion> deque;
    private final ArrayList<SlicingCriterion> usedSlicingCriteria;
    private final HashSet<String> excludeClassNames;
    private final HashMap<String, ArrayList<SlicingCriterion>> tempSlicingCriteriaMap;
    private final HashMap<Unit, ArrayList<SlicingCriterion>> derivedSlicingCriteriaMap;
    private final HashMap<Unit, HashSet<String>> retainVariablesMap;
    private final LinkedHashMap<String, ArrayList<Line>> sliceMap;

    private final int upperLevel;
    private final int lowerLevel;

    public ProgramSlicer() {
        codeInspector = CodeInspector.getInstance();
        slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
        sliceOptimizer = SliceOptimizer.getInstance();
        constraintSolver = ConstraintSolver.getInstance();
        sliceMerger = SliceMerger.getInstance();

        deque = new LinkedList<>();
        usedSlicingCriteria = new ArrayList<>();
        excludeClassNames = new HashSet<>();
        tempSlicingCriteriaMap = new HashMap<>();
        derivedSlicingCriteriaMap = new HashMap<>();
        retainVariablesMap = new HashMap<>();
        sliceMap = new LinkedHashMap<>();

        Configuration configuration = Configuration.getInstance();
        upperLevel = parseInt(configuration.getConfig("upperLevel"));
        lowerLevel = parseInt(configuration.getConfig("lowerLevel"));
    }

    public static ProgramSlicer getInstance() {
        return ProgramSlicer.Holder.instance;
    }

    public void runWhileQueueIsNotEmpty(SlicingCriterion slicingCriterion) {
        String targetHashCode = String.valueOf(slicingCriterion.hashCode());
        Node callee2 = sliceMerger.addNode(targetHashCode, targetHashCode, "leaf");
        slicingCriterion.setCaller2(callee2);

        deque.add(slicingCriterion);

        while (!deque.isEmpty()) {
            SlicingCriterion sc = deque.poll();
            performSlicing(sc);
        }
    }

    public HashSet<String> getRetainVariables(Unit unit) {
        return retainVariablesMap.get(unit);
    }

    public ArrayList<Line> getSlice(String hashCode) {
        return sliceMap.get(hashCode);
    }

    public ArrayList<ArrayList<Line>> findSlices(String targetSignature, ArrayList<Line> slice) {
        ArrayList<ArrayList<Line>> targetSlices = new ArrayList<>();

        Collection<ArrayList<Line>> slices = sliceMap.values();
        for (ArrayList<Line> s : slices) {
            if (s.equals(slice)) {
                continue;
            }

            for (Line l : s) {
                int unitType = l.getUnitType();
                if ((unitType & INVOKE) != INVOKE) {
                    continue;
                }

                Unit unit = l.getUnit();
                String signature = getSignature(unit);
                if (!signature.equals(targetSignature)) {
                    continue;
                }

                targetSlices.add(s);
            }
        }

        return targetSlices;
    }

    private int getSwitchIndex(Unit unit, HashMap<Integer, ArrayList<Unit>> switchTargetsMap) {
        int index = -1;

        Set<Map.Entry<Integer, ArrayList<Unit>>> entries = switchTargetsMap.entrySet();
        for (Map.Entry<Integer, ArrayList<Unit>> e : entries) {
            ArrayList<Unit> targets = e.getValue();
            if (!targets.contains(unit)) {
                continue;
            }

            index = e.getKey();
        }

        return index;
    }

    private void performSlicing(SlicingCriterion slicingCriterion) {
        Node caller2 = slicingCriterion.getCaller2();
        if (caller2 == null) {
            return;
        }

        Node caller = slicingCriterion.getCaller();
        if (usedSlicingCriteria.contains(slicingCriterion)) {
            ArrayList<SlicingCriterion> tempSlicingCriteria = tempSlicingCriteriaMap.get(caller.getId());
            if (tempSlicingCriteria != null) {
                deque.addAll(tempSlicingCriteria);
            }

            return;
        }

        usedSlicingCriteria.add(slicingCriterion);

        String targetHashCode = String.valueOf(slicingCriterion.hashCode());
        String callerName = caller.getId();
        HashSet<String> callerNames = slicingCriterion.getCallerNames();
        String targetStatement1 = slicingCriterion.getTargetStatement1();
        String targetStatement2 = slicingCriterion.getTargetStatement2();
        String targetStatement = (targetStatement2 == null) ? targetStatement1 : targetStatement2;
        ArrayList<String> oldTargetVariables = slicingCriterion.getTargetVariables();
        HashSet<String> newTargetVariables = new HashSet<>(oldTargetVariables);

        ArrayList<Unit> wholeUnits = slicingCriterion.getWholeUnits();
        ArrayList<Unit> partialUnits = slicingCriterion.getPartialUnits();
        HashMap<Integer, ArrayList<Unit>> switchTargetsMap = slicingCriterion.getSwitchTargetsMap();
        ArrayList<Unit> targetGotoUnits = slicingCriterion.getTargetGotoUnits();

        ArrayList<Unit> targetUnits = slicingCriterion.getTargetUnits();
        ArrayList<String> unitStrings = slicingCriterion.getUnitStrings();
        ArrayList<Unit> targetIfUnits = slicingCriterion.getTargetIfUnits();
        ArrayList<Unit> excludeTargetUnits = new ArrayList<>();
        ArrayList<String> uselessVariables = slicingCriterion.getUselessVariables();
        boolean isInSwitch = slicingCriterion.isInSwitch();
        ArrayList<String> targetParamValues = slicingCriterion.getTargetParamValues();
        ArrayList<String> nextParamNums = slicingCriterion.getNextParamNums();

        int wholeUnitCount = wholeUnits.size();
        int partialUnitCount = partialUnits.size();

        int startUnitIndex1 = slicingCriterion.getTargetUnitIndex(); // absolute unit index of wholeUnits
        int startUnitIndex2 = (partialUnits.containsAll(wholeUnits)) ? startUnitIndex1 : 0;
        Unit startUnit = partialUnits.get(startUnitIndex2);
        int startUnitType = getUnitType(startUnit);
        String startClassName = null;
        String startMethodName = null;
        if ((startUnitType & INVOKE) == INVOKE) {
            startClassName = getClassName(targetStatement);
            startMethodName = getMethodName(targetStatement);
            retainVariablesMap.put(startUnit, new HashSet<>(newTargetVariables));
        }

        int startLineNum = wholeUnitCount - startUnitIndex1;
        boolean canEscape = false;
        Unit lastUnit = startUnit;
        int lastUnitIndex = startUnitIndex2;

        ArrayList<Line> slice = new ArrayList<>();
        addLine(startUnit, startUnitType, callerName, startLineNum, targetUnits, slice);

        int oldQueueSize1 = deque.size();
        for (int i = startUnitIndex2 + 1; i < partialUnitCount; i++) {
            Unit unit = partialUnits.get(i);
            int unitType = getUnitType(unit);
            if (unitType == -1 || unitType == IDENTITY || unitType == EXCEPTION) {
                continue;
            }

            String unitStr = (unitType == SWITCH) ? null : unit.toString();
            int unitIndex = wholeUnits.indexOf(unit);
            int lineNum = wholeUnitCount - unitIndex;

            if (unitType == IF) {
                ArrayList<String> variables = getVariables(unit, IMMEDIATE);

                boolean isInLoop = false;
                for (int j = unitIndex; j < partialUnitCount; j++) {
                    Unit prevUnit = partialUnits.get(j);
                    Unit gotoUnit = codeInspector.getTargetUnit(prevUnit);
                    if (gotoUnit == null) {
                        continue;
                    }

                    isInLoop = true;
                    break;
                }

                if (isInLoop) {
                    uselessVariables.add(variables.get(0));
                    continue;
                }

                Unit targetUnit = getTargetUnit(unit);
                if (targetUnit.equals(lastUnit)) {
                    continue;
                }

                if (excludeTargetUnits.contains(targetUnit)) {
                    continue;
                }

                int targetUnitType = getUnitType(targetUnit);
                if (targetUnitType == RETURN_VALUE && startUnitType == RETURN_VALUE && !targetUnits.contains(targetUnit)) {
                    continue;
                }

                int targetUnitIndex = wholeUnits.indexOf(targetUnit);
                if (targetUnitIndex > lastUnitIndex) {
                    continue;
                }

                if (targetUnitType != -1 && ((targetUnitType & INVOKE) == INVOKE || targetUnitType == ASSIGN_VARIABLE_SIGNATURE)) { // for kotlin
                    String signature = getSignature(targetUnit);
                    String className = getClassName(signature);
                    ArrayList<String> paramTypes = getParamTypes(signature);
                    if (paramTypes.size() == 2 && paramTypes.contains("java.lang.Object")) {
                        excludeClassNames.add(className);
                        continue;
                    }

                    Unit prevUnit = partialUnits.get(targetUnitIndex - 1);
                    int prevUnitType = getUnitType(prevUnit);
                    if (prevUnitType == NEW_EXCEPTION) {
                        excludeClassNames.add(className);// generated by Soot
                        continue;
                    }
                }

                if (unitIndex < wholeUnitCount) {
                    Unit nextUnit = partialUnits.get(unitIndex + 1); // for kotlin
                    int nextUnitType = getUnitType(nextUnit);
                    if (nextUnitType != -1 && ((nextUnitType & INVOKE) == INVOKE)) {
                        String signature = getSignature(nextUnit);
                        String className = getClassName(signature);
                        ArrayList<String> paramTypes = getParamTypes(signature);
                        if (paramTypes.size() == 2 && paramTypes.contains("java.lang.Object")) {
                            excludeClassNames.add(className);
                            continue;
                        }
                    }
                }

                lastUnit = unit;
                lastUnitIndex = unitIndex;

                addTargetVariables(variables, newTargetVariables);

                addLine(unit, unitType, callerName, lineNum, targetUnits, slice);
                continue;
            } else if (unitType == GOTO) {
                targetGotoUnits.remove(unit);

                Unit targetUnit = getTargetUnit(unit);
                if (targetUnit.equals(lastUnit)) {
                    continue;
                }

                int targetUnitIndex = wholeUnits.indexOf(targetUnit);
                if (lastUnitIndex < targetUnitIndex) {
                    continue;
                }

                int targetUnitType = getUnitType(targetUnit);
                if (targetUnitType == ASSIGN_VARIABLE_ADD) { // for for-loop
                    int j = targetUnitIndex - 2;
                    if (j > 0) {
                        Unit tempUnit = wholeUnits.get(targetUnitIndex - 2);
                        excludeTargetUnits.add(tempUnit);
                    }

                    continue;
                }

                lastUnit = unit;
                lastUnitIndex = unitIndex;

                addLine(unit, unitType, callerName, lineNum, targetUnits, slice);
                continue;
            } else if (unitType == SWITCH) {
                ArrayList<String> variables = getVariables(unit, ALL);
                uselessVariables.addAll(variables);
                continue;
            }

            int switchIndex = getSwitchIndex(unit, switchTargetsMap);
            if (switchIndex > -1) {
                i = wholeUnitCount - switchIndex;
                continue;
            }

            if (unitStr != null && unitStr.contains(targetStatement)) {
                continue;
            }

            if (unitType == ASSIGN_SIGNATURE_VARIABLE) {
                String signature = getSignature(unit);
                String variable = getRightValueStr(unit, unitType);
                if (callerName.contains("<clinit>") && !signature.equals(targetStatement) && newTargetVariables.contains(variable)) {
                    break;
                }
            } else if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                if (excludeClassNames.contains(className)) {
                    continue;
                }

                String methodName = getMethodName(signature);
                if (className.equals(startClassName) && methodName.equals(startMethodName)) {
                    continue;
                }
            }

            Unit gotoUnit = codeInspector.getTargetUnit(unit);
            if (gotoUnit != null) {
                targetGotoUnits.add(gotoUnit);
            }

            ArrayList<String> allVariables = getVariables(unit, ALL);
            HashSet<String> retainVariables = new HashSet<>(newTargetVariables);
            retainVariables.retainAll(allVariables);
            if (retainVariables.isEmpty()) {
                continue;
            }

            if ((unitType & INVOKE) == INVOKE) {
                retainVariablesMap.put(unit, new HashSet<>(retainVariables));
            }

            boolean hasConstant = false;
            for (String v : retainVariables) {
                if (isVariableStr(v) || v.contains("[")) {
                    continue;
                }

                hasConstant = true;
                break;
            }

            if (hasConstant) {
                continue;
            }

            int oldQueueSize2 = deque.size();
            Value leftValue = getLeftValue(unit, unitType);
            String leftValueStr = (leftValue != null) ? leftValue.toString() : "null";
            String rightValueStr = getRightValueStr(unit, unitType);

            switch (unitType) {
                case VIRTUAL_INVOKE:
                case STATIC_INVOKE:
                case INTERFACE_INVOKE:
                case SPECIAL_INVOKE: {
                    String signature = getSignature(unitStr);
                    String className = getClassName(signature);
                    String methodName = getMethodName(signature);
                    ArrayList<String> paramValues = getParamValues(unitStr);

                    if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
                        String oldVariable = paramValues.get(2);
                        if (!retainVariables.contains(oldVariable)) {
                            continue;
                        }

                        newTargetVariables.remove(oldVariable);
                        String newVariable = paramValues.get(0);
                        newTargetVariables.add(newVariable);
                    } else if (className.equals("java.lang.StringBuilder") && methodName.equals("append")) {
                        newTargetVariables.add(paramValues.get(0));
                    } else if (className.equals("java.util.Map") && methodName.equals("put")) {
                        String oldVariable = paramValues.get(0);
                        if (!newTargetVariables.contains(oldVariable)) {
                            continue;
                        }

                        String newVariable = paramValues.get(1);
                        newTargetVariables.add(newVariable);
                    } else if (className.contains("java.util.Objects") && methodName.equals("requireNonNull")) {
                        continue;
                    } else if (className.equals("java.io.RandomAccessFile") && methodName.equals("<init>")) {
                        break;
                    } else if ((className.equals("java.security.MessageDigest") || className.equals("javax.crypto.Cipher") || className.equals("javax.crypto.Mac")) && methodName.equals("update")) {
                        newTargetVariables.add(paramValues.get(0));
                    } else if (className.equals("javax.crypto.Cipher") && methodName.equals("init")) {
                        break; // just add this line without adding paramValues
                    } else if (className.equals("javax.crypto.Mac") && methodName.equals("init")) {
                        break;
                    } else if (className.equals("javax.crypto.spec.PBEKeySpec") && methodName.equals("<init>")) {
                        newTargetVariables.add(paramValues.get(0)); // for tracking key
                    } else if (className.contains("kotlin.jvm.internal")) {
                        continue;
                    } else {
                        String returnType = getReturnType(signature);
                        ArrayList<String> paramTypes = getParamTypes(signature);
                        if (unitType == STATIC_INVOKE && returnType.equals("void") && paramTypes.contains("java.lang.Object") && paramTypes.contains("java.lang.String")) {
                            continue;
                        }

                        String localVariable = getLocalVariable(unit);
                        if (isStackVariable(localVariable)) {
                            newTargetVariables.add(localVariable);
                        }

                        addTargetVariables(paramValues, newTargetVariables);
                    }

                    break;
                }

                case ASSIGN: { // e.g., $i1 = $i1 - $i0
                    if (targetGotoUnits.isEmpty()) {
                        newTargetVariables.remove(leftValueStr);
                    }

                    int count = frequency(allVariables, leftValueStr);
                    if (count == 1) {
                        allVariables.remove(leftValueStr);
                    }

                    addTargetVariables(allVariables, newTargetVariables);
                    break;
                }

                case ASSIGN_VIRTUAL_INVOKE:
                case ASSIGN_STATIC_INVOKE:
                case ASSIGN_INTERFACE_INVOKE:
                case ASSIGN_SPECIAL_INVOKE: {
                    if (targetGotoUnits.isEmpty()) {
                        newTargetVariables.remove(leftValueStr);
                    }

                    String signature = getSignature(unitStr);
                    String className = getClassName(signature);
                    String methodName = getMethodName(signature);
                    String localVariable = getLocalVariable(unit);
                    ArrayList<String> paramValues = getParamValues(unitStr);

                    if (className.equals("java.util.Map") && methodName.equals("get")) {
                        newTargetVariables.add(localVariable);
                        newTargetVariables.add(paramValues.get(0));
                    } else if ((className.equals("java.lang.Class") && methodName.equals("getMethod")) || (className.equals("java.lang.reflect.Method") && methodName.equals("invoke"))) {
                        break;
                    } else if (className.equals("java.util.Arrays") && (methodName.equals("copyOf") || methodName.equals("copyOfRange"))) {
                        newTargetVariables.add(paramValues.get(0));
                    } else if (className.equals("java.io.ByteArrayOutputStream") && methodName.equals("toByteArray")) {
                        newTargetVariables.add(localVariable);
                    } else if (className.equals("java.lang.Integer") && methodName.equals("parseInt")) {
                        String variable = paramValues.get(0);
                        if (retainVariables.contains(variable)) {
                            continue;
                        }

                        newTargetVariables.add(variable);
                    } else if (className.equals("java.lang.String") && methodName.equals("toCharArray")) {
                        newTargetVariables.add(localVariable);
                    } else if (className.equals("java.lang.String") && methodName.equals("getBytes")) {
                        newTargetVariables.add(localVariable);
                    } else if (className.equals("java.lang.Object") && methodName.equals("toString")) {
                        if (retainVariables.contains(localVariable)) {
                            continue;
                        }

                        newTargetVariables.add(localVariable);
                    } else if (className.contains("java.security.KeyStore")) {
                        newTargetVariables.add(localVariable);
                    } else if (className.equals("javax.crypto.Cipher") && methodName.equals("getInstance")) {
                        newTargetVariables.add(paramValues.get(0));
                    } else if (className.equals("javax.crypto.Mac") && methodName.equals("doFinal")) {
                        newTargetVariables.add(localVariable);

                        if (!paramValues.isEmpty()) {
                            newTargetVariables.add(paramValues.get(0));
                        }
                    } else if (className.equals("android.util.Base64") && methodName.equals("decode")) {
                        newTargetVariables.add(paramValues.get(0));
                    } else if (className.equals("android.database.Cursor")) {
                        break;
                    } else {
                        SootMethod sootMethod = codeInspector.getSootMethod(signature);
                        if (sootMethod == null) {
                            addTargetVariables(paramValues, newTargetVariables);
                            break;
                        }

                        String returnType = getReturnType(signature);
                        ArrayList<String> paramTypes = getParamTypes(signature);
                        HashSet<String> tempParamTypes = new HashSet<>(paramTypes);
                        if (returnType.equals("java.lang.String") && tempParamTypes.contains(returnType)) {
                            if (paramValues.contains(leftValueStr)) {
                                newTargetVariables.add(leftValueStr);
                                break;
                            } else {
                                continue;
                            }
                        }

                        handleAssignInvokeUnit(caller2, signature, paramValues);
                        if (paramValues.isEmpty()) {
                            break;
                        }

                        int deltaQueueSize = deque.size() - oldQueueSize2;
                        if (deltaQueueSize == 0) {
                            break;
                        }

                        ArrayList<String> targetParamIndexes = getTargetParamIndexes();
                        if (targetParamIndexes.isEmpty() || deltaQueueSize > 1) {
                            setTempSlicingCriteriaMap(slicingCriterion, caller2, signature, newTargetVariables, i, switchTargetsMap, targetUnits, unitStrings, targetIfUnits, uselessVariables, paramValues, isInSwitch, nextParamNums);

                            sliceMap.put(targetHashCode, slice);
                            canEscape = true;
                        } else {
                            for (String s : targetParamIndexes) {
                                int index = parseInt(s);
                                String variable = paramValues.get(index);
                                newTargetVariables.add(variable);
                            }
                        }
                    }

                    break;
                }

                case PARAMETER: {
                    String paramNum = getParamNum(unit);
                    nextParamNums.add(0, paramNum);
                    break;
                }

                case EXCEPTION: {
                    break;
                }

                case NEW_INSTANCE: {
                    if (targetGotoUnits.isEmpty()) {
                        newTargetVariables.remove(leftValueStr);
                    }

                    break;
                }

                case NEW_ARRAY: {
                    if (targetGotoUnits.isEmpty()) {
                        newTargetVariables.remove(leftValueStr);
                    }

                    String size = getArraySize(unit);
                    if (isVariableStr(size)) {
                        newTargetVariables.add(size);
                    }

                    break;
                }

                case ASSIGN_VARIABLE_CONSTANT: {
                    if (uselessVariables.contains(leftValueStr)) {
                        uselessVariables.remove(leftValueStr);
                        continue;
                    }

                    if (targetGotoUnits.isEmpty()) {
                        newTargetVariables.remove(leftValueStr);
                    }

                    break;
                }

                case ASSIGN_VARIABLE_VARIABLE: {
                    newTargetVariables.remove(leftValueStr);
                    newTargetVariables.add(rightValueStr);
                    break;
                }

                case ASSIGN_VARIABLE_ARRAY: { // eg., $r2 = $r1[4];
                    rightValueStr = rightValueStr.substring(0, rightValueStr.indexOf("["));

                    newTargetVariables.remove(leftValueStr);
                    newTargetVariables.add(rightValueStr);
                    break;
                }

                case ASSIGN_ARRAY_CONSTANT: {
                    if (targetGotoUnits.isEmpty()) {
                        newTargetVariables.remove(leftValueStr);
                    }

                    String variable = leftValueStr.substring(0, leftValueStr.indexOf("["));
                    newTargetVariables.remove(variable);

                    String index = leftValueStr.substring(leftValueStr.indexOf("[") + 1, leftValueStr.indexOf("]"));
                    if (isVariableStr(index)) {
                        newTargetVariables.add(index);
                    } else {
                        int n = Integer.parseInt(index);
                        if (n == 0) {
                            newTargetVariables.add(variable);
                        } else {
                            n--;
                            String newVariable = variable + "[" + n + "]";
                            newTargetVariables.add(newVariable);
                        }
                    }

                    break;
                }

                case ASSIGN_ARRAY_VARIABLE: { // eg., $r1[4] = $r2;
                    if (isVariableStr(rightValueStr)) {
                        newTargetVariables.add(rightValueStr);
                    }

                    if (leftValueStr.contains("[0]")) {
                        leftValueStr = leftValueStr.substring(0, leftValueStr.indexOf("["));
                        newTargetVariables.remove(leftValueStr);
                    }

                    break;
                }

                case ASSIGN_VARIABLE_SIGNATURE: {
                    int j = i + 1;
                    if (j < partialUnitCount) {
                        Unit nextUnit = partialUnits.get(j);
                        int nextUnitType = getUnitType(nextUnit);
                        if (nextUnitType == ASSIGN_SIGNATURE_VARIABLE) { // skip ASSIGN_SIGNATURE_VARIABLE + ASSIGN_VARIABLE_SIGNATURE
                            String nextLeftValueStr = getLeftValueStr(nextUnit, nextUnitType);
                            String nextRightValueStr = getRightValueStr(nextUnit, nextUnitType);
                            if (leftValueStr.equals(nextRightValueStr) && rightValueStr.equals(nextLeftValueStr)) {
                                continue;
                            }
                        }
                    }

                    newTargetVariables.remove(leftValueStr);
                    String localVariable = getLocalVariable(unit);
                    if (isStackVariable(localVariable)) { // e.g., $r8 = $r0.<com.waz.utils.crypto.AESUtils$EncryptedBytes: byte[] bytes>
                        newTargetVariables.add(rightValueStr);
                    }

                    String signature = getSignature(unitStr);
                    Unit modifiedUnit = getNewAssignUnit(unit, leftValue, signature);
                    if (unit.equals(modifiedUnit)) {
                        handleAssignVariableSignatureUnit(caller, caller2, signature);
                    } else {
                        unit = modifiedUnit;
                        unitType = ASSIGN_VARIABLE_CONSTANT;
                    }

                    break;
                }

                case ASSIGN_SIGNATURE_VARIABLE: {
                    String signature = getSignature(unitStr);
                    newTargetVariables.remove(signature);

                    String methodName = getMethodName(callerName);
                    if (methodName.equals("<init>")) {
                        newTargetVariables.add(rightValueStr);
                    }

                    break;
                }

                case CAST:
                case LENGTH_OF: {
                    if (!retainVariables.contains(leftValueStr)) {
                        continue;
                    }

                    newTargetVariables.remove(leftValueStr);
                    String newVariable = rightValueStr.split(" ")[1];
                    newTargetVariables.add(newVariable);
                    break;
                }

                case RETURN_VALUE: {
                    String variable = getRightValueStr(unit, unitType);
                    uselessVariables.add(variable);
                    continue;
                }

                default: {
                    continue;
                }
            }

            lastUnit = unit;
            lastUnitIndex = unitIndex;

            addLine(unit, unitType, callerName, lineNum, targetUnits, slice);

            int deltaQueueSize = deque.size() - oldQueueSize2;
            if (deltaQueueSize == 0) {
                continue;
            }

            ArrayList<SlicingCriterion> slicingCriteria = new ArrayList<>();
            for (int j = 0; j < deltaQueueSize; j++) {
                SlicingCriterion tempCriterion = deque.removeLast();
                slicingCriteria.add(0, tempCriterion);
            }

            deque.addAll(slicingCriteria);
            derivedSlicingCriteriaMap.put(unit, slicingCriteria);

            if (canEscape) {
                break;
            }
        }

        ArrayList<Unit> infeasibleUnits = new ArrayList<>();
        if (((startUnitType & ASSIGN_SIGNATURE_VARIABLE) == ASSIGN_SIGNATURE_VARIABLE)) {
            infeasibleUnits = constraintSolver.findInfeasibleUnits(callerName, targetUnits);
        } else if ((startUnitType & RETURN) == RETURN) {
            infeasibleUnits = sliceOptimizer.findInfeasibleUnits(callerName, targetUnits, targetParamValues);
        }

        if (infeasibleUnits.contains(startUnit)) {
            infeasibleUnits.addAll(targetUnits);
            removeUnreachableSlicingCriteria(infeasibleUnits);

            slice.clear();
            sliceMap.put(targetHashCode, slice);
            return;
        } else {
            removeLines(slice, infeasibleUnits);
            removeUnreachableSlicingCriteria(infeasibleUnits);
        }

        /* print this slice */
        System.out.println(slicingCriterion);
        for (Line l : slice) {
            System.out.println(l);
        }
        System.out.println();

        String key;
        String parentHashCode = caller2.getId();
        ArrayList<Line> parentSlice = sliceMap.get(parentHashCode);
        if (parentSlice != null && !parentSlice.containsAll(slice)) {
            key = parentHashCode;
            slice.addAll(parentSlice);
        } else {
            key = targetHashCode;
        }

        sliceMap.put(key, slice);
        if (canEscape || slice.isEmpty()) {
            return;
        }

        handleParameterUnit(caller, caller2, nextParamNums, callerNames);
        removeUselessSlicingCriteria(callerName, oldTargetVariables, startUnit, lastUnit, oldQueueSize1);
    }

    private void addTargetVariables(ArrayList<String> variables, HashSet<String> targetVariables) {
        for (String v : variables) {
            if (!isVariableStr(v)) {
                continue;
            }

            targetVariables.add(v);
        }
    }

    private void handleAssignInvokeUnit(Node caller2, String calleeName, ArrayList<String> paramValues) {
        int level = (int) (caller2.getAttribute("level"));
        if (level == lowerLevel) {
            return;
        }

        String targetStatement1 = "return";
        level--;

        String bridgeNodeId = String.valueOf(calleeName.hashCode());
        Node bridgeNode = sliceMerger.addNode(bridgeNodeId, bridgeNodeId, null);

        ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(calleeName, targetStatement1, null, RETURN_VALUE, null, new ArrayList<>(paramValues));
        for (SlicingCriterion sc : slicingCriteria) {
            String callee2Id = String.valueOf(sc.hashCode());
            Node callee2 = sliceMerger.addNode(callee2Id, callee2Id, null);
            callee2.setAttribute("level", level);

            sliceMerger.addEdge(bridgeNode, callee2, DOWNWARD);

            sc.setCaller2(callee2);
            deque.add(sc);
        }
    }

    private void handleAssignVariableSignatureUnit(Node oldCaller, Node oldCaller2, String signature) {
        Node valueNode = codeInspector.getNode(signature);
        if (valueNode == null) {
            return;
        }

        int level = (int) (oldCaller2.getAttribute("level"));
        if (level == upperLevel) {
            return;
        }

        level++;

        String bridgeNodeId = String.valueOf(signature.hashCode());
        Node bridgeNode = sliceMerger.getNode(bridgeNodeId);
        if (bridgeNode != null) {
            return;
        }

        bridgeNode = sliceMerger.addNode(bridgeNodeId, bridgeNodeId, null);

        Stream<Edge> stream = valueNode.edges();
        List<Edge> edges = stream.collect(toList());
        for (Edge e : edges) {
            EdgeType type = (EdgeType) e.getAttribute("ui.class");
            if (type == READ) {
                continue;
            }

            Node source = e.getSourceNode();
            if (source.equals(oldCaller)) {
                continue;
            }

            String sourceId = source.getId();
            String className = getClassName(sourceId);
            SootClass sootClass = Scene.v().getSootClass(className);
            if (sootClass.isEnum()) {
                continue;
            }

            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(sourceId, signature, null, ASSIGN, null, null);
            for (SlicingCriterion sc : slicingCriteria) {
                String newCaller2Id = valueOf(sc.hashCode());
                Node newCaller2 = sliceMerger.addNode(newCaller2Id, newCaller2Id, null);
                newCaller2.setAttribute("level", level);
                sliceMerger.addEdge(bridgeNode, newCaller2, null);

                sc.setCaller2(newCaller2);
                deque.add(sc);
            }
        }
    }

    private void handleParameterUnit(Node callee, Node callee2, ArrayList<String> paramNums, HashSet<String> callerNames) {
        if (paramNums.isEmpty()) {
            return;
        }

        String calleeName = callee.getId();
        ArrayList<SlicingCriterion> tempSlicingCriteria = tempSlicingCriteriaMap.get(calleeName);
        if (tempSlicingCriteria != null) {
            for (SlicingCriterion sc : tempSlicingCriteria) {
                ArrayList<String> targetVariables = sc.getTargetVariables();
                ArrayList<String> targetParamValues = sc.getTargetParamValues();
                for (String v : targetParamValues) {
                    int index = targetParamValues.indexOf(v);
                    if (!paramNums.contains(valueOf(index))) {
                        continue;
                    }

                    if (!targetVariables.contains(v)) {
                        targetVariables.add(v);
                    }
                }

                sc.setTargetStatement1(calleeName);
                deque.add(sc);
            }

            return;
        }

        int level = (int) (callee2.getAttribute("level"));
        if (level == upperLevel) {
            return;
        }

        level++;

        Stream<Edge> stream = callee.enteringEdges();
        List<Edge> edges = stream.collect(toList());
        for (Edge e : edges) {
            Node source = e.getSourceNode();
            String sourceName = source.getId();
            if (callerNames != null && !callerNames.contains(sourceName)) {
                continue;
            }

            ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria(sourceName, calleeName, null, INVOKE, paramNums, null);
            tempSlicingCriteria = new ArrayList<>(slicingCriteria);

            for (SlicingCriterion sc : tempSlicingCriteria) {
                String hashCode = String.valueOf(sc.hashCode());
                Node caller2 = sliceMerger.addNode(hashCode, hashCode, null);
                caller2.setAttribute("level", level);

                sliceMerger.addEdge(callee2, caller2, UPWARD);

                ArrayList<SlicingCriterion> splitted = slicingCriteriaGenerator.splitSlicingCriterion(sc);
                for (SlicingCriterion sc2 : splitted) {
                    sc2.setCaller2(caller2);
                    deque.add(sc2);
                }
            }
        }
    }

    private void addLine(Unit unit, int unitType, String callerName, int lineNum, ArrayList<Unit> targetUnits, ArrayList<Line> slice) {
        targetUnits.add(0, unit);

        Line line = new Line();
        line.setUnit(unit);
        line.setUnitType(unitType);
        line.setCallerName(callerName);
        line.setLineNumber(lineNum);

        slice.add(0, line);
    }

    private ArrayList<String> getTargetParamIndexes() {
        ArrayList<String> indexes = new ArrayList<>();

        SlicingCriterion slicingCriterion = deque.removeLast();
        deque.add(slicingCriterion);

        String tempHashCode = String.valueOf(slicingCriterion.hashCode());
        ArrayList<Line> tempSlice = sliceMap.get(tempHashCode);
        if (tempSlice == null) {
            return indexes;
        }

        for (Line l : tempSlice) {
            Unit unit = l.getUnit();
            int unitType = l.getUnitType();
            if (unitType == PARAMETER) {
                String paramNum = getParamNum(unit);
                indexes.add(paramNum);
            }
        }

        return indexes;
    }

    private void setTempSlicingCriteriaMap(SlicingCriterion slicingCriterion, Node caller2, String signature, HashSet<String> targetVariables, int targetUnitIndex, HashMap<Integer, ArrayList<Unit>> switchTargetsMap, ArrayList<Unit> targetUnits, ArrayList<String> unitStrings, ArrayList<Unit> targetIfUnits, ArrayList<String> loopVariables, ArrayList<String> targetParamValues, boolean isInSwitch, ArrayList<String> nextParamNums) {
        ArrayList<SlicingCriterion> tempSlicingCriteria = tempSlicingCriteriaMap.get(signature);
        if (tempSlicingCriteria == null) {
            tempSlicingCriteria = new ArrayList<>();
        }

        SlicingCriterion tempSlicingCriterion = (SlicingCriterion) slicingCriterion.clone();
        tempSlicingCriterion.setCaller2(caller2);
        tempSlicingCriterion.setTargetStatement1(signature);
        tempSlicingCriterion.setTargetVariables(new ArrayList<>(targetVariables));
        tempSlicingCriterion.setTargetUnitIndex(targetUnitIndex);
        tempSlicingCriterion.setSwitchTargetsMap(switchTargetsMap);
        tempSlicingCriterion.setTargetUnits(new ArrayList<>(targetUnits));
        tempSlicingCriterion.setUnitStrings(new ArrayList<>(unitStrings));
        tempSlicingCriterion.setTargetIfUnits(targetIfUnits);
        tempSlicingCriterion.setUselessVariables(new ArrayList<>(loopVariables));
        tempSlicingCriterion.setTargetParamValues(new ArrayList<>(targetParamValues));
        tempSlicingCriterion.setInSwitch(isInSwitch);
        tempSlicingCriterion.setNextParamNums(nextParamNums);
        tempSlicingCriteria.add(tempSlicingCriterion);

        tempSlicingCriteriaMap.put(signature, tempSlicingCriteria);
    }

    private Unit getNewAssignUnit(Unit unit, Value leftValue, String signature) {
        Value value = codeInspector.getConstantValue(signature);
        if (value != null) {
            return new JAssignStmt(leftValue, value);
        }

        boolean existWriteEdge = false;
        Node node = codeInspector.getNode(signature);
        if (node == null) {
            return unit;
        }

        Stream<Edge> stream = node.edges();
        List<Edge> edges = stream.collect(toList());
        for (Edge e : edges) {
            EdgeType type = (EdgeType) e.getAttribute("ui.class");
            if (type == READ) {
                continue;
            }

            existWriteEdge = true;
            break;
        }

        if (!existWriteEdge) {
            String variableType = getReturnType(signature);
            value = (variableType.equals("boolean")) ? IntConstant.v(0) : NullConstant.v();
            unit = new JAssignStmt(leftValue, value);
        }

        return unit;
    }

    private void removeLines(ArrayList<Line> slice, ArrayList<Unit> targetUnits) {
        ArrayList<Line> tempSlice = new ArrayList<>(slice);
        for (Line l : tempSlice) {
            Unit unit = l.getUnit();
            if (targetUnits.contains(unit)) {
                slice.remove(l);
            }
        }
    }

    private void removeUnreachableSlicingCriteria(ArrayList<Unit> infeasibleUnits) {
        for (Unit u : infeasibleUnits) {
            ArrayList<SlicingCriterion> slicingCriteria = derivedSlicingCriteriaMap.get(u);
            if (slicingCriteria == null) {
                continue;
            }

            deque.removeAll(slicingCriteria);
        }
    }

    private void removeUselessSlicingCriteria(String callerName, ArrayList<String> oldTargetVariables, Unit startUnit, Unit lastUnit, int oldQueueSize) {
        int deltaQueueSize = deque.size() - oldQueueSize;
        if (deltaQueueSize < 1) {
            return;
        }

        SlicingCriterion lastSlicingCriterion = deque.removeLast(); // to avoid useless slicing
        String lastTargetStatement = lastSlicingCriterion.getTargetStatement1();
        String localVariable = getLocalVariable(startUnit);
        int startUnitType = getUnitType(startUnit);
        int lastUnitType = getUnitType(lastUnit);

        if (!oldTargetVariables.contains(localVariable) && (startUnitType & INVOKE) == INVOKE && lastUnitType == PARAMETER && !lastTargetStatement.equals(callerName)) {
            deltaQueueSize--;

            for (int i = 0; i < deltaQueueSize; i++) {
                deque.removeLast();
            }
        } else {
            deque.add(lastSlicingCriterion);
        }
    }

    private static class Holder {
        private static final ProgramSlicer instance = new ProgramSlicer();
    }
}