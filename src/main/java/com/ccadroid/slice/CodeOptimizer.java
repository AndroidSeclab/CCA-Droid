package com.ccadroid.slice;

import com.ccadroid.inspect.CodeInspector;
import com.ccadroid.util.ChocoSolver;
import org.json.JSONArray;
import org.json.JSONObject;
import soot.*;
import soot.jimple.IntConstant;
import soot.jimple.Jimple;
import soot.jimple.NullConstant;
import soot.jimple.StringConstant;
import soot.jimple.internal.*;
import soot.util.Chain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static com.ccadroid.slice.SliceConstant.*;
import static com.ccadroid.util.Common.isNumber;
import static com.ccadroid.util.soot.Soot.*;
import static com.ccadroid.util.soot.SootUnit.*;

public class CodeOptimizer {
    private static final CodeInspector codeInspector;
    private static final ProgramSlicer programSlicer;
    private static final SliceDatabase sliceDatabase;

    static {
        codeInspector = CodeInspector.getInstance();
        programSlicer = ProgramSlicer.getInstance();
        sliceDatabase = SliceDatabase.getInstance();
    }

    private final HashMap<Value, Value> aliasingVariableMap;
    private final HashMap<String, Integer> variableCountMap;

    public CodeOptimizer() {
        aliasingVariableMap = new HashMap<>();
        variableCountMap = new HashMap<>();
    }

    public static CodeOptimizer getInstance() {
        return SingletonHolder.instance;
    }

    public void runPointerAnalysis(String callerName, ArrayList<Unit> wholeUnit) {
        ArrayList<Integer> indexes = new ArrayList<>();
        ArrayList<Unit> aliasedUnits = getAliasedUnits(wholeUnit);

        for (int i = 0; i < wholeUnit.size(); i++) {
            Unit unit = wholeUnit.get(i);
            int unitType = getUnitType(unit);

            if (unitType == IF) {
                Value condition = getIfCondition(unit, unitType);
                ArrayList<Value> tempValues = new ArrayList<>();
                ArrayList<Value> conditionValues = getIfConditionValues(unit, unitType);
                for (Value v : conditionValues) {
                    Value newValue = aliasingVariableMap.get(v);
                    tempValues.add(newValue == null || newValue == NullConstant.v() ? v : newValue);
                }

                setIfCondition(unit, condition, tempValues);

                if (isIfElseStatement(wholeUnit, unit, unitType)) {
                    Unit targetUnit = getIfGotoTargetUnit(unit, unitType);
                    int j = wholeUnit.indexOf(targetUnit);
                    IntStream.range(i, j + 1).forEach(indexes::add);
                }
            }

            if (!aliasedUnits.contains(unit)) {
                continue;
            }

            Value leftOp = getLeftOp(unit, unitType);
            Value rightOp = getRightOp(unit, unitType);

            if ((unitType & INVOKE) == INVOKE) {
                Value oldBase = getBase(unit, unitType);
                Value newBase = aliasingVariableMap.get(oldBase);

                ArrayList<Value> newParameters = new ArrayList<>();
                ArrayList<Value> parameters = getParameters(unit, unitType);
                for (Value v : parameters) {
                    Value newValue = (aliasingVariableMap.get(v) != v && aliasingVariableMap.get(v) != NullConstant.v()) ? aliasingVariableMap.getOrDefault(v, v) : v;
                    newParameters.add(newValue);
                }

                if ((unitType & ASSIGN) == ASSIGN) {
                    Value newLeftOp = (aliasingVariableMap.containsKey(leftOp) && !indexes.contains(i) ? getNewAssignedValue(callerName, leftOp) : leftOp);
                    aliasingVariableMap.put(leftOp, newLeftOp);

                    setAssignInvokeUnit(unit, newLeftOp, newBase, newParameters);
                } else {
                    setInvokeUnit(unit, newBase, newParameters);
                }
            } else if (unitType == NEW_INSTANCE || unitType == NEW_ARRAY || ((unitType & ASSIGN_VARIABLE) == ASSIGN_VARIABLE) || unitType == CAST || unitType == LENGTH_OF) {
                Value newLeftOp;

                if (aliasingVariableMap.containsKey(leftOp) && !indexes.contains(i)) {
                    if (aliasingVariableMap.containsKey(IntConstant.v(rightOp.equivHashCode()))) {
                        newLeftOp = aliasingVariableMap.get(leftOp) == NullConstant.v() ? getNewAssignedValue(callerName, leftOp) : aliasingVariableMap.get(leftOp);
                    } else {
                        newLeftOp = getNewAssignedValue(callerName, leftOp);
                    }
                } else {
                    newLeftOp = leftOp;
                }

                aliasingVariableMap.put(leftOp, newLeftOp);

                if (unitType == NEW_INSTANCE || unitType == NEW_ARRAY || (unitType & ASSIGN_VARIABLE) == ASSIGN_VARIABLE) {
                    setAssignUnit(unit, newLeftOp, rightOp);
                } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                    Value base = getBase(unit, unitType);
                    Value newBase = aliasingVariableMap.getOrDefault(base, base);
                    setAssignVariableSignatureUnit(unit, newLeftOp, rightOp, newBase);
                } else if (unitType == CAST) {
                    Value internalOp = getRightInternalOp(unit, unitType);
                    Value newInternalOp = (aliasingVariableMap.get(internalOp) == NullConstant.v()) ? internalOp : aliasingVariableMap.get(internalOp);
                    setCastUnit(unit, newLeftOp, rightOp, newInternalOp);
                } else { // lengthOf
                    Value internalOp = getRightInternalOp(unit, unitType);
                    Value newInternalOp = aliasingVariableMap.get(internalOp);
                    setLengthOfUnit(unit, newLeftOp, rightOp, newInternalOp);
                }
            } else if (unitType == ASSIGN_ARRAY_CONSTANT) {
                Value base = getBase(unit, unitType);
                Value newBase = aliasingVariableMap.get(base);
                setArrayBase(leftOp, newBase);
            } else if (unitType == ASSIGN_SIGNATURE_VARIABLE) {
                Value base = getBase(unit, unitType);
                Value newRightOp = (aliasingVariableMap.get(rightOp) == NullConstant.v()) ? rightOp : aliasingVariableMap.get(rightOp);
                setAssignSignatureVariable(unit, leftOp, base, newRightOp);
            } else if (unitType == RETURN_VALUE) {
                Value newRightOp = aliasingVariableMap.get(rightOp);
                setReturnValue(unit, newRightOp);
            }
        }
    }

    public void preModifyUnits(ArrayList<Unit> wholeUnit) {
        ArrayList<Value> callerParameters = new ArrayList<>();
        HashMap<Value, String> targetValueMap = new HashMap<>();

        for (Unit u : wholeUnit) {
            int unitType = getUnitType(u);
            if (unitType == -1) {
                continue;
            }

            if (unitType == PARAMETER) {
                Value leftOp = getLeftOp(u, unitType);
                callerParameters.add(leftOp);
            } else if ((unitType & INVOKE) == INVOKE) {
                String unitString = u.toString();
                String signature = getSignature(unitString);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);

                if (className.equals("java.lang.String") && methodName.equals("replace")) {
                    Value base = getBase(u, unitType);
                    if (!targetValueMap.containsKey(base)) {
                        continue;
                    }

                    Value leftOp = getLeftOp(u, unitType);
                    String constant = targetValueMap.get(base);
                    ArrayList<String> parameters = getParameters(unitString);
                    String oldChar = parameters.get(0);
                    String newChar = parameters.get(1);

                    String newValueStr = constant.replace(oldChar, newChar);
                    Value newValue = StringConstant.v(newValueStr);
                    setAssignUnit(u, leftOp, newValue);
                } else if (className.equals("java.lang.Math") && (methodName.equals("abs") || methodName.equals("round"))) {
                    Value leftOp = getLeftOp(u, unitType);
                    ArrayList<Value> parameters = getParameters(u, unitType);
                    Value v = parameters.get(0);
                    String valueStr = convertToStr(v);
                    String str = targetValueMap.getOrDefault(v, valueStr);
                    if (!isNumber(str)) {
                        continue;
                    }

                    ArrayList<String> paramTypes = getParamTypes(signature);
                    String targetType = paramTypes.get(0);
                    Value newValue = convertToValue(targetType, str);
                    setAssignUnit(u, leftOp, newValue);
                } else if (className.equals("java.lang.Integer") && methodName.equals("parseInt")) {
                    Value leftOp = getLeftOp(u, unitType);
                    ArrayList<Value> parameters = getParameters(u, unitType);
                    Value v = parameters.get(0);
                    String valueStr = convertToStr(v);
                    String str = targetValueMap.getOrDefault(v, valueStr);
                    if (!isNumber(str)) {
                        continue;
                    }

                    Value newValue = convertToValue("int", str);
                    setAssignUnit(u, leftOp, newValue);
                }
            } else if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                Value leftOp = getLeftOp(u, unitType);
                Value rightOp = getRightOp(u, unitType);
                targetValueMap.put(leftOp, convertToStr(rightOp));
            } else if (unitType == IF || unitType == GOTO) {
                int unitIndex = wholeUnit.indexOf(u);
                int gotoUnitIndex = getTargetUnitIndex(wholeUnit, u, unitType);
                int startUnitIndex = unitIndex + 1;
                int endUnitIndex = gotoUnitIndex - 1;
                ArrayList<Unit> units = new ArrayList<>();
                for (int i = startUnitIndex; i < endUnitIndex; i++) {
                    Unit unit = wholeUnit.get(i);
                    units.add(unit);
                }

                ArrayList<Value> conditionValues = getIfConditionValues(u, unitType);
                ArrayList<Value> tempValues = new ArrayList<>(callerParameters);
                tempValues.retainAll(conditionValues);
                if (!tempValues.isEmpty()) {
                    continue;
                }

                ArrayList<String> randomSignatures = getRandomSignatures();
                if (hasSignature(units, randomSignatures)) {
                    IntStream.range(startUnitIndex, endUnitIndex).forEach(i -> wholeUnit.set(i, getNopStmt()));
                }
            }
        }
    }

    public void removeUnreachableUnits(ArrayList<Unit> wholeUnit) {
        ArrayList<Unit> tempUnits = getUnreachableUnits(wholeUnit, wholeUnit, new HashMap<>());
        tempUnits.forEach(wholeUnit::remove);
    }

    public void removeUselessStatement(ArrayList<Unit> units, ArrayList<JSONObject> contents) {
        ArrayList<JSONObject> tempContents = new ArrayList<>();

        for (int i = 0; i < units.size(); i++) {
            Unit unit = units.get(i);
            int unitType = getUnitType(unit);

            if (unitType == NOP) {
                JSONObject line = contents.get(i);
                tempContents.add(line);
            }
        }

        contents.removeAll(tempContents);
    }

    public void postModifyUnits(ArrayList<Unit> units) {
        HashMap<Value, String> targetValueMap = new HashMap<>();

        for (Unit u : units) {
            int unitType = getUnitType(u);
            if (unitType == -1) {
                continue;
            }

            if ((unitType & INVOKE) == INVOKE) {
                String unitString = u.toString();
                String signature = getSignature(unitString);
                List<String> query = List.of(String.format("%s==%s", CALLER_NAME, signature), String.format("%s==return", TARGET_STATEMENT), String.format("%s!=null", CONTENTS));
                JSONObject result = sliceDatabase.selectOne(query);
                if (result == null) {
                    continue;
                }

                String nodeId = result.getString(NODE_ID);
                ArrayList<Unit> targetUnits = programSlicer.getUnits(nodeId);
                Unit targetUnit = targetUnits.get(0);
                int targetUnitType = getUnitType(targetUnit);
                if (targetUnitType != RETURN_VALUE) {
                    continue;
                }

                Value rightOp = getRightOp(targetUnit, targetUnitType);
                if (rightOp == null || !isStackVariable(rightOp)) {
                    continue;
                }

                Value leftOp = getLeftOp(u, unitType);
                setAssignUnit(u, leftOp, rightOp);
                targetValueMap.put(leftOp, convertToStr(rightOp));
            } else if (unitType == RETURN_VALUE) {
                Value oldRightOp = getRightOp(u, unitType);
                String constant = targetValueMap.get(oldRightOp);
                if (constant == null) {
                    continue;
                }

                String returnType = convertToStr(oldRightOp).contains("i") ? "int" : "java.lang.String";
                Value newRightOp = convertToValue(returnType, constant);
                setReturnValue(u, newRightOp);
            }
        }
    }

    public void removeUnreachableStatement(ArrayList<JSONObject> slices, ArrayList<JSONObject> contents) {
        HashMap<Value, String> targetValueMap = new HashMap<>();

        for (JSONObject s : slices) {
            String nodeId = s.getString(NODE_ID);
            String callerName = s.getString(CALLER_NAME);
            JSONArray c = s.getJSONArray(CONTENTS);
            ArrayList<Unit> wholeUnit = codeInspector.getWholeUnit(callerName);
            ArrayList<Unit> units = programSlicer.getUnits(nodeId);
            ArrayList<Unit> tempUnits = getUnreachableUnits(wholeUnit, units, targetValueMap);

            for (Unit u : units) {
                if (!tempUnits.contains(u)) {
                    continue;
                }

                for (int i = 0; i < c.length(); i++) {
                    JSONObject line = c.getJSONObject(i);
                    if (u.toString().equals(line.getString(UNIT_STRING))) {
                        contents.remove(line);
                        break;
                    }
                }
            }
        }
    }

    private ArrayList<Unit> getAliasedUnits(List<Unit> wholeUnit) {
        ArrayList<Unit> units = new ArrayList<>();

        for (Unit u : wholeUnit) {
            int unitType = getUnitType(u);
            if (unitType == -1) {
                continue;
            }

            Value leftOp = ((unitType & ASSIGN_ARRAY) == ASSIGN_ARRAY) ? getBase(u, unitType) : getLeftOp(u, unitType);
            Value base = getBase(u, unitType);
            Value rightOp = getRightOp(u, unitType);
            ArrayList<Value> parameters = getParameters(u, unitType);
            if ((leftOp == null && base == null && rightOp == null && parameters.isEmpty()) || (unitType == RETURN_VALUE && rightOp == NullConstant.v())) { // static or return null
                continue;
            }

            List<Value> targetValues = parameters.stream().filter(v -> aliasingVariableMap.get(v) == NullConstant.v()).collect(Collectors.toList());
            if (aliasingVariableMap.containsKey(leftOp) || aliasingVariableMap.get(base) == NullConstant.v() || aliasingVariableMap.get(rightOp) == NullConstant.v() || !targetValues.isEmpty()) {
                Value value = (leftOp == null) ? (base == null) ? rightOp : base : (isStackVariable(leftOp) ? leftOp : IntConstant.v(leftOp.equivHashCode()));
                aliasingVariableMap.put(value, NullConstant.v());
                units.add(u);
            } else if ((unitType & ASSIGN) == ASSIGN && (unitType & ASSIGN_VARIABLE_OPERATION) != ASSIGN_VARIABLE_OPERATION && isStackVariable(leftOp)) {
                aliasingVariableMap.putIfAbsent(leftOp, leftOp);
            }
        }

        return units;
    }

    private Value getNewAssignedValue(String signature, Value local) {
        int count;

        if (variableCountMap.containsKey(signature)) {
            count = variableCountMap.get(signature);
        } else {
            SootMethod sootMethod = getSootMethod(signature);
            Chain<Local> locals = getLocals(sootMethod);
            count = locals.size();
        }

        count++;
        variableCountMap.put(signature, count);

        String localString = local.toString();
        String name = localString.replaceAll("[0-9]{1,10}", String.valueOf(count));
        Type type = local.getType();

        return Jimple.v().newLocal(name, type);
    }

    private int getTargetUnitIndex(ArrayList<Unit> wholeUnit, Unit unit, int unitType) {
        if (isLoopStatement(wholeUnit, unit, unitType)) {
            return -1;
        }

        Unit targetUnit = getIfGotoTargetUnit(unit, unitType);

        return wholeUnit.indexOf(targetUnit);
    }

    private ArrayList<String> getRandomSignatures() {
        ArrayList<String> list = new ArrayList<>();
        list.add("<java.util.Random: int nextInt()>");
        list.add("<java.util.Random: int nextInt(int)>");
        list.add("<java.util.Random: long nextLong()>");
        list.add("<java.util.Random: void nextBytes(byte[])>");
        list.add("<java.security.SecureRandom int next(int)>");
        list.add("<java.security.SecureRandom: int nextInt()>");
        list.add("<java.security.SecureRandom: java.util.stream.IntStream ints()>");
        list.add("<java.security.SecureRandom: void nextBytes(byte[])>");
        list.add("<javax.crypto.KeyAgreement: byte[] generateSecret()>");
        list.add("<javax.crypto.KeyGenerator: javax.crypto.SecretKey generateKey()>");

        return list;
    }

    private boolean hasSignature(ArrayList<Unit> units, ArrayList<String> signatures) {
        for (Unit u : units) {
            int unitType = getUnitType(u);
            if (unitType == -1) {
                continue;
            }

            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String signature = getSignature(u);
            if (signatures.contains(signature)) {
                return true;
            }
        }

        return false;
    }

    private ArrayList<Unit> getUnreachableUnits(ArrayList<Unit> wholeUnit, ArrayList<Unit> units, HashMap<Value, String> targetValueMap) {
        int wholeUnitCount = wholeUnit.size();
        ArrayList<Unit> tempUnits = new ArrayList<>();

        for (int i = 0; i < wholeUnitCount; i++) {
            Unit unit = wholeUnit.get(i);
            if (!units.contains(unit)) {
                continue;
            }

            int unitType = getUnitType(unit);
            if (unitType == -1) {
                continue;
            }

            if ((unitType & INVOKE) == INVOKE) {
                String unitString = unit.toString();
                String signature = getSignature(unitString);
                ArrayList<Value> parameters = getParameters(unit, unitType);

                mappingParameters(parameters, signature, targetValueMap);
            } else if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                Value leftOp = getLeftOp(unit, unitType);
                if (targetValueMap.containsKey(leftOp)) { // avoid ternary operator
                    targetValueMap.remove(leftOp);
                } else {
                    Value rightOp = getRightOp(unit, unitType);
                    String rightOpStr = convertToStr(rightOp);
                    targetValueMap.put(leftOp, rightOpStr);
                }
            } else if (unitType == ASSIGN_VARIABLE_VARIABLE) {
                Value leftOp = getLeftOp(unit, unitType);
                Value rightOp = getRightOp(unit, unitType);

                targetValueMap.put(rightOp, targetValueMap.remove(leftOp));
            } else if (unitType == ASSIGN_VARIABLE_OPERATION) {
                Value leftOp = getLeftOp(unit, unitType);
                targetValueMap.remove(leftOp);
            } else if (unitType == IF) {
                if (isLoopStatement(wholeUnit, unit, unitType)) {
                    continue;
                }

                int result = getIfStatementResult(unit, unitType, targetValueMap);
                if (result == -1) {
                    continue;
                }

                Unit targetUnit = getIfGotoTargetUnit(unit, unitType);
                int targetUnitIndex = wholeUnit.indexOf(targetUnit);
                if (targetUnitIndex == -1) { // The targetUnit may be JNopStmt
                    continue;
                }

                Unit prevUnit = wholeUnit.get(targetUnitIndex - 1);
                int gotoUnitIndex = wholeUnit.indexOf(prevUnit);
                if (result == 1) {
                    for (int j = i + 1; j < gotoUnitIndex; j++) {
                        Unit u = wholeUnit.get(j);
                        tempUnits.add(u);
                    }

                    i = targetUnitIndex;
                } else {
                    int prevUnitType = getUnitType(prevUnit);
                    Unit prevTargetUnit = getIfGotoTargetUnit(prevUnit, prevUnitType);
                    if (prevTargetUnit == null) {
                        continue;
                    }

                    int prevTargetUnitIndex = wholeUnit.indexOf(prevTargetUnit);
                    for (int j = gotoUnitIndex + 1; j < prevTargetUnitIndex; j++) {
                        Unit u = wholeUnit.get(j);
                        tempUnits.add(u);
                    }

                    i = prevTargetUnitIndex;
                }
            }
        }

        return tempUnits;
    }

    private void mappingParameters(ArrayList<Value> parameters, String signature, HashMap<Value, String> targetValueMap) {
        ArrayList<Unit> wholeUnit = codeInspector.getWholeUnit(signature);
        if (wholeUnit == null) {
            return;
        }

        for (Unit u : wholeUnit) {
            int unitType = getUnitType(u);
            if (unitType == -1) {
                continue;
            }

            if (unitType == PARAMETER) {
                int index = getParamIndex(u, unitType);
                Value targetValue = parameters.get(index);
                if (!targetValueMap.containsKey(targetValue) && isStackVariable(targetValue)) {
                    continue;
                }

                Value leftOp = getLeftOp(u, unitType);
                targetValueMap.put(leftOp, targetValueMap.containsKey(targetValue) ? targetValueMap.get(targetValue) : convertToStr(targetValue));
            } else {
                break;
            }
        }
    }

    private int getIfStatementResult(Unit unit, int unitType, HashMap<Value, String> targetValueMap) {
        Value condition = getIfCondition(unit, unitType);
        if (condition == null) {
            return -1;
        }

        AbstractJimpleIntBinopExpr expr = (AbstractJimpleIntBinopExpr) condition;
        String operand = getOperand(condition);
        Value op1 = expr.getOp1();
        Value op2 = expr.getOp2();
        String str1 = targetValueMap.get(op1);
        String str2 = targetValueMap.get(op2);

        if (isNumber(str1) && isNumber(str2)) {
            return ChocoSolver.getResolveResult(str1, operand, str2) == 1 ? 1 : 0;
        } else if ((isNumber(str1) && isNumericConstant(op2)) || (isNumericConstant(op1) && isNumber(str2))) {
            str1 = str1 == null ? convertToStr(op1) : str1;
            str2 = str2 == null ? convertToStr(op2) : str2;

            return ChocoSolver.getResolveResult(str1, operand, str2) == 1 ? 1 : 0;
        } else if ((!isNumber(str1) && isNumericConstant(op2)) || (isNumericConstant(op1) && !isNumber(str2))) { // e.g., $i1 < 32
            return -1;
        } else {
            return -1;
        }
    }

    private String getOperand(Value condition) {
        String operand = null;

        if (condition instanceof JGeExpr) {
            operand = ">=";
        } else if (condition instanceof JGtExpr) {
            operand = ">";
        } else if (condition instanceof JEqExpr) {
            operand = "=";
        } else if (condition instanceof JNeExpr) {
            operand = "!=";
        } else if (condition instanceof JLtExpr) {
            operand = "<";
        } else if (condition instanceof JLeExpr) {
            operand = "<=";
        }

        return operand;
    }

    private static class SingletonHolder {
        private static final CodeOptimizer instance = new CodeOptimizer();
    }
}