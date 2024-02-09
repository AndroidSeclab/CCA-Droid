package com.ccadroid.slice;

import com.ccadroid.inspect.CodeInspector;
import org.apache.commons.lang3.math.NumberUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import soot.Unit;
import soot.Value;
import soot.jimple.IntConstant;
import soot.jimple.StringConstant;
import soot.jimple.internal.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.soot.SootUnit.*;

public class SliceOptimizer {
    private final CodeInspector codeInspector;

    public SliceOptimizer() {
        codeInspector = CodeInspector.getInstance();
    }

    public static SliceOptimizer getInstance() {
        return SliceOptimizer.Holder.instance;
    }

    public ArrayList<Unit> getUnreachableUnits(ArrayList<Unit> wholeUnit, ArrayList<Unit> units) {
        HashMap<Value, String> targetValueMap = new HashMap<>();

        return getUnreachableUnits(wholeUnit, units, null, targetValueMap);
    }

    public HashMap<Unit, Unit> getInterpretedUnits(ArrayList<Unit> units, HashMap<Value, Unit> targetValueMap) {
        HashMap<Unit, Unit> updates = new HashMap<>();

        for (Unit u : units) {
            int unitType = getUnitType(u);

            if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                Value leftValue = getLeftValue(u, unitType);
                targetValueMap.put(leftValue, u);
            } else if ((unitType & INVOKE) == INVOKE) {
                Value localValue = getLocalValue(u, unitType);

                String unitStr = u.toString();
                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                if (className.equals("java.lang.String") && methodName.equals("replace")) {
                    if (!targetValueMap.containsKey(localValue)) {
                        continue;
                    }

                    Unit oldUnit = targetValueMap.get(localValue);
                    int oldUnitType = getUnitType(oldUnit);
                    Value rightValue = getRightValue(oldUnit, oldUnitType);
                    String rightValueStr = convertToStr(rightValue);

                    ArrayList<String> paramValues = getParamValues(unitStr);
                    String oldChar = paramValues.get(0);
                    String newChar = paramValues.get(1);

                    String newValueStr = replaceString(rightValueStr, oldChar, newChar);
                    Value newValue = StringConstant.v(newValueStr);
                    Unit newUnit = new JAssignStmt(localValue, newValue);
                    updates.put(oldUnit, newUnit);
                }
            }
        }

        return updates;
    }

    public void updateLines(HashMap<Unit, Unit> updates, ArrayList<JSONObject> content) {
        ProgramSlicer slicer = ProgramSlicer.getInstance();

        Set<Map.Entry<Unit, Unit>> entries = updates.entrySet();
        for (Map.Entry<Unit, Unit> e : entries) {
            Unit oldUnit = e.getKey();
            Unit newUnit = e.getValue();
            JSONObject targetLine = findLine(content, oldUnit.toString());
            if (targetLine == null) {
                continue;
            }

            if (!targetLine.has(CONSTANTS)) {
                continue;
            }

            targetLine.put(UNIT_STRING, newUnit.toString());
            JSONArray constants = targetLine.getJSONArray(CONSTANTS);
            if (constants == null) {
                continue;
            }

            int newUnitType = getUnitType(newUnit);
            constants = slicer.getConstants(newUnit, newUnitType);
            targetLine.put(CONSTANTS, constants);
        }
    }

    public ArrayList<JSONObject> getUnreachableLines(ArrayList<JSONObject> slices) {
        ProgramSlicer slicer = ProgramSlicer.getInstance();
        int slicesSize = slices.size();
        HashMap<Value, String> targetValueMap = new HashMap<>();
        ArrayList<JSONObject> lines = new ArrayList<>();

        for (int i = 0; i < slicesSize; i++) {
            JSONObject slice = slices.get(i);
            String nodeId = slice.getString(NODE_ID);
            String callerName = slice.getString(CALLER_NAME);
            String targetStatement = slice.getString(TARGET_STATEMENT);
            String targetSignature = (i == 0) ? targetStatement : callerName;

            ArrayList<Unit> wholeUnit = codeInspector.getWholeUnit(callerName);
            ArrayList<Unit> units = slicer.getUnits(nodeId);
            ArrayList<Unit> unreachables = getUnreachableUnits(wholeUnit, units, targetSignature, targetValueMap);
            ArrayList<String> unitStrings = new ArrayList<>();
            for (Unit u : unreachables) {
                unitStrings.add(u.toString());
            }

            JSONArray content = slice.getJSONArray(CONTENT);
            for (Object o : content) {
                JSONObject line = (JSONObject) o;
                String unitStr = line.getString(UNIT_STRING);
                if (!unitStrings.contains(unitStr)) {
                    continue;
                }

                lines.add(line);
            }
        }

        return lines;
    }

    public HashMap<Unit, Unit> getInterpretedUnits(ArrayList<JSONObject> slices) {
        ProgramSlicer slicer = ProgramSlicer.getInstance();
        HashMap<Value, Unit> targetValueMap = new HashMap<>();
        HashMap<Unit, Unit> updates = new HashMap<>();

        for (JSONObject l : slices) {
            String nodeId = l.getString(NODE_ID);
            ArrayList<Unit> units = slicer.getUnits(nodeId);
            if (units == null) {
                continue;
            }

            HashMap<Unit, Unit> tempUpdates = getInterpretedUnits(units, targetValueMap);
            updates.putAll(tempUpdates);
        }

        return updates;
    }

    private ArrayList<Unit> getUnreachableUnits(ArrayList<Unit> wholeUnit, ArrayList<Unit> units, String targetSignature, HashMap<Value, String> targetValueMap) {
        int wholeUnitCount = wholeUnit.size();

        ArrayList<Unit> visitedUnits = new ArrayList<>();
        ArrayList<Unit> targetUnits = new ArrayList<>();

        for (int i = 0; i < wholeUnitCount; i++) {
            Unit unit = wholeUnit.get(i);
            if (units != null && !units.contains(unit)) {
                continue;
            }

            int unitType = getUnitType(unit);
            if (unitType == -1) {
                continue;
            }

            if (visitedUnits.contains(unit)) {
                continue;
            } else {
                visitedUnits.add(unit);
            }

            if ((unitType & INVOKE) == INVOKE) {
                String unitStr = unit.toString();
                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                if (className.equals("java.lang.String") && methodName.equals("isEmpty")) {
                    Value localValue = getLocalValue(unit, unitType);
                    String valueStr = targetValueMap.remove(localValue);
                    if (valueStr == null) {
                        continue;
                    }

                    Value leftValue = getLeftValue(unit, unitType);
                    targetValueMap.put(leftValue, String.valueOf(valueStr.equals("\"\"") ? 1 : 0));
                }

                if (targetSignature == null || !targetSignature.equals(signature)) {
                    continue;
                }

                ArrayList<Value> paramValues = getParamValues(unit, unitType);
                for (int j = 0; j < paramValues.size(); j++) {
                    Value value = paramValues.get(j);
                    String valueStr = convertToStr(value);
                    if (valueStr.equals("null")) {
                        continue;
                    }

                    targetValueMap.put(IntConstant.v(j), valueStr);
                }
            } else if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                Value leftValue = getLeftValue(unit, unitType);
                Value rightValue = getRightValue(unit, unitType);
                String rightValueStr = convertToStr(rightValue);

                targetValueMap.put(leftValue, rightValueStr);
            } else if (unitType == ASSIGN_VARIABLE_VARIABLE) {
                Value leftValue = getLeftValue(unit, unitType);
                Value rightValue = getRightValue(unit, unitType);

                targetValueMap.put(rightValue, targetValueMap.remove(leftValue));
            } else if (unitType == PARAMETER) {
                String unitStr = unit.toString();
                String paramNum = getParamNumber(unitStr, unitType);
                int n = Integer.parseInt(paramNum);
                Value v = IntConstant.v(n);
                if (!targetValueMap.containsKey(v)) {
                    continue;
                }

                Value value = getLeftValue(unit, unitType);
                targetValueMap.put(value, targetValueMap.remove(v));
            } else if (unitType == IF) {
                int result = getIfStatementResult(unit, unitType, targetValueMap);
                if (result == -1) {
                    continue;
                }

                Unit targetUnit1 = getTargetUnit(unit, unitType);
                int targetUnitIndex1 = wholeUnit.indexOf(targetUnit1);
                if (targetUnitIndex1 == -1) {
                    continue;
                }

                Unit prevUnit = wholeUnit.get(targetUnitIndex1 - 1);
                int gotoUnitIndex = wholeUnit.indexOf(prevUnit);
                if (result == 1) {
                    for (int j = i + 1; j < gotoUnitIndex; j++) {
                        Unit u = wholeUnit.get(j);
                        targetUnits.add(u);
                    }

                    i = targetUnitIndex1;
                } else {
                    int prevUnitType = getUnitType(prevUnit);
                    Unit targetUnit2 = getTargetUnit(prevUnit, prevUnitType);
                    if (targetUnit2 == null) {
                        continue;
                    }

                    int targetUnitIndex2 = wholeUnit.indexOf(targetUnit2);
                    for (int j = gotoUnitIndex + 1; j <= targetUnitIndex2; j++) {
                        Unit u = wholeUnit.get(j);
                        targetUnits.add(u);
                    }

                    i = targetUnitIndex2;
                }
            }
        }

        return targetUnits;
    }

    private int getIfStatementResult(Unit unit, int unitType, HashMap<Value, String> targetValueMap) {
        Value conditionValue = getConditionValue(unit, unitType);
        if (conditionValue == null) {
            return -1;
        }

        AbstractJimpleIntBinopExpr expr = (AbstractJimpleIntBinopExpr) conditionValue;
        Value leftValue = expr.getOp1();
        if (!targetValueMap.containsKey(leftValue)) {
            return -1;
        }

        Value rightValue = expr.getOp2();
        if (!(rightValue instanceof IntConstant) && !targetValueMap.containsKey(rightValue)) {
            return -1;
        }

        String leftValueStr = targetValueMap.get(leftValue);
        String rightValueStr = targetValueMap.containsKey(rightValue) ? targetValueMap.get(rightValue) : convertToStr(rightValue);
        if (!NumberUtils.isCreatable(leftValueStr) || !NumberUtils.isCreatable(rightValueStr)) {
            return -1;
        }

        int n1 = Integer.parseInt(leftValueStr);
        int n2 = Integer.parseInt(rightValueStr);

        return getIfStatementResult(conditionValue, n1, n2);
    }

    private int getIfStatementResult(Value conditionValue, int n1, int n2) {
        boolean flag;

        if (conditionValue instanceof JGeExpr) {
            flag = (n1 >= n2);
        } else if (conditionValue instanceof JGtExpr) {
            flag = (n1 > n2);
        } else if (conditionValue instanceof JEqExpr) {
            flag = (n1 == n2);
        } else if (conditionValue instanceof JNeExpr) {
            flag = (n1 != n2);
        } else if (conditionValue instanceof JLtExpr) {
            flag = (n1 < n2);
        } else { // conditionValue instanceof JLeExpr
            flag = (n1 <= n2);
        }

        return flag ? 1 : 0;
    }

    private String replaceString(String target, String oldChar, String newChar) {
        target = target.replace("\"", "");
        oldChar = oldChar.replace("\"", "");
        newChar = newChar.replace("\"", "");
        target = target.replace(oldChar, newChar);

        return target;
    }

    private JSONObject findLine(ArrayList<JSONObject> content, String targetUnitStr) {
        if (targetUnitStr == null) {
            return null;
        }

        for (JSONObject l : content) {
            String unitStr = l.getString(UNIT_STRING);
            if (unitStr.contains(targetUnitStr)) {
                return l;
            }
        }

        return null;
    }

    private static class Holder {
        private static final SliceOptimizer instance = new SliceOptimizer();
    }
}