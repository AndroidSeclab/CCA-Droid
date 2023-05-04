package slice;

import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.internal.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static java.lang.Integer.parseInt;
import static java.lang.String.valueOf;
import static utils.Soot.isSuperClassOf;
import static utils.SootUnit.*;

public class SliceOptimizer {

    public static SliceOptimizer getInstance() {
        return SliceOptimizer.Holder.instance;
    }

    public ArrayList<Unit> findInfeasibleUnits(HashMap<String, ArrayList<Unit>> targetUnitsMap) {
        ArrayList<Unit> infeasibleUnits = new ArrayList<>();
        HashMap<String, String> targetValueMap = new HashMap<>();

        int index = 0;
        Set<Map.Entry<String, ArrayList<Unit>>> entries = targetUnitsMap.entrySet();
        int entrySize = entries.size();

        for (Map.Entry<String, ArrayList<Unit>> e : entries) {
            String signature = e.getKey();
            ArrayList<Unit> targetUnits = e.getValue();

            index++;
            if (index < entrySize) {
                updateTargetValueMap(targetValueMap, targetUnits);
            }

            ArrayList<Unit> tempUnits = findInfeasibleUnits(signature, targetUnits, targetValueMap);
            infeasibleUnits.addAll(tempUnits);
        }

        return infeasibleUnits;
    }

    public ArrayList<Unit> findInfeasibleUnits(String signature, ArrayList<Unit> targetUnits, ArrayList<String> targetParamValues) {
        if (targetParamValues == null) {
            return new ArrayList<>();
        }

        HashMap<String, String> paramValueMap = new HashMap<>();
        int targetParamValueCount = targetParamValues.size();
        for (int i = 0; i < targetParamValueCount; i++) {
            String targetParamValue = targetParamValues.get(i);
            paramValueMap.put(valueOf(i), targetParamValue);
        }

        return findInfeasibleUnits(signature, targetUnits, paramValueMap);
    }

    public ArrayList<Unit> findInfeasibleUnits(String signature, ArrayList<Unit> targetUnits, HashMap<String, String> targetValueMap) {
        ArrayList<Unit> wholeUnits = getWholeUnits(signature);
        ArrayList<Unit> infeasibleUnits = new ArrayList<>();

        for (Unit u : targetUnits) {
            int unitType = getUnitType(u);

            if (unitType == PARAMETER) {
                String leftValueStr = getLeftValueStr(u, unitType);
                String paramNum = getParamNum(u);
                String value = targetValueMap.remove(paramNum);
                if (value == null) {
                    continue;
                }

                targetValueMap.put(leftValueStr, value);
            }
            if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                String leftValue = getLeftValueStr(u, unitType);
                String rightValue = getRightValueStr(u, unitType);

                targetValueMap.put(leftValue, rightValue);
            } else if (unitType == INSTANCE_OF) {
                String leftValueStr = getLeftValueStr(u, unitType);
                Value rightValue = getRightValue(u, unitType);

                JInstanceOfExpr expr = (JInstanceOfExpr) rightValue;
                ValueBox opBox = expr.getOpBox();
                Value op = opBox.getValue();
                String targetVariable = op.toString();
                String targetSignature = targetValueMap.get(targetVariable);
                if (targetSignature == null) {
                    continue;
                }

                Type checkType = expr.getCheckType();
                String typeStr = checkType.toString();

                targetValueMap.put(leftValueStr, isSuperClassOf(targetSignature, typeStr) ? "1" : "0");
            } else if (unitType == IF) {
                int result = getIfStatementResult(u, targetValueMap);
                if (result == -1) {
                    continue;
                }

                int unitIndex = wholeUnits.indexOf(u);
                Unit targetUnit = getTargetUnit(u);
                int targetUnitIndex = wholeUnits.indexOf(targetUnit);

                int startTargetUnitIndex = -1;
                int endTargetUnitIndex = -1;
                boolean flag = result == 1;
                if (flag) {
                    startTargetUnitIndex = unitIndex;
                    endTargetUnitIndex = targetUnitIndex - 2;
                } else {
                    int tempUnitIndex1 = targetUnitIndex - 1;
                    Unit tempUnit1 = wholeUnits.get(tempUnitIndex1);
                    boolean isGoto = (getUnitType(tempUnit1) == GOTO);
                    if (isGoto) {
                        Unit tempUnit2 = getTargetUnit(tempUnit1);
                        int tempUnitIndex2 = wholeUnits.indexOf(tempUnit2);
                        if (tempUnitIndex2 < tempUnitIndex1) {
                            continue;
                        }

                        startTargetUnitIndex = tempUnitIndex1;
                        endTargetUnitIndex = tempUnitIndex2;
                    }
                }

                if (startTargetUnitIndex > 0 && endTargetUnitIndex > 0) {
                    for (int j = startTargetUnitIndex; j < endTargetUnitIndex; j++) {
                        infeasibleUnits.add(wholeUnits.get(j));
                    }
                }
            }
        }

        return infeasibleUnits;
    }

    private int getIfStatementResult(Unit unit, HashMap<String, String> targetValueMap) {
        JIfStmt stmt = (JIfStmt) unit;
        ValueBox conditionBox = stmt.getConditionBox();
        Value conditionValue = conditionBox.getValue();

        AbstractJimpleIntBinopExpr expr = (AbstractJimpleIntBinopExpr) conditionValue;
        ValueBox op1Box = expr.getOp1Box();
        Value op1 = op1Box.getValue();
        String op1Str = op1.toString();
        String leftValue = targetValueMap.get(op1Str);
        if (leftValue == null || (leftValue != null && isVariableStr(leftValue))) {
            return -1;
        }

        ValueBox op2Box = expr.getOp2Box();
        Value op2 = op2Box.getValue();
        String op2Str = op2.toString();
        String rightValue = (isVariableStr(op2Str)) ? targetValueMap.get(op2Str) : op2Str;
        if (rightValue == null || (rightValue != null && isVariableStr(rightValue))) {
            return -1;
        }

        int n1 = convertStringToInt(leftValue);
        int n2 = convertStringToInt(rightValue);

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

    private void updateTargetValueMap(HashMap<String, String> targetValueMap, ArrayList<Unit> targetUnits) {
        Unit lastUnit = targetUnits.get(targetUnits.size() - 1);
        ArrayList<String> paramValues = getParamValues(lastUnit);

        int size = paramValues.size();
        for (int j = 0; j < size; j++) {
            String key = paramValues.get(j);
            String value = (isVariableStr(key)) ? targetValueMap.remove(key) : key;

            targetValueMap.put(String.valueOf(j), value);
        }
    }

    private int convertStringToInt(String value) {
        if (value.equals("null")) {
            return 0;
        }

        try {
            return parseInt(value);
        } catch (NumberFormatException ignored) {
            return 1; // present this value is not null
        }
    }

    private static class Holder {
        private static final SliceOptimizer instance = new SliceOptimizer();
    }
}