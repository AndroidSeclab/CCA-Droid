package com.ccadroid.inspect;

import com.ccadroid.util.graph.CallGraph;
import com.ccadroid.util.soot.Soot;
import com.ccadroid.util.soot.SootUnit;
import org.graphstream.graph.Node;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JAssignStmt;
import soot.tagkit.ConstantValueTag;
import soot.tagkit.Tag;
import soot.util.Chain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static com.ccadroid.util.graph.BaseGraph.EdgeType.*;
import static com.ccadroid.util.soot.SootUnit.*;

public class CodeInspector {
    private final CallGraph callGraph;
    private final HashMap<String, Value> constantValueMap;
    private final HashMap<String, HashMap<Integer, ArrayList<Unit>>> targetUnitsMap;
    private final HashMap<String, ArrayList<Unit>> wholeUnitMap;

    private CodeInspector() {
        callGraph = new CallGraph();

        constantValueMap = new HashMap<>();
        targetUnitsMap = new HashMap<>();
        wholeUnitMap = new HashMap<>();
    }

    public static CodeInspector getInstance() {
        return CodeInspector.Holder.instance;
    }

    public void buildCallGraph() {
        ApkParser apkParser = ApkParser.getInstance();
        ArrayList<String> dexClassNames = apkParser.getDexClassNames();
        for (String name : dexClassNames) {
            if (name.startsWith("dalvik") || name.startsWith("android") || name.startsWith("kotlin") || name.startsWith("io.flutter") || name.startsWith("scala")) {
                continue;
            }

            SootClass sootClass = Soot.getSootClass(name);
            List<SootMethod> sootMethods = sootClass.getMethods();
            ArrayList<SootMethod> tempMethods = new ArrayList<>(sootMethods);
            for (SootMethod m : tempMethods) {
                if (!m.isConcrete()) {
                    continue;
                }

                boolean isStaticInitializer = m.isStaticInitializer();
                if (isStaticInitializer) { // for only static initializer
                    parseStaticFinalValue(sootClass);
                }

                try {
                    String callerName = m.toString();
                    Node caller = callGraph.addNode(callerName, callerName);

                    HashMap<Integer, ArrayList<Unit>> map = new HashMap<>();

                    Body body = m.retrieveActiveBody();
                    UnitPatchingChain chain = body.getUnits();
                    ArrayList<Unit> units = new ArrayList<>(chain);
                    for (Unit u : units) {
                        int unitType = getUnitType(u);
                        switch (unitType) {
                            case VIRTUAL_INVOKE:
                            case STATIC_INVOKE:
                            case INTERFACE_INVOKE:
                            case SPECIAL_INVOKE:
                            case ASSIGN_VIRTUAL_INVOKE:
                            case ASSIGN_STATIC_INVOKE:
                            case ASSIGN_INTERFACE_INVOKE:
                            case ASSIGN_SPECIAL_INVOKE: {
                                String calleeName = getSignature(u);
                                Node callee = callGraph.addNode(calleeName, calleeName);
                                callGraph.addEdge(caller, callee, DOWNWARD);
                                break;
                            }

                            case ASSIGN_SIGNATURE_CONSTANT: {
                                String signature = getSignature(u);
                                Value value = constantValueMap.get(signature);
                                if (value == null) {
                                    value = getRightValue(u, unitType);
                                    constantValueMap.put(signature, value);
                                }

                                break;
                            }

                            case ASSIGN_VARIABLE_SIGNATURE:
                            case ASSIGN_SIGNATURE_VARIABLE: {
                                String signature = getSignature(u);
                                String className = getClassName(signature);
                                if (!dexClassNames.contains(className)) {
                                    break;
                                }

                                Node callee = callGraph.addNode(signature, signature);
                                if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                                    Value rightValue = constantValueMap.get(signature);
                                    if (rightValue == null) {
                                        callGraph.addEdge(caller, callee, READ);
                                    } else {
                                        Value leftValue = getLeftValue(u, unitType);

                                        int index = units.indexOf(u);
                                        Unit newUnit = new JAssignStmt(leftValue, rightValue);
                                        units.set(index, newUnit);
                                    }
                                } else {
                                    callGraph.addEdge(caller, callee, WRITE);
                                }

                                break;
                            }

                            case SWITCH: {
                                int index = units.size() - units.indexOf(u) - 1;
                                ArrayList<Unit> tempTargetUnits = SootUnit.getTargetUnits(u, unitType);
                                ArrayList<Unit> targetUnits = new ArrayList<>(tempTargetUnits);

                                map.put(index, targetUnits);
                                break;
                            }

                            default: {
                                break;
                            }
                        }

                        if (!map.isEmpty()) {
                            targetUnitsMap.put(callerName, map);
                        }
                    }

                    ArrayList<Unit> wholeUnit = new ArrayList<>(units);
                    wholeUnitMap.put(callerName, wholeUnit);
                } catch (RuntimeException | StackOverflowError | OutOfMemoryError ignored) { // for Soot internal error

                }
            }
        }
    }

    public Node getNode(String signature) {
        return callGraph.getNode(signature);
    }

    public ArrayList<ArrayList<String>> traverseCallers(String signature, boolean upper) {
        return callGraph.getListOfIds(signature, upper);
    }

    public HashMap<Integer, ArrayList<Unit>> getTargetUnitsMap(String callerName) {
        return targetUnitsMap.get(callerName);
    }

    public ArrayList<Unit> getWholeUnit(String signature) {
        return wholeUnitMap.get(signature);
    }

    public boolean isLoopStatement(Unit unit, int unitType, ArrayList<Unit> reversedUnits) {
        Unit targetUnit = getTargetUnit(unit, unitType);

        if (unitType == IF) {
            int targetUnitIndex = reversedUnits.indexOf(targetUnit);
            int prevUnitIndex = targetUnitIndex + 1;
            if (prevUnitIndex == reversedUnits.size()) {
                return false;
            }

            Unit prevUnit = reversedUnits.get(prevUnitIndex);
            int prevUnitType = getUnitType(prevUnit);
            if (prevUnitType == GOTO) {
                targetUnit = getTargetUnit(prevUnit, prevUnitType);
            }

            return (unit == targetUnit);
        } else {
            int targetUnitType = getUnitType(targetUnit);
            Unit tempUnit = getTargetUnit(targetUnit, targetUnitType);
            int tempUnitIndex = reversedUnits.indexOf(tempUnit);
            Unit prevUnit = reversedUnits.get(tempUnitIndex + 1);

            return (unit == prevUnit);
        }
    }

    private void parseStaticFinalValue(SootClass sootClass) {
        Chain<SootField> fields = sootClass.getFields();
        for (SootField f : fields) {
            if (!f.isStatic() || !f.isFinal()) {
                continue;
            }

            List<Tag> tags = f.getTags();
            if (tags.isEmpty()) {
                continue;
            }

            Tag tag = tags.get(0);
            if (!(tag instanceof ConstantValueTag)) {
                continue;
            }

            String key = f.getSignature();
            Value value;

            String tagStr = tag.toString();
            String[] strArr = tagStr.split("ConstantValue: ");
            int length = strArr.length;
            if (length > 1) {
                String returnType = getReturnType(key);
                value = convertToValue(returnType, strArr[1]);
            } else {
                value = StringConstant.v("");
            }

            constantValueMap.putIfAbsent(key, value);
        }
    }

    private Value convertToValue(String returnType, String valueStr) {
        if (valueStr.equals("null")) {
            return NullConstant.v();
        }

        Value value = null;
        switch (returnType) {
            case "boolean":
            case "short":
            case "int": {
                value = IntConstant.v(Integer.parseInt(valueStr));
                break;
            }

            case "double": {
                if (valueStr.contains("NaN")) {
                    value = DoubleConstant.v(Double.NaN);
                } else if (valueStr.contains("Infinity")) {
                    value = (valueStr.contains("-")) ? DoubleConstant.v(Double.NEGATIVE_INFINITY) : DoubleConstant.v(Double.POSITIVE_INFINITY);
                } else {
                    value = DoubleConstant.v(Double.parseDouble(valueStr));
                }

                break;
            }

            case "long": {
                valueStr = valueStr.replace("L", "");
                value = LongConstant.v(Long.parseLong(valueStr));
                break;
            }

            case "float": {
                valueStr = valueStr.replace("F", "");
                if (valueStr.contains("NaN")) {
                    value = FloatConstant.v(Float.NaN);
                } else if (valueStr.contains("Infinity")) {
                    value = (valueStr.contains("-")) ? FloatConstant.v(Float.NEGATIVE_INFINITY) : FloatConstant.v(Float.POSITIVE_INFINITY);
                } else {
                    value = FloatConstant.v(Float.parseFloat(valueStr));
                }

                break;
            }

            case "char":
            case "byte":
            case "java.lang.String": {
                valueStr = valueStr.replace("\"", "");
                value = StringConstant.v(valueStr);
                break;
            }

            default: {
                break;
            }
        }

        return value;
    }

    private static class Holder {
        private static final CodeInspector instance = new CodeInspector();
    }
}