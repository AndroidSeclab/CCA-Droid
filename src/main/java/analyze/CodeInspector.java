package analyze;

import graph.CallGraph;
import org.graphstream.graph.Node;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JLookupSwitchStmt;
import soot.tagkit.ConstantValueTag;
import soot.tagkit.Tag;
import soot.util.Chain;
import utils.SootUnit;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static graph.BaseGraph.EdgeType.*;
import static java.lang.Double.parseDouble;
import static java.lang.Float.parseFloat;
import static java.lang.Integer.parseInt;
import static java.lang.Long.parseLong;
import static java.util.regex.Pattern.compile;
import static utils.SootUnit.*;

public class CodeInspector {
    private final CallGraph callGraph;
    private final HashMap<String, SootMethod> sootMethodMap;
    private final HashMap<String, Value> constantValueMap;
    private final HashMap<Unit, Unit> targetUnitMap;
    private final HashMap<String, HashMap<Integer, ArrayList<Unit>>> switchTargetUnitsMap;

    private CodeInspector() {
        sootMethodMap = new HashMap<>();
        callGraph = new CallGraph();
        constantValueMap = new HashMap<>();
        targetUnitMap = new HashMap<>();
        switchTargetUnitsMap = new HashMap<>();
    }

    public static CodeInspector getInstance() {
        return CodeInspector.Holder.instance;
    }

    public void buildCallGraph() {
        ApkParser apkParser = ApkParser.getInstance();
        ArrayList<String> targetClassNames = apkParser.getDexClassNames();
        String excludeRegex = "^(dalvik|android|kotlin|io.flutter|scala).*$";
        Pattern pattern = compile(excludeRegex);
        HashSet<String> removedSignatures = new HashSet<>();

        for (String name : targetClassNames) {
            Matcher matcher = pattern.matcher(name);
            if (matcher.matches()) {
                continue;
            }

            SootClass sootClass = Scene.v().getSootClass(name);
            List<SootMethod> sootMethods = sootClass.getMethods();
            ArrayList<SootMethod> tempMethods = new ArrayList<>(sootMethods); // avoid java.util.ConcurrentModificationException
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
                    sootMethodMap.put(callerName, m);

                    Node caller = callGraph.addNode(callerName, callerName, null);
                    Body body = m.retrieveActiveBody();
                    UnitPatchingChain chain = body.getUnits();
                    ArrayList<Unit> units = new ArrayList<>(chain);
                    HashMap<Integer, ArrayList<Unit>> map = new HashMap<>();
                    for (Unit u : units) {
                        int unitType = getUnitType(u);
                        if (unitType == -1) {
                            continue;
                        }

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
                                Node callee = callGraph.addNode(calleeName, calleeName, null);
                                callGraph.addEdge(caller, callee, DOWNWARD);
                                break;
                            }

                            case ASSIGN_SIGNATURE_CONSTANT: {
                                String signature = getSignature(u);
                                if (removedSignatures.contains(signature)) {
                                    break;
                                }

                                if (!constantValueMap.containsKey(signature)) {
                                    String valueStr = getRightValueStr(u, unitType);
                                    valueStr = valueStr.replace("\"", "");
                                    Value value = convertStringToValue(signature, valueStr);
                                    constantValueMap.put(signature, value);
                                } else {
                                    String valueStr1 = getRightValueStr(u, unitType);
                                    valueStr1 = valueStr1.replace("\"", "");

                                    Value value = constantValueMap.get(signature);
                                    String valueStr2 = value.toString();
                                    if (!valueStr1.equals(valueStr2)) {
                                        constantValueMap.remove(signature);
                                        removedSignatures.add(signature);
                                    }
                                }

                                break;
                            }

                            case ASSIGN_VARIABLE_SIGNATURE:
                            case ASSIGN_SIGNATURE_VARIABLE: {
                                String signature = getSignature(u);
                                String className = getClassName(signature);
                                if (!targetClassNames.contains(className)) {
                                    break;
                                }

                                Node callee = callGraph.addNode(signature, signature, null);
                                if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                                    callGraph.addEdge(caller, callee, READ);
                                } else {
                                    callGraph.addEdge(caller, callee, WRITE);
                                }

                                break;
                            }

                            case GOTO: {
                                Unit targetUnit = SootUnit.getTargetUnit(u);
                                targetUnitMap.put(targetUnit, u);
                                break;
                            }

                            case SWITCH: {
                                int index = units.indexOf(u);
                                List<Unit> list = ((JLookupSwitchStmt) u).getTargets();
                                ArrayList<Unit> targets = new ArrayList<>(list);

                                map.put(index, targets);
                                break;
                            }
                        }

                        switchTargetUnitsMap.put(callerName, map);
                    }
                } catch (RuntimeException | StackOverflowError | OutOfMemoryError ignored) { // for Soot internal error

                }
            }
        }
    }

    public Node getNode(String signature) {
        return callGraph.getNode(signature);
    }

    public SootMethod getSootMethod(String signature) {
        return sootMethodMap.get(signature);
    }

    public Value getConstantValue(String signature) {
        return constantValueMap.get(signature);
    }

    public Unit getTargetUnit(Unit unit) {
        return targetUnitMap.get(unit);
    }

    public HashMap<Integer, ArrayList<Unit>> getSwitchTargetUnits(String callerName) {
        return switchTargetUnitsMap.get(callerName);
    }

    public ArrayList<ArrayList<String>> traverseCallers(String signature, boolean upper) {
        return callGraph.getListOfIds(signature, upper);
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
            String tagStr = tag.toString();
            String[] strArr = tagStr.split("ConstantValue: ");
            int length = strArr.length;
            if (length > 1) {
                Value value = convertStringToValue(key, strArr[1]);
                constantValueMap.putIfAbsent(key, value);
            } else {
                constantValueMap.putIfAbsent(key, StringConstant.v("")); // this is <className: String variableName> = ""
            }
        }
    }

    private Value convertStringToValue(String signature, String valueStr) {
        if (valueStr.equals("null")) {
            return NullConstant.v();
        }

        Value value;
        String returnType = getReturnType(signature);
        switch (returnType) {
            case "boolean":
            case "short":
            case "int": {
                value = IntConstant.v(parseInt(valueStr));
                break;
            }

            case "double": {
                if (valueStr.contains("NaN")) {
                    value = DoubleConstant.v(Double.NaN);
                } else if (valueStr.contains("Infinity")) {
                    value = (valueStr.contains("-")) ? DoubleConstant.v(Double.NEGATIVE_INFINITY) : DoubleConstant.v(Double.POSITIVE_INFINITY);
                } else {
                    value = DoubleConstant.v(parseDouble(valueStr));
                }

                break;
            }

            case "long": {
                valueStr = valueStr.replace("L", "");
                value = LongConstant.v(parseLong(valueStr));
                break;
            }

            case "float": {
                valueStr = valueStr.replace("F", "");
                if (valueStr.contains("NaN")) {
                    value = FloatConstant.v(Float.NaN);
                } else if (valueStr.contains("Infinity")) {
                    value = (valueStr.contains("-")) ? FloatConstant.v(Float.NEGATIVE_INFINITY) : FloatConstant.v(Float.POSITIVE_INFINITY);
                } else {
                    value = FloatConstant.v(parseFloat(valueStr));
                }

                break;
            }

            default: { // char, byte, java.lang.String
                valueStr = valueStr.replace("\"", "");
                value = StringConstant.v(valueStr);
                break;
            }
        }

        return value;
    }

    private static class Holder {
        private static final CodeInspector instance = new CodeInspector();
    }
}