package com.ccadroid.inspect;

import com.ccadroid.util.graph.CallGraph;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static com.ccadroid.util.soot.Soot.*;
import static com.ccadroid.util.soot.SootUnit.*;

public class CodeInspector {
    private static final ApkParser apkParser;

    static {
        apkParser = ApkParser.getInstance();
    }

    private final CallGraph callGraph;
    private final HashMap<String, Value> constantValueMap;
    private final HashMap<Unit, Unit> switchTargetUnitMap;

    private CodeInspector() {
        callGraph = new CallGraph();
        constantValueMap = new HashMap<>();
        switchTargetUnitMap = new HashMap<>();
    }

    public static CodeInspector getInstance() {
        return SingletonHolder.instance;
    }

    public void buildCallGraph() {
        ArrayList<String> dexClassNames = apkParser.getDexClassNames();

        for (String dexClassName : dexClassNames) {
            SootClass sootClass = getSootClass(dexClassName);
            List<SootMethod> sootMethods = sootClass.getMethods();
            ArrayList<SootMethod> tempMethods = new ArrayList<>(sootMethods);

            for (SootMethod m : tempMethods) {
                String callerName = m.toString();
                Node caller = addNode(callerName, callerName);
                boolean isConcrete = m.isConcrete();
                callGraph.setConcrete(caller, isConcrete);

                if (apkParser.isBuiltInClassName(dexClassName)) {
                    continue;
                }

                if (!isConcrete) {
                    continue;
                }

                boolean isStaticInitializer = m.isStaticInitializer();
                if (isStaticInitializer) { // for only static initializer
                    HashMap<String, Value> map = getStaticFinalValueMap(sootClass);
                    map.forEach(constantValueMap::putIfAbsent);
                }

                try {
                    String subSignature = m.getSubSignature();
                    String interfaceMethodName = getInterfaceMethodName(dexClassName, subSignature);
                    if (interfaceMethodName != null) {
                        callGraph.setInterfaceName(caller, interfaceMethodName);
                    }

                    ArrayList<Unit> wholeUnit = getUnits(m);

                    for (Unit u : wholeUnit) {
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
                                Node callee = addNode(calleeName, calleeName);
                                addEdge(caller, callee, true);
                                break;
                            }

                            case ASSIGN_SIGNATURE_CONSTANT: {
                                String signature = getSignature(u);
                                Value rightOp = getRightOp(u, unitType);
                                Value constant = constantValueMap.get(signature);
                                if (constantValueMap.containsKey(signature)) {
                                    if (rightOp != null && !rightOp.toString().equals(constant.toString())) {
                                        constantValueMap.remove(signature);
                                    }
                                } else {
                                    constantValueMap.put(signature, rightOp);
                                }

                                break;
                            }

                            case ASSIGN_VARIABLE_SIGNATURE: {
                                String signature = getSignature(u);
                                String className = getClassName(signature);
                                if (!dexClassNames.contains(className)) {
                                    break;
                                }

                                Value constant = constantValueMap.get(signature);
                                if (constant == null) {
                                    Node memberVar = addNode(signature, signature);
                                    addEdge(caller, memberVar, false);
                                } else {
                                    Value leftOp = getLeftOp(u, unitType);
                                    setAssignUnit(u, leftOp, constant);
                                }

                                break;
                            }

                            case ASSIGN_SIGNATURE_VARIABLE: {
                                String signature = getSignature(u);
                                String className = getClassName(signature);
                                if (!dexClassNames.contains(className)) {
                                    break;
                                }

                                Node memberVar = addNode(signature, signature);
                                addEdge(caller, memberVar, false);
                                break;
                            }

                            case SWITCH: {
                                ArrayList<Unit> targetUnits = getSwitchTargetUnits(u, unitType);
                                targetUnits.forEach(unit -> switchTargetUnitMap.put(unit, u));
                                break;
                            }

                            default: {
                                break;
                            }
                        }
                    }
                } catch (RuntimeException | StackOverflowError | OutOfMemoryError ignored) { // for Soot internal error

                }
            }
        }
    }

    public Node getNode(String signature) {
        return callGraph.getNode(signature);
    }

    public Node getInterfaceNode(Node node) {
        return node.getAttribute(CallGraph.INTERFACE_NAME) == null ? null : getNode(callGraph.getInterfaceName(node));
    }

    public List<Edge> getEdges(Node node) {
        return callGraph.getEdges(node);
    }

    public Unit getSwitchUnit(Unit unit) {
        return switchTargetUnitMap.getOrDefault(unit, null);
    }

    public ArrayList<Unit> getWholeUnit(String callerName) {
        return getUnits(callerName);
    }

    public ArrayList<ArrayList<String>> traverseCallers(String signature) {
        return callGraph.getListOfIds(signature);
    }

    private Node addNode(String id, String label) {
        return callGraph.addNode(id, label);
    }

    private void addEdge(Node node1, Node node2, boolean isDirected) {
        callGraph.addEdge(node1, node2, isDirected);
    }

    private static class SingletonHolder {
        private static final CodeInspector instance = new CodeInspector();
    }
}