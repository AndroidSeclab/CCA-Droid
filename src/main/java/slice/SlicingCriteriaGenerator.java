package slice;

import analyze.ApkParser;
import analyze.CodeInspector;
import model.SlicingCriterion;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import soot.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.lang.Integer.parseInt;
import static java.util.Collections.reverse;
import static java.util.regex.Pattern.compile;
import static java.util.stream.Collectors.toList;
import static utils.SootUnit.*;

public class SlicingCriteriaGenerator {
    private final ApkParser apkParser;
    private final CodeInspector codeInspector;
    private final HashMap<String, ArrayList<ArrayList<String>>> listOfCallersMap;
    private final HashMap<String, SlicingCriterion> slicingCriterionMap;
    private int criteriaCount;

    private SlicingCriteriaGenerator() {
        apkParser = ApkParser.getInstance();
        codeInspector = CodeInspector.getInstance();
        listOfCallersMap = new HashMap<>();
        slicingCriterionMap = new HashMap<>();

        criteriaCount = 0;
    }

    public static SlicingCriteriaGenerator getInstance() {
        return SlicingCriteriaGenerator.Holder.instance;
    }

    public ArrayList<SlicingCriterion> createSlicingCriteria(ArrayList<SlicingCriterion> candidates) {
        ArrayList<SlicingCriterion> slicingCriteria = new ArrayList<>();

        String packageName = apkParser.getPackageName();
        String applicationClassName = apkParser.getApplicationClassName();
        ArrayList<String> components = apkParser.getAndroidComponents();

        for (SlicingCriterion sc : candidates) {
            String targetStatement1 = sc.getTargetStatement1();
            if (!isCorrectSignature(targetStatement1)) {
                continue;
            }

            Node callee = codeInspector.getNode(targetStatement1);
            if (callee == null) {
                continue;
            }

            String targetStatement2 = sc.getTargetStatement2();
            ArrayList<String> targetParamNums = sc.getTargetParamNums();

            Stream<Edge> stream = callee.edges();
            List<Edge> edges = stream.collect(toList());
            for (Edge e : edges) {
                Node caller = e.getSourceNode();
                String callerName = caller.getId();
                ArrayList<ArrayList<String>> listOfCallers = listOfCallersMap.get(callerName);
                if (listOfCallers == null) {
                    listOfCallers = codeInspector.traverseCallers(callerName, true);
                    removeUnReachableCallerList(packageName, applicationClassName, components, listOfCallers);

                    listOfCallersMap.put(callerName, listOfCallers);
                }

                if (listOfCallers.isEmpty()) {
                    continue;
                }

                HashSet<String> callerNames = new HashSet<>();
                for (ArrayList<String> l : listOfCallers) {
                    callerNames.addAll(l);
                }

                ArrayList<SlicingCriterion> criteria = createSlicingCriteria(callerName, targetStatement1, targetStatement2, INVOKE, targetParamNums, null);
                for (SlicingCriterion c : criteria) {
                    c.setCallerNames(callerNames);
                    slicingCriteria.add(c);
                }
            }
        }

        criteriaCount += slicingCriteria.size();

        return slicingCriteria;
    }

    public ArrayList<SlicingCriterion> createSlicingCriteria(String callerName, String targetStatement1, String targetStatement2, int targetUnitType, ArrayList<String> targetParamNums, ArrayList<String> targetParamValues) {
        String returnType = null;
        ArrayList<String> targetClassNames = apkParser.getDexClassNames();
        if (targetUnitType == ASSIGN) {
            returnType = getReturnType(targetStatement1);
            SootClass sootClass = Scene.v().getSootClass(returnType);
            if (targetClassNames.contains(returnType) && !sootClass.isEnum()) {
                return new ArrayList<>();
            }
        } else if (targetUnitType == RETURN_VALUE) {
            returnType = getReturnType(callerName);
            if (targetClassNames.contains(returnType)) {
                return new ArrayList<>();
            }
        }

        ArrayList<String> excludeReturnTypes = new ArrayList<>();
        excludeReturnTypes.add("boolean");
        excludeReturnTypes.add("java.util.List");
        excludeReturnTypes.add("java.security.KeyPair");
        excludeReturnTypes.add("java.security.KeyStore");
        excludeReturnTypes.add("android.content.SharedPreferences");
        if (excludeReturnTypes.contains(returnType)) {
            return new ArrayList<>();
        }

        Node caller = codeInspector.getNode(callerName);
        if (caller == null) {
            return new ArrayList<>();
        }

        SootMethod sootMethod = codeInspector.getSootMethod(callerName); // avoid built-in library
        if (sootMethod == null) {
            return new ArrayList<>();
        }

        ArrayList<SlicingCriterion> slicingCriteria = new ArrayList<>();
        Body body = sootMethod.retrieveActiveBody();
        UnitPatchingChain unitChain = body.getUnits();
        ArrayList<Unit> wholeUnits = new ArrayList<>(unitChain);
        ArrayList<Unit> partialUnits = new ArrayList<>();
        reverse(wholeUnits);

        HashMap<Integer, ArrayList<Unit>> switchTargetsMap = codeInspector.getSwitchTargetUnits(callerName);
        Unit gotoUnit = null;
        ArrayList<Unit> targetGotoUnits = new ArrayList<>();

        int wholeUnitsSize = wholeUnits.size();
        for (int i = 0; i < wholeUnitsSize; i++) {
            Unit unit = wholeUnits.get(i);
            int unitType = getUnitType(unit);
            if (gotoUnit == null) {
                gotoUnit = codeInspector.getTargetUnit(unit);
            }

            String unitStr = unit.toString();
            if ((!(unitStr.contains(targetStatement1)) && targetStatement2 == null) || (targetStatement2 != null && !unitStr.contains(targetStatement2))) {
                continue;
            }

            boolean isAssign = (targetUnitType == ASSIGN && (unitType == ASSIGN_SIGNATURE_VARIABLE));
            boolean isInvoke = (targetUnitType == INVOKE && (unitType & INVOKE) == INVOKE);
            boolean isReturn = (targetUnitType == RETURN_VALUE && unitType == RETURN_VALUE);
            if (!isAssign && !isInvoke && !isReturn) {
                continue;
            }

            ArrayList<String> targetVariables = new ArrayList<>();

            switch (unitType) {
                case ASSIGN_SIGNATURE_VARIABLE: { // <className: returnType methodName()> = $r1
                    String valueStr = getRightValueStr(unit, unitType);
                    if (isVariableStr(valueStr)) {
                        targetVariables.add(valueStr);
                    }

                    Unit nextUnit = wholeUnits.get(i + 1);
                    int nextUnitType = getUnitType(nextUnit);
                    if (nextUnitType != ASSIGN_ARRAY_CONSTANT) {
                        break;
                    }

                    String index = getArrayIndex(nextUnit);
                    if (isVariableStr(index)) { // Using control-flow graph makes low performance
                        break;
                    }

                    int arraySize = parseInt(index) + 1;
                    int j = i + arraySize;
                    if (j > wholeUnitsSize) {
                        break;
                    }

                    for (int k = i; k < (i + arraySize); k++) {
                        partialUnits.add(wholeUnits.get(k));
                    }

                    Unit lastUnit = wholeUnits.get(j);
                    partialUnits.add(lastUnit);

                    int lastUnitType = getUnitType(lastUnit);
                    if (lastUnitType == ASSIGN_ARRAY_CONSTANT) {
                        partialUnits.add(wholeUnits.get(j + 1));
                    }

                    break;
                }

                case RETURN_VALUE: {
                    String valueStr = getRightValueStr(unit, unitType);
                    targetVariables.add(valueStr);
                    break;
                }

                case ASSIGN_VIRTUAL_INVOKE:
                case ASSIGN_STATIC_INVOKE:
                case ASSIGN_SPECIAL_INVOKE:
                case VIRTUAL_INVOKE:
                case STATIC_INVOKE:
                case SPECIAL_INVOKE: {
                    String signature = getSignature(unitStr);
                    ArrayList<String> paramTypes = getParamTypes(signature);
                    ArrayList<String> paramValues = getParamValues(unitStr);
                    if (targetParamNums.isEmpty() && !paramValues.isEmpty()) {
                        continue;
                    }

                    String localVariable = getLocalVariable(unit);
                    if (targetParamNums.contains("-1") && isStackVariable(localVariable)) {
                        targetVariables.add(localVariable);
                    }

                    String excludeRegex = "^(dalvik|android|kotlin|io.flutter|scala).*$";
                    Pattern pattern = compile(excludeRegex);
                    ArrayList<String> tempParamNums = new ArrayList<>(targetParamNums);
                    for (String j : tempParamNums) { // for multiple paramNums
                        if (j.equals("-1")) {
                            continue;
                        }

                        int k = parseInt(j);
                        String type = paramTypes.get(k);
                        if (targetClassNames.contains(type)) {
                            continue;
                        }

                        Matcher matcher = pattern.matcher(type);
                        if (matcher.matches()) {
                            continue;
                        }

                        String variable = paramValues.get(k);
                        targetVariables.add(variable);
                    }

                    if (targetVariables.isEmpty()) {
                        continue;
                    }

                    break;
                }
            }

            if (partialUnits.isEmpty()) {
                partialUnits.addAll(wholeUnits);
            }

            if (gotoUnit != null) {
                targetGotoUnits.add(gotoUnit);
            }

            SlicingCriterion slicingCriterion = new SlicingCriterion();
            slicingCriterion.setCaller(caller);
            slicingCriterion.setTargetStatement1(targetStatement1);
            slicingCriterion.setTargetStatement2(targetStatement2);
            slicingCriterion.setTargetParamNums(targetParamNums);
            slicingCriterion.setTargetUnitIndex(i);
            slicingCriterion.setTargetVariables(new ArrayList<>(targetVariables));
            slicingCriterion.setWholeUnits(wholeUnits);
            slicingCriterion.setPartialUnits(partialUnits);
            slicingCriterion.setSwitchTargetsMap(switchTargetsMap);
            slicingCriterion.setTargetGotoUnits(targetGotoUnits);
            slicingCriterion.setTargetParamValues(targetParamValues);
            if (slicingCriteria.contains(slicingCriterion)) {
                continue;
            }

            String hashCode = String.valueOf(slicingCriterion.hashCode());
            slicingCriterionMap.put(hashCode, slicingCriterion);

            slicingCriteria.add(slicingCriterion);

            gotoUnit = null;
            targetGotoUnits = new ArrayList<>();

            if (unitType == ASSIGN_SIGNATURE_VARIABLE) {
                break;
            }
        }

        return slicingCriteria;
    }

    public ArrayList<SlicingCriterion> splitSlicingCriterion(SlicingCriterion slicingCriterion) {
        ArrayList<SlicingCriterion> list = new ArrayList<>();

        ArrayList<String> targetParamNums = slicingCriterion.getTargetParamNums();
        ArrayList<String> targetVariables = slicingCriterion.getTargetVariables();
        for (String v : targetVariables) {
            ArrayList<String> tempParamNums = new ArrayList<>();
            int i = targetVariables.indexOf(v);
            tempParamNums.add(targetParamNums.get(i));

            ArrayList<String> tempVariables = new ArrayList<>();
            tempVariables.add(v);

            SlicingCriterion tempCriterion = (SlicingCriterion) slicingCriterion.clone();
            tempCriterion.setTargetParamNums(tempParamNums);
            tempCriterion.setTargetVariables(tempVariables);
            tempCriterion.setTargetUnits(new ArrayList<>());
            tempCriterion.setUnitStrings(new ArrayList<>());
            tempCriterion.setNextParamNums(new ArrayList<>());

            list.add(tempCriterion);
        }

        for (SlicingCriterion sc : list) {
            String hashCode = String.valueOf(sc.hashCode());
            slicingCriterionMap.put(hashCode, sc);
        }

        return list;
    }

    public SlicingCriterion getSlicingCriterion(String hashCode) {
        return slicingCriterionMap.get(hashCode);
    }

    public int getCriteriaCount() {
        return criteriaCount;
    }

    private boolean isCorrectSignature(String signature) {
        String className = getClassName(signature);
        SootClass sootClass = Scene.v().getSootClass(className);
        List<SootMethod> methods = sootClass.getMethods();
        String methodsStr = methods.toString();

        return !sootClass.isPhantomClass() || !methodsStr.contains(signature);
    }

    private void removeUnReachableCallerList(String packageName, String applicationClassName, ArrayList<String> components, ArrayList<ArrayList<String>> listOfCallers) {
        ArrayList<ArrayList<String>> targetLists = new ArrayList<>();

        for (ArrayList<String> l : listOfCallers) {
            boolean flag = true;

            for (String c : l) {
                String className = getClassName(c);
                className = className.split("\\$")[0];
                if (className.contains(packageName) || className.equals(applicationClassName) || components.contains(className)) {
                    flag = false;
                    break;
                }

                ArrayList<String> strings1 = new ArrayList<>(Arrays.asList(packageName.split("\\.")));
                ArrayList<String> strings2 = new ArrayList<>(Arrays.asList(className.split("\\.")));
                int length = strings1.size();
                int count = 0;
                for (int i = 0; i < length; i++) {
                    String str1 = strings1.get(i);
                    String str2 = strings2.get(i);
                    if (str1.equals(str2)) {
                        count++;
                    } else {
                        break;
                    }
                }

                if (count > 1) {
                    flag = false;
                    break;
                }
            }

            if (flag) {
                targetLists.add(l);
            }
        }

        listOfCallers.removeAll(targetLists);
    }

    private static class Holder {
        private static final SlicingCriteriaGenerator instance = new SlicingCriteriaGenerator();
    }
}