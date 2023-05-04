package check;

import model.Line;
import model.Pair;
import model.SlicingCriterion;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Node;
import slice.ProgramSlicer;
import slice.SliceMerger;
import soot.Unit;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.lang.Integer.parseInt;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static java.util.regex.Pattern.compile;
import static java.util.stream.Collectors.toList;
import static javax.xml.bind.DatatypeConverter.parseBase64Binary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static utils.SootUnit.*;

public abstract class BaseChecker {
    protected static HashMap<String, ArrayList<LinkedHashSet<Line>>> targetLinesMap = new HashMap<>();
    protected static HashMap<ArrayList<Line>, SchemeType> schemeTypeMap = new HashMap<>();
    protected final ProgramSlicer slicer;
    protected final SliceMerger sliceMerger;
    protected String checkerName;
    protected HashMap<Line, String> targetValueMap;

    public BaseChecker() {
        slicer = ProgramSlicer.getInstance();
        sliceMerger = SliceMerger.getInstance();

        targetValueMap = new HashMap<>();
    }

    public abstract ArrayList<SlicingCriterion> getSlicingCandidates();

    public abstract void checkRule(SlicingCriterion slicingCriterion, HashMap<String, ArrayList<ArrayList<Line>>> slicesMap);

    protected String getCheckerName(Class<?> clazz) {
        return clazz.getName();
    }

    protected ArrayList<ArrayList<Line>> findAssignInvokeSlices(String signature) {
        String bridgeNodeId = String.valueOf(signature.hashCode());
        Node bridgeNode = sliceMerger.getNode(bridgeNodeId);
        if (bridgeNode == null) {
            return new ArrayList<>();
        }

        ArrayList<ArrayList<Line>> slices = new ArrayList<>();
        Stream<Edge> stream = bridgeNode.leavingEdges();
        List<Edge> edges = stream.collect(toList());
        for (Edge e : edges) {
            Node target = e.getTargetNode();
            String targetHashCode = target.getId();
            ArrayList<Line> subSlice = slicer.getSlice(targetHashCode);
            if (subSlice == null) {
                continue;
            }

            slices.add(subSlice);
        }

        return slices;
    }

    protected ArrayList<ArrayList<Line>> findVariableSignatureSlices(String signature) {
        String bridgeNodeId = String.valueOf(signature.hashCode());
        Node bridgeNode = sliceMerger.getNode(bridgeNodeId);
        if (bridgeNode == null) {
            return new ArrayList<>();
        }

        ArrayList<ArrayList<Line>> slices = new ArrayList<>();
        Stream<Edge> stream = bridgeNode.edges();
        List<Edge> edges = stream.collect(toList());
        for (Edge e : edges) {
            Node target = e.getTargetNode();
            String targetId = target.getId();

            slices.addAll(sliceMerger.createSlices(targetId));
        }

        return slices;
    }

    protected int getValueSize(Line line) {
        int size;

        String value = extractValue(line);
        if (value == null) { // for array
            Unit unit = line.getUnit();
            String arraySize = getArraySize(unit);
            size = isVariableStr(arraySize) ? -1 : parseInt(getArraySize(unit));
        } else {
            size = value.length();
        }

        return size;
    }

    protected ArrayList<Line> findConstantLines(ArrayList<Line> slice, String regex, boolean findArray) {
        ArrayList<Line> targetLines = new ArrayList<>();

        int sliceSize = slice.size();
        ArrayList<Pair<ArrayList<Line>, Integer>> stack = new ArrayList<>();
        stack.add(new Pair<>(slice, sliceSize));
        ArrayList<ArrayList<Line>> visitedSlices = new ArrayList<>();

        Pattern pattern = compile(regex, CASE_INSENSITIVE);

        ArrayList<String> whiteSignatures = new ArrayList<>();
        whiteSignatures.add("<java.lang.Byte: void <init>(byte)>");
        whiteSignatures.add("<java.lang.Integer: void <init>(int)>");
        whiteSignatures.add("<java.util.Base64$Decoder: byte[] decode(java.lang.String)>");
        whiteSignatures.add("<java.util.Map: java.lang.Object put(java.lang.Object,java.lang.Object)>");
        whiteSignatures.add("<javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String)>");
        whiteSignatures.add("<javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String,java.security.Provider)>");
        whiteSignatures.add("<javax.crypto.Cipher: javax.crypto.Cipher getInstance(java.lang.String,java.lang.String)>");

        ArrayList<String> excludeSignatures1 = new ArrayList<>();
        excludeSignatures1.add("<java.lang.String: byte[] getBytes(java.lang.String)>");
        excludeSignatures1.add("<java.lang.System: void arraycopy(java.lang.Object,int,java.lang.Object,int,int)>");
        excludeSignatures1.add("<java.io.BufferedInputStream: void mark(int)>");
        excludeSignatures1.add("<java.security.MessageDigest: java.security.MessageDigest getInstance(java.lang.String)>");
        excludeSignatures1.add("<android.content.Context: android.content.SharedPreferences getSharedPreferences(java.lang.String,int)>");
        excludeSignatures1.add("<android.database.Cursor: int getColumnIndexOrThrow(java.lang.String)>");
        excludeSignatures1.add("<androidx.room.util.CursorUtil: int getColumnIndexOrThrow(android.database.Cursor,java.lang.String)>");
        excludeSignatures1.add("<kotlin.jvm.internal.Intrinsics: void checkNotNullExpressionValue(java.lang.Object,java.lang.String)>");

        ArrayList<String> excludeClassName = new ArrayList<>();
        excludeClassName.add("java.util.Arrays");
        excludeClassName.add("javax.crypto.spec.SecretKeySpec");
        excludeClassName.add("android.util.Base64");
        excludeClassName.add("org.apache.commons.lang3.StringUtils");
        excludeClassName.add("org.json.JSONArray");
        excludeClassName.add("org.json.JSONObject");

        while (!stack.isEmpty()) {
            int stackSize = stack.size();
            Pair<ArrayList<Line>, Integer> pair = stack.remove(stackSize - 1);
            ArrayList<Line> targetSlice = pair.getKey();
            if (visitedSlices.contains(targetSlice)) {
                continue;
            }

            visitedSlices.add(targetSlice);
            int targetIndex = pair.getValue();

            for (int i = targetIndex - 1; i > -1; i--) {
                Line line = targetSlice.get(i);
                Unit unit = line.getUnit();
                int unitType = line.getUnitType();
                if ((unitType & INVOKE) == INVOKE) {
                    String signature = getSignature(unit);
                    if (excludeSignatures1.contains(signature)) {
                        continue;
                    }

                    String className = getClassName(signature);
                    if (excludeClassName.contains(className)) {
                        continue;
                    }

                    ArrayList<ArrayList<Line>> slices = findAssignInvokeSlices(signature);
                    if (!slices.isEmpty()) {
                        stack.add(new Pair<>(targetSlice, i));

                        for (ArrayList<Line> s : slices) {
                            int subSliceSize = s.size();
                            stack.add(new Pair<>(s, subSliceSize));
                        }
                    }

                    ArrayList<String> targetVariables = new ArrayList<>();
                    if (whiteSignatures.contains(signature)) {
                        ArrayList<String> paramValues = getParamValues(unit);
                        targetVariables.addAll(paramValues);
                    } else {
                        HashSet<String> retainVariables = slicer.getRetainVariables(unit);
                        String leftValueStr = (((unitType & ASSIGN) == ASSIGN)) ? getLeftValueStr(unit, unitType) : null;
                        String localVariable = getLocalVariable(unit);
                        if (retainVariables != null && !retainVariables.contains(leftValueStr) && !retainVariables.contains(localVariable)) {
                            targetVariables.addAll(retainVariables);
                        }
                    }

                    for (String v : targetVariables) {
                        if (v.contains("null") || v.contains("AndroidOpenSSL") || isVariableStr(v)) {
                            continue;
                        }

                        v = v.replace("\"", "");
                        Matcher matcher = pattern.matcher(v);
                        if (!matcher.matches()) {
                            continue;
                        }

                        targetLines.add(line);
                        targetValueMap.put(line, v);
                        break;
                    }
                } else if (findArray && unitType == NEW_ARRAY) {
                    targetLines.add(line);
                } else if (unitType == ASSIGN_ARRAY_CONSTANT || unitType == ASSIGN_VARIABLE_CONSTANT || unitType == RETURN_VALUE) {
                    String rightValueStr = getRightValueStr(unit, unitType);
                    rightValueStr = rightValueStr.replace("\"", "");
                    if (rightValueStr.equals("") || rightValueStr.contains("null") || rightValueStr.contains("class \"L") || isVariableStr(rightValueStr)) {
                        continue;
                    }

                    Matcher matcher = pattern.matcher(rightValueStr);
                    if (matcher.matches()) {
                        targetLines.add(line);
                    }
                } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                    String signature = getSignature(unit);
                    ArrayList<ArrayList<Line>> slices = findVariableSignatureSlices(signature);
                    for (ArrayList<Line> s : slices) {
                        stack.add(new Pair<>(s, s.size() - 1));
                    }
                }
            }
        }

        return targetLines;
    }

    protected String extractValue(Line line) {
        String value = null;

        Unit unit = line.getUnit();
        int unitType = line.getUnitType();
        if ((unitType & INVOKE) == INVOKE) {
            value = targetValueMap.get(line);
        } else if (unitType == ASSIGN_ARRAY_CONSTANT) {
            value = getRightValueStr(unit, unitType);
        } else if (unitType == ASSIGN_VARIABLE_CONSTANT || unitType == RETURN_VALUE) {
            value = getRightValueStr(unit, unitType);
        }

        if (value != null) {
            value = value.replace("\"", "");
        }

        return value;
    }

    protected ArrayList<Line> getSlice(ArrayList<ArrayList<Line>> slices, int index) {
        int sliceCount = slices.size();
        return (index >= sliceCount) ? new ArrayList<>() : slices.get(index);
    }

    protected ArrayList<Line> findTargetSignatureLines(ArrayList<Line> slice, ArrayList<String> targetSignatures) {
        ArrayList<Line> targetLines = findSignatures(slice, targetSignatures);

        int sliceSize = slice.size();
        ArrayList<Pair<ArrayList<Line>, Integer>> stack = new ArrayList<>();
        stack.add(new Pair<>(slice, sliceSize - 1));
        ArrayList<ArrayList<Line>> visitedSlices = new ArrayList<>();

        while (!stack.isEmpty() && targetLines.isEmpty()) {
            int stackSize = stack.size();
            Pair<ArrayList<Line>, Integer> pair = stack.remove(stackSize - 1);
            ArrayList<Line> targetSlice = pair.getKey();
            if (visitedSlices.contains(targetSlice)) {
                continue;
            }

            visitedSlices.add(targetSlice);
            targetLines = findSignatures(targetSlice, targetSignatures);
            if (!targetLines.isEmpty()) {
                break;
            }

            int targetIndex = pair.getValue();
            for (int i = targetIndex - 1; i > -1; i--) {
                Line line = targetSlice.get(i);
                Unit unit = line.getUnit();
                int unitType = line.getUnitType();

                if ((unitType & INVOKE) == INVOKE) {
                    stack.add(new Pair<>(targetSlice, i));

                    String signature = getSignature(unit);
                    ArrayList<ArrayList<Line>> slices = findAssignInvokeSlices(signature);
                    for (ArrayList<Line> s : slices) {
                        int subSliceSize = s.size();
                        stack.add(new Pair<>(s, subSliceSize));
                    }
                } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                    stack.add(new Pair<>(targetSlice, i));

                    String signature = getSignature(unit);
                    ArrayList<ArrayList<Line>> slices = findVariableSignatureSlices(signature);
                    for (ArrayList<Line> s : slices) {
                        int subSliceSize = s.size();
                        stack.add(new Pair<>(s, subSliceSize));
                    }
                }
            }
        }

        return targetLines;
    }

    protected ArrayList<Line> findClasses(ArrayList<Line> slice, ArrayList<String> classNames) {
        ArrayList<Line> lines = new ArrayList<>();

        for (Line l : slice) {
            int unitType = l.getUnitType();
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            Unit unit = l.getUnit();
            String signature = getSignature(unit);
            String className = getClassName(signature);
            if (!classNames.contains(className)) {
                continue;
            }

            lines.add(l);
        }

        return lines;
    }

    protected ArrayList<Line> findSignatures(ArrayList<Line> slice, ArrayList<String> targetSignatures) {
        ArrayList<Line> targetLines = new ArrayList<>();

        for (Line l : slice) {
            int unitType = l.getUnitType();
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            Unit unit = l.getUnit();
            String signature = getSignature(unit);
            if (!targetSignatures.contains(signature)) {
                continue;
            }

            targetLines.add(l);
        }

        return targetLines;
    }

    private boolean isBase64String(String str) {
        Pattern pattern = compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");
        Matcher matcher = pattern.matcher(str);

        return matcher.matches();
    }

    private boolean isHexString(String str) {
        Pattern pattern = compile("^[0-9a-fA-F]+$");
        Matcher matcher = pattern.matcher(str);

        return matcher.matches();
    }

    protected RSAKey convertStringToRSAKey(String s) {
        String tempStr = s.replace("\"", "");
        tempStr = tempStr.replace("\\r", "").replace("\\n", "");

        byte[] bytes = null;
        if (isBase64String(tempStr)) {
            bytes = parseBase64Binary(tempStr);
        } else if (isHexString(tempStr)) {
            if (tempStr.length() % 2 == 1) {
                tempStr = "0" + tempStr;
            }

            bytes = parseHexBinary(tempStr);
        }

        return (bytes == null) ? null : getRSAKey(bytes);
    }

    private RSAKey getRSAKey(byte[] bytes) {
        RSAKey key = null;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            key = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {

        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            key = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {

        }

        return key;
    }

    protected ArrayList<Line> findConstantArraySlice(ArrayList<Line> slice) {
        ArrayList<Line> targetLines = new ArrayList<>();

        int sliceSize = slice.size();
        ArrayList<Pair<ArrayList<Line>, Integer>> stack = new ArrayList<>();
        stack.add(new Pair<>(slice, sliceSize - 1));
        ArrayList<ArrayList<Line>> visitedSlices = new ArrayList<>();

        while (!stack.isEmpty() && targetLines.isEmpty()) {
            int stackSize = stack.size();
            Pair<ArrayList<Line>, Integer> pair = stack.remove(stackSize - 1);
            ArrayList<Line> targetSlice = pair.getKey();
            if (visitedSlices.contains(targetSlice)) {
                continue;
            }

            visitedSlices.add(targetSlice);

            int targetIndex = pair.getValue();
            for (int i = targetIndex - 1; i > -1; i--) {
                Line line = targetSlice.get(i);
                Unit unit = line.getUnit();
                int unitType = line.getUnitType();

                if ((unitType & INVOKE) == INVOKE) {
                    stack.add(new Pair<>(targetSlice, i));

                    String signature = getSignature(unit);
                    String returnType = getReturnType(signature);
                    if (!returnType.equals("byte[]")) {
                        continue;
                    }

                    ArrayList<ArrayList<Line>> slices = findAssignInvokeSlices(signature);
                    for (ArrayList<Line> s : slices) {
                        int subSliceSize = s.size();
                        stack.add(new Pair<>(s, subSliceSize));
                    }
                } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                    stack.add(new Pair<>(targetSlice, i));

                    String signature = getSignature(unit);
                    String returnType = getReturnType(signature);
                    if (!returnType.equals("byte[]")) {
                        continue;
                    }

                    ArrayList<ArrayList<Line>> slices = findVariableSignatureSlices(signature);
                    for (ArrayList<Line> s : slices) {
                        if (s.size() < 3) {
                            continue;
                        }

                        Line firstLine = s.get(0);
                        int firstUnitType = firstLine.getUnitType();
                        Line secondLine = s.get(1);
                        int secondUnitType = secondLine.getUnitType();
                        Line lastLine = s.get(s.size() - 1);
                        int lastUnitType = lastLine.getUnitType();

                        if (firstUnitType == NEW_ARRAY && secondUnitType == ASSIGN_ARRAY_CONSTANT && lastUnitType == ASSIGN_SIGNATURE_VARIABLE) {
                            targetLines.addAll(s);
                            break;
                        }
                    }
                }
            }
        }

        return targetLines;
    }

    protected RSAKey convertArrayToRSAKey(ArrayList<Line> slice) {
        Line firstLine = slice.get(0);
        Unit firstUnit = firstLine.getUnit();
        int byteSize = parseInt(getArraySize(firstUnit));
        byte[] bytes = new byte[byteSize];

        int sliceSize = slice.size();
        for (int i = 1; i < (sliceSize - 1); i++) {
            Line line = slice.get(i);
            Unit unit = line.getUnit();

            String rightValueStr = getRightValueStr(unit, ASSIGN_ARRAY_CONSTANT);
            int c = parseInt(rightValueStr);
            bytes[i - 1] = (byte) c;
        }

        return getRSAKey(bytes);
    }

    protected boolean isDuplicateLines(String checkerName, LinkedHashSet<Line> targetLines) {
        ArrayList<LinkedHashSet<Line>> list = targetLinesMap.get(checkerName);
        if (list == null) {
            list = new ArrayList<>();
        }

        if (list.contains(targetLines)) {
            return true;
        }

        list.add(targetLines);
        targetLinesMap.put(checkerName, list);

        return false;
    }

    protected void printResult(String ruleId, String ruleDescription, SlicingCriterion slicingCriterion, HashMap<String, Object> resultMap, LinkedHashSet<Line> targetLines) {
        Node caller = slicingCriterion.getCaller();
        String callerName = caller.getId();
        String targetStatement = slicingCriterion.getTargetStatement1();
        ArrayList<String> targetParamNums = slicingCriterion.getTargetParamNums();

        System.out.println("=======================================");
        System.out.println("[*] Rule id : " + ruleId);
        System.out.println("[*] Rule description : " + ruleDescription);
        System.out.println("[*] Caller : " + callerName);
        System.out.println("[*] Slicing signature : " + targetStatement);
        System.out.println("[*] Parameter number : " + targetParamNums);

        if (resultMap != null) {
            Set<Map.Entry<String, Object>> entries = resultMap.entrySet();
            for (Map.Entry<String, Object> entry : entries) {
                String key = entry.getKey();
                Object value = entry.getValue();
                System.out.println("[*] " + key + " : " + value);
            }
        }

        if (targetLines != null && !targetLines.isEmpty()) {
            System.out.println("[*] Target lines:");
            for (Line l : targetLines) {
                System.out.println(l);
            }
        }

        System.out.println("=======================================");
    }

    public enum SchemeType {
        EncryptthenMAC, EncryptandMAC, NotDecided
    }
}