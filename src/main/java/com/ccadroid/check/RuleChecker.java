package com.ccadroid.check;

import com.ccadroid.slice.SliceDatabase;
import com.ccadroid.util.soot.SootUnit;
import org.apache.commons.lang3.math.NumberUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.mariuszgromada.math.mxparser.Argument;
import org.mariuszgromada.math.mxparser.Expression;
import org.mariuszgromada.math.mxparser.License;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.ccadroid.check.RuleConstants.*;
import static com.ccadroid.slice.SliceConstants.*;
import static com.ccadroid.util.soot.SootUnit.*;

public class RuleChecker {
    private static final Pattern BASE64_PATTERN = Pattern.compile("^([A-Za-z\\d+/]{4})*([A-Za-z\\d+/]{3}=|[A-Za-z\\d+/]{2}==)?$");
    private static final Pattern HEX_PATTERN = Pattern.compile("^[\\da-fA-F]+$");
    private final SliceDatabase sliceDatabase;
    private final ArrayList<JSONObject> rules;

    public RuleChecker() {
        sliceDatabase = SliceDatabase.getInstance();
        rules = new ArrayList<>();

        License.iConfirmNonCommercialUse("CCA-Droid");
    }

    public static RuleChecker getInstance() {
        return RuleChecker.Holder.instance;
    }

    public void loadRules(File ruleFileDir) {
        File[] ruleFiles = ruleFileDir.listFiles();
        if (ruleFiles == null) {
            return;
        }

        for (File f : ruleFiles) {
            try {
                if (f.isDirectory()) {
                    continue;
                }

                String path = f.getAbsolutePath();
                InputStream inputStream = Files.newInputStream(Paths.get(path));
                JSONTokener tokenizer = new JSONTokener(inputStream);
                JSONObject root = new JSONObject(tokenizer);
                rules.add(root);

                inputStream.close();
            } catch (IOException | JSONException ignored) {
                System.out.println("[*] ERROR: Cannot import rule file: " + f.getName());
            }
        }

        rules.sort((o1, o2) -> {
            JSONObject rule1 = o1.getJSONObject(INSECURE_RULE);
            JSONObject rule2 = o2.getJSONObject(INSECURE_RULE);
            String ruleNum1 = rule1.getString(RULE_ID).split("-")[0];
            String ruleNum2 = rule2.getString(RULE_ID).split("-")[0];

            return Integer.compare(Integer.parseInt(ruleNum1), Integer.parseInt(ruleNum2));
        });
    }

    public void extractLines(JSONArray content, String targetVariable, String targetSignature, String targetParamNum, ArrayList<JSONObject> targetLines) {
        JSONArray tempContent = new JSONArray(content);
        int length = tempContent.length();

        JSONObject lastLine = tempContent.getJSONObject(length - 1);
        if (!targetLines.contains(lastLine)) {
            targetLines.add(lastLine);
        }

        for (int i = length - 1; i >= 0; i--) {
            JSONObject line = (JSONObject) (tempContent.get(i));
            if (line.equals(lastLine)) {
                continue;
            }

            String unitStr = line.getString(UNIT_STRING);
            if (targetVariable != null && !unitStr.contains(targetVariable)) {
                continue;
            }

            if (targetSignature != null && targetSignature.equals(line.getString(CALLER_NAME))) {
                continue;
            }

            if (targetLines.contains(line)) {
                continue;
            }

            targetLines.add(0, line);
            int unitType = line.getInt(UNIT_TYPE);
            if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                ArrayList<String> paramValues = getParamValues(unitStr);

                if ((className.equals("java.util.Arrays") && methodName.equals("copyOf")) || (className.equals("java.lang.System") && methodName.equals("arraycopy"))) {
                    targetVariable = paramValues.get(0);
                } else if (className.equals("java.util.Map") && methodName.equals("put")) {
                    targetVariable = paramValues.get(1);
                } else if (className.contains("java.util.Base64$Decoder") && methodName.equals("decode")) {
                    targetVariable = paramValues.get(0);
                } else if (className.equals("javax.crypto.spec.PBEKeySpec") && methodName.equals("<init>")) { // for SecretKeyFactory.generateSecret()
                    targetVariable = paramValues.get(0);
                } else {
                    if (targetSignature != null && unitStr.contains(targetSignature)) {
                        targetVariable = paramValues.get(Integer.parseInt(targetParamNum));
                        targetSignature = null;
                        targetParamNum = null;
                    } else {
                        if (targetVariable != null && !unitStr.startsWith(targetVariable)) {
                            continue;
                        }

                        if (unitType == ASSIGN_STATIC_INVOKE) {
                            continue;
                        }

                        String valueStr = getLocalValue(unitStr);
                        if (valueStr == null) {
                            targetLines.remove(line);
                            continue;
                        }

                        extractLines(content, valueStr, null, null, targetLines);
                    }
                }
            } else if (unitType == PARAMETER) {
                String paramNum = getParamNumber(unitStr, unitType);
                extractLines(content, null, line.getString(CALLER_NAME), paramNum, targetLines);
            } else if (unitType == NEW_INSTANCE) {
                break;
            } else if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                break;
            } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                break;
            } else if (unitType == CAST) {
                targetVariable = getRightInternalValue(unitStr, unitType);
            }
        }
    }

    public void checkRules() {
        HashMap<JSONObject, HashMap<String, ArrayList<JSONObject>>> sliceMap = classifySlices();
        if (sliceMap.isEmpty()) {
            return;
        }

        Set<Map.Entry<JSONObject, HashMap<String, ArrayList<JSONObject>>>> entries = sliceMap.entrySet();
        for (Map.Entry<JSONObject, HashMap<String, ArrayList<JSONObject>>> e : entries) {
            JSONObject root = e.getKey();
            HashMap<String, ArrayList<JSONObject>> targetSlicesMap = e.getValue();

            checkRules(root, targetSlicesMap, INSECURE_RULE);
            checkRules(root, targetSlicesMap, SECURE_RULE);
        }
    }

    private HashMap<JSONObject, HashMap<String, ArrayList<JSONObject>>> classifySlices() {
        LinkedHashMap<JSONObject, HashMap<String, ArrayList<JSONObject>>> slicesMap = new LinkedHashMap<>();

        List<String> query1 = List.of(String.format("/%s==null", CALLER_NAME));
        ArrayList<JSONObject> result1 = sliceDatabase.selectAll(query1);
        for (JSONObject s1 : result1) {
            String nodeId = s1.getString(NODE_ID);
            String targetStatement = s1.getString(TARGET_STATEMENT);
            List<Object> targetParamNumbers = s1.getJSONArray(TARGET_PARAM_NUMBERS).toList();
            JSONArray content = s1.getJSONArray(CONTENT);

            for (JSONObject r : rules) {
                HashMap<String, ArrayList<JSONObject>> map = slicesMap.containsKey(r) ? slicesMap.get(r) : new HashMap<>();
                ArrayList<JSONObject> targetSlices = new ArrayList<>();
                HashSet<Object> tempContent = new HashSet<>(content.toList());

                JSONObject obj = r.getJSONObject(SLICING_SIGNATURES);
                Map<String, Object> objAsMap = obj.toMap();
                Set<Map.Entry<String, Object>> entries = objAsMap.entrySet();
                for (Map.Entry<String, Object> e : entries) {
                    String signature = e.getKey();
                    Object paramNumbers = e.getValue();
                    if (!targetStatement.equals(signature)) {
                        continue;
                    }

                    if (!(targetParamNumbers.equals(paramNumbers))) {
                        continue;
                    }

                    ArrayList<JSONObject> result2 = getRelatedSlices(nodeId);
                    for (JSONObject s2 : result2) {
                        JSONArray content2 = s2.getJSONArray(CONTENT);
                        if (content.equals(content2)) {
                            targetSlices.add(s2);
                            continue;
                        }

                        ArrayList<Object> tempContent2 = new ArrayList<>(content2.toList());
                        if (tempContent.containsAll(tempContent2)) {
                            continue;
                        }

                        tempContent.retainAll(tempContent2);
                        if (!tempContent.isEmpty()) {
                            continue;
                        }

                        tempContent.addAll(tempContent2);
                        targetSlices.add(s2);
                    }

                    map.put(nodeId, targetSlices);
                }

                slicesMap.put(r, map);
            }
        }

        return slicesMap;
    }

    private ArrayList<JSONObject> getRelatedSlices(String nodeId) {
        List<String> query1 = List.of(String.format("%s==%s", NODE_ID, nodeId), String.format("/%s==null", CALLER_NAME));
        ArrayList<JSONObject> mergedSlices = sliceDatabase.selectAll(query1);
        ArrayList<JSONObject> slices = new ArrayList<>(mergedSlices);

        ArrayList<String> queue = new ArrayList<>();
        queue.add(nodeId);

        while (!queue.isEmpty()) {
            String id = queue.remove(0);
            List<String> query2 = List.of(String.format("%s==%s", NODE_ID, id), String.format("/%s!=null", CALLER_NAME));
            JSONObject slice = sliceDatabase.selectOne(query2);
            if (slice == null) {
                continue;
            }

            if (slices.contains(slice)) {
                continue;
            } else if (!id.equals(nodeId) && !slices.contains(slice)) {
                slices.add(slice);
            }

            JSONArray relatedNodeIds = slice.getJSONArray(RELATED_NODE_IDS);
            if (relatedNodeIds.isEmpty()) {
                break;
            }

            for (Object o : relatedNodeIds) {
                queue.add((String) o);
            }
        }

        return slices;
    }

    private HashMap<String, LinkedHashSet<String>> findMisusedLines(Object conditions, Object targetAlgorithms, Object targetSignatures, ArrayList<JSONObject> slices) {
        HashMap<String, LinkedHashSet<String>> map = new HashMap<>();
        HashMap<String, String> targetSignatureMap = getTargetSignatureMap(slices);

        if (conditions instanceof JSONObject) {
            JSONObject obj = (JSONObject) conditions;
            HashSet<String> foundKeys = new HashSet<>();

            for (JSONObject s : slices) {
                String callerName = getCallerName(s);
                boolean hasCipherAndMac = hasCipherAndMac(callerName);
                JSONArray content = s.getJSONArray(CONTENT);
                LinkedHashSet<String> unitStrings = new LinkedHashSet<>();

                if (((obj.has(TARGET_SCHEME_TYPES) && !targetSignatureMap.isEmpty()) || obj.has(REQUIRED_SCHEME_TYPES)) && !foundKeys.contains(TARGET_SCHEME_TYPES)) {
                    String unitStr = checkSchemeTypes(s, content, obj, targetSignatureMap);
                    if (unitStr != null) {
                        foundKeys.add(TARGET_SCHEME_TYPES);
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_ALGORITHMS) && !hasCipherAndMac) {
                    String unitStr = checkAlgorithms(content, obj, targetAlgorithms);
                    if (unitStr != null) {
                        foundKeys.add(TARGET_ALGORITHMS);
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_SIGNATURES)) {
                    String unitStr = checkSignatures(content, obj);
                    if (unitStr != null) {
                        foundKeys.add(TARGET_SIGNATURES);
                        unitStrings.add(unitStr);
                    }
                }

                if (obj.has(TARGET_CONSTANT)) {
                    String unitStr = checkConstant(s, content, obj, targetSignatures);
                    if (unitStr != null) {
                        foundKeys.add(TARGET_CONSTANT);
                        unitStrings.add(unitStr);
                    }

                    LinkedHashSet<String> tempStrings = checkArray(s, content, obj, targetSignatures);
                    if (tempStrings != null && !tempStrings.isEmpty()) {
                        foundKeys.add(TARGET_CONSTANT);
                        unitStrings.addAll(tempStrings);
                    }
                }

                if (unitStrings.isEmpty()) {
                    continue;
                }

                LinkedHashSet<String> targetStrings = map.containsKey(callerName) ? map.get(callerName) : new LinkedHashSet<>();
                targetStrings.addAll(unitStrings);
                map.put(callerName, targetStrings);
            }

            if (!foundKeys.containsAll(getTargetKeys(obj))) {
                map.clear();
            }
        } else {
            JSONArray arr = (JSONArray) conditions;
            HashSet<String> foundKeys = new HashSet<>();

            for (JSONObject s : slices) {
                String callerName = getCallerName(s);
                boolean hasCipherAndMac = hasCipherAndMac(callerName);
                JSONArray content = s.getJSONArray(CONTENT);
                LinkedHashSet<String> unitStrings = new LinkedHashSet<>();

                Object obj1 = getValue(arr, TARGET_SCHEME_TYPES);
                if (obj1 != null) {
                    if (!targetSignatureMap.isEmpty()) {
                        String unitStr = checkSchemeTypes(s, content, obj1, targetSignatureMap);
                        if (unitStr != null) {
                            foundKeys.add(TARGET_SIGNATURES);
                            unitStrings.add(unitStr);
                        }
                    }
                }

                Object obj2 = getValue(arr, TARGET_ALGORITHMS);
                if (obj2 != null && !hasCipherAndMac) {
                    String unitStr = checkAlgorithms(content, obj2, targetAlgorithms);
                    if (unitStr != null) {
                        foundKeys.add(TARGET_ALGORITHMS);
                        unitStrings.add(unitStr);
                    }
                }

                Object obj3 = getValue(arr, TARGET_SIGNATURES);
                if (obj3 != null) {
                    String unitStr = checkSignatures(content, obj3);
                    if (unitStr != null) {
                        foundKeys.add(TARGET_SIGNATURES);
                        unitStrings.add(unitStr);
                    }
                }

                Object obj4 = getValue(arr, TARGET_CONSTANT);
                if (obj4 != null) {
                    String unitStr = checkConstant(s, content, obj4, targetSignatures);
                    if (unitStr != null) {
                        foundKeys.add(TARGET_CONSTANT);
                        unitStrings.add(unitStr);
                    }

                    LinkedHashSet<String> tempStrings = checkArray(s, content, obj4, targetSignatures);
                    if (tempStrings != null) {
                        foundKeys.add(TARGET_CONSTANT);
                        unitStrings.addAll(tempStrings);
                    }
                }

                if (unitStrings.isEmpty()) {
                    continue;
                }

                LinkedHashSet<String> targetStrings = map.containsKey(callerName) ? map.get(callerName) : new LinkedHashSet<>();
                targetStrings.addAll(unitStrings);
                map.put(callerName, targetStrings);
            }

            boolean flag = false;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                HashSet<String> targetKeys = getTargetKeys(obj);
                if (foundKeys.containsAll(targetKeys) && (foundKeys.containsAll(obj.keySet()) || obj.keySet().containsAll(foundKeys))) {
                    flag = true;
                    break;
                }
            }

            if (!flag) {
                map.clear();
            }
        }

        return map;
    }

    private void checkRules(JSONObject root, HashMap<String, ArrayList<JSONObject>> targetSlicesMap, String ruleName) {
        if (!root.has(ruleName)) {
            return;
        }

        JSONObject rule = root.getJSONObject(ruleName);
        if (!rule.has(CONDITIONS)) {
            return;
        }

        Object targetAlgorithms = null;
        Object targetSignatures = null;
        if (ruleName.equals(INSECURE_RULE)) {
            JSONObject secureRule = root.getJSONObject(SECURE_RULE);
            targetAlgorithms = getValue(secureRule, TARGET_ALGORITHMS);
            targetSignatures = getValue(secureRule, TARGET_SIGNATURES);
        }

        Object conditions = rule.get(CONDITIONS);
        Set<Map.Entry<String, ArrayList<JSONObject>>> entries = targetSlicesMap.entrySet();
        for (Map.Entry<String, ArrayList<JSONObject>> e : entries) {
            ArrayList<JSONObject> slices = e.getValue();
            HashMap<String, LinkedHashSet<String>> misusedLinesMap = findMisusedLines(conditions, targetAlgorithms, targetSignatures, slices);
            if (misusedLinesMap.isEmpty()) {
                continue;
            }

            String nodeId = e.getKey();
            List<String> query = List.of(String.format("%s==%s", NODE_ID, nodeId), String.format("/%s!=null", CALLER_NAME));
            JSONObject targetSlice = sliceDatabase.selectOne(query);
            if (targetSlice == null) {
                continue;
            }

            String ruleId = rule.getString(RULE_ID);
            String description = rule.getString(DESCRIPTION);
            String callerName = targetSlice.getString(CALLER_NAME);
            String targetStatement = targetSlice.getString(TARGET_STATEMENT);

            printResult(ruleId, description, callerName, targetStatement, misusedLinesMap);
        }
    }

    private String checkSchemeTypes(JSONObject slice, JSONArray content, Object object, HashMap<String, String> targetSignatureMap) {
        if (object == null) {
            return null;
        }

        JSONObject obj = (object instanceof JSONObject) ? (JSONObject) object : new JSONObject();
        if (obj.has(REQUIRED_SCHEME_TYPES)) {
            return findTargetString(slice);
        }

        JSONArray types = (object instanceof JSONObject) ? obj.getJSONArray(TARGET_SCHEME_TYPES) : (JSONArray) object;
        List<Object> typeAsList = types.toList();

        String targetVariable = null;
        String targetParamNumber = null;
        String targetSignature = null;

        for (int i = content.length() - 1; i > -1; i--) {
            JSONObject line = content.getJSONObject(i);
            String unitStr = line.getString(UNIT_STRING);
            int unitType = line.getInt(UNIT_TYPE);
            if (targetVariable != null && unitStr.startsWith(targetVariable) && unitType == PARAMETER) {
                targetParamNumber = getParamNumber(unitStr, unitType);
                targetSignature = line.getString(CALLER_NAME);
                continue;
            }

            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String signature = getSignature(unitStr);
            String className = getClassName(signature);
            String methodName = getMethodName(signature);
            ArrayList<String> paramValues = getParamValues(unitStr);
            if (className.equals("javax.crypto.Cipher") && ((methodName.equals("update") || methodName.equals("doFinal")))) {
                if (targetVariable == null && paramValues.isEmpty()) { // for doFinal()
                    continue;
                } else if (targetVariable == null && paramValues.size() == 1) { // update or doFinal(byte[])
                    targetVariable = paramValues.get(0);
                    continue;
                }

                if (targetVariable != null && ((unitStr.startsWith(targetVariable) && typeAsList.contains(ENCRYPT_THEN_MAC)) || (!unitStr.startsWith(targetVariable) && typeAsList.contains(ENCRYPT_AND_MAC)))) {
                    List<String> query = List.of(String.format("%s==%s", TARGET_STRING, unitStr));
                    sliceDatabase.update(slice, query);

                    return unitStr;
                }
            } else if (className.equals("java.lang.System") && methodName.equals("arraycopy")) {
                if (!paramValues.contains(targetVariable)) {
                    continue;
                }

                targetVariable = paramValues.get(0);
            } else if (className.equals("javax.crypto.Mac") && ((methodName.equals("update") || methodName.equals("doFinal")))) {
                if (targetVariable == null && paramValues.isEmpty()) { // for doFinal()
                    continue;
                } else if (targetVariable == null && paramValues.size() == 1) { // update or doFinal(byte[])
                    targetVariable = paramValues.get(0);
                    continue;
                }

                if (targetVariable != null && unitStr.startsWith(targetVariable) && typeAsList.contains(MAC_THEN_ENCRYPT)) {
                    List<String> query = List.of(String.format("%s==%s", TARGET_STRING, unitStr));
                    sliceDatabase.update(slice, query);

                    return unitStr;
                }
            } else if (targetParamNumber != null && targetSignature != null && unitStr.contains(targetSignature)) {
                int index = Integer.parseInt(targetParamNumber);
                targetVariable = paramValues.get(index);

                targetParamNumber = null;
                targetSignature = null;
            } else if (targetVariable != null && targetSignatureMap.containsValue(signature)) {
                if (className.equals("javax.crypto.spec.SecretKeySpec") && methodName.equals("<init>")) {
                    continue;
                }

                if ((unitStr.startsWith(targetVariable) && typeAsList.contains(ENCRYPT_THEN_MAC)) || (!unitStr.startsWith(targetVariable) && typeAsList.contains(ENCRYPT_AND_MAC))) {
                    List<String> query = List.of(String.format("%s==%s", TARGET_STRING, unitStr));
                    sliceDatabase.update(slice, query);

                    return unitStr;
                }
            }
        }

        return null;
    }

    private String checkAlgorithms(JSONArray content, Object object, Object targetAlgorithms) {
        String oldUnitStr = checkAlgorithms(content, object);
        if (targetAlgorithms == null) {
            return oldUnitStr;
        }

        String newUnitStr = checkAlgorithms(content, targetAlgorithms);

        return findLateUnitString(content, oldUnitStr, newUnitStr);
    }

    private String checkAlgorithms(JSONArray content, Object object) {
        if (object == null) {
            return null;
        }

        JSONArray arr = (object instanceof JSONObject) ? ((JSONObject) object).getJSONArray(TARGET_ALGORITHMS) : (JSONArray) object;
        int arrSize = arr.length();

        for (Object l : content) {
            JSONObject line = (JSONObject) l;
            if (!line.has(CONSTANTS)) {
                continue;
            }

            JSONArray constants = line.getJSONArray(CONSTANTS);
            for (Object o : constants) {
                String s = (String) o;
                s = s.replace("\"", "");
                if (!isAlgorithm(s)) {
                    continue;
                }

                for (int i = 0; i < arrSize; i++) {
                    boolean flag;
                    String algorithm = arr.getString(i);
                    String regex = "-";

                    if (algorithm.contains(regex)) {
                        String[] strArr = algorithm.split(regex);
                        Pattern pattern = Pattern.compile("(?i)^(" + strArr[0] + ")?(/.*)?$");
                        Matcher matcher = pattern.matcher(s);
                        flag = matcher.matches() && !s.toLowerCase().contains(strArr[1].toLowerCase());
                    } else {
                        Pattern pattern = Pattern.compile("(?i)^(" + algorithm + ")?(/.*)?$");
                        Matcher matcher = pattern.matcher(s);
                        flag = matcher.matches();
                    }

                    if (flag) {
                        return line.getString(UNIT_STRING);
                    }
                }
            }
        }

        return null;
    }

    private String checkSignatures(JSONArray content, Object object) {
        if (object == null) {
            return null;
        }

        JSONArray arr = (object instanceof JSONObject) ? ((JSONObject) object).getJSONArray(TARGET_SIGNATURES) : (JSONArray) object;
        List<Object> objects = arr.toList();

        JSONArray tempContent = new JSONArray(content);
        for (int i = tempContent.length() - 1; i >= 0; i--) {
            JSONObject line = (JSONObject) (tempContent.get(i));
            int unitType = line.getInt(UNIT_TYPE);
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String unitStr = line.getString(UNIT_STRING);
            String signature = SootUnit.getSignature(unitStr);
            if (objects.contains(signature)) {
                return unitStr;
            }
        }

        return null;
    }

    private String checkConstant(JSONObject slice, JSONArray content, Object object, Object targetSignatures) {
        ArrayList<JSONObject> targetLines = new ArrayList<>();

        List<Object> targetParamNumbers = slice.getJSONArray(TARGET_PARAM_NUMBERS).toList();
        JSONArray targetVariables = slice.getJSONArray(TARGET_VARIABLES);
        String targetVariable = (String) targetVariables.get(0);
        if (targetParamNumbers.contains(-1) && targetVariables.length() == 2) {
            targetVariable = (String) targetVariables.get(1);
        }

        extractLines(content, targetVariable, null, null, targetLines);
        if (targetLines.isEmpty()) {
            return null;
        }

        String oldUnitStr = checkConstant(targetLines, targetVariable, object);
        if (targetSignatures == null) {
            return oldUnitStr;
        }

        String newUnitStr = findSecureUnitString(content, targetSignatures);

        return findLateUnitString(content, oldUnitStr, newUnitStr);
    }

    private String checkConstant(ArrayList<JSONObject> content, String targetVariable, Object object) {
        if (object == null) {
            return null;
        }

        JSONObject obj = (JSONObject) object;
        String regex = obj.getString(TARGET_CONSTANT);
        Pattern targetPattern = Pattern.compile(regex);
        String length = obj.has(TARGET_CONSTANT_LENGTH) ? obj.getString(TARGET_CONSTANT_LENGTH) : null;
        String size = obj.has(TARGET_CONSTANT_SIZE) ? obj.getString(TARGET_CONSTANT_SIZE) : null;

        for (int i = 0; i < content.size(); i++) {
            JSONObject line = content.get(i);
            if (!line.has(CONSTANTS)) {
                continue;
            }

            JSONArray constants = line.getJSONArray(CONSTANTS);
            for (Object o : constants) {
                String s = (String) o;
                s = s.replace("\"", "");
                if (i == content.size() - 1 && !targetVariable.contains(s)) {
                    continue;
                }

                if (s.toLowerCase().contains("f") && NumberUtils.isCreatable(s)) {
                    s = String.valueOf((int) Double.parseDouble(s));
                }

                Matcher matcher = targetPattern.matcher(s);
                if (!matcher.matches()) {
                    continue;
                }

                if (isAlgorithm(s)) {
                    continue;
                }

                if (regex.equals(".*") && size == null && isNumber(s)) {
                    continue;
                }

                if (length != null) {
                    s = String.valueOf(s.length());
                }

                if (size != null) {
                    RSAKey rsaKey = convertToRSAKey(s);
                    if (rsaKey == null) {
                        s = (isNumber(s)) ? s : String.valueOf(s.length());
                    } else {
                        BigInteger modulus = rsaKey.getModulus();
                        int bitLength = modulus.bitLength();
                        s = String.valueOf(bitLength);
                    }
                }

                if (length != null || size != null) {
                    Argument argument = new Argument("x=" + s);
                    String expression = (length == null) ? size : length;
                    Expression e = new Expression(expression, argument);
                    if (e.calculate() == 0) {
                        continue;
                    }
                }

                return line.getString(UNIT_STRING);
            }
        }

        return null;
    }

    private LinkedHashSet<String> checkArray(JSONObject slice, JSONArray content, Object object, Object targetSignatures) {
        ArrayList<JSONObject> targetLines = new ArrayList<>();

        List<Object> targetParamNumbers = slice.getJSONArray(TARGET_PARAM_NUMBERS).toList();
        JSONArray targetVariables = slice.getJSONArray(TARGET_VARIABLES);
        String targetVariable = (String) targetVariables.get(0);
        if (targetParamNumbers.contains(-1) && targetVariables.length() == 2) {
            targetVariable = (String) targetVariables.get(1);
        }

        extractLines(content, targetVariable, null, null, targetLines);
        if (targetLines.isEmpty()) {
            return null;
        }

        LinkedHashSet<String> oldUnitStrings = checkArray(targetLines, object);
        if (oldUnitStrings.isEmpty()) {
            return null;
        }

        if (targetSignatures == null) {
            return oldUnitStrings;
        }

        String newUnitStr = findSecureUnitString(content, targetSignatures);
        if (newUnitStr == null) {
            return oldUnitStrings.isEmpty() ? null : oldUnitStrings;
        }

        String oldUnitStr = new ArrayList<>(oldUnitStrings).get(0);
        LinkedHashSet<String> newUnitStrings = new LinkedHashSet<>();
        newUnitStrings.add(newUnitStr);

        return findLateUnitString(content, oldUnitStr, newUnitStr) == null ? null : newUnitStrings;
    }

    private LinkedHashSet<String> checkArray(ArrayList<JSONObject> content, Object object) {
        if (object == null) {
            return null;
        }

        JSONObject obj = (JSONObject) object;
        LinkedHashSet<String> unitStrings = new LinkedHashSet<>();

        JSONObject firstLine = content.get(0);
        int firstUnitType = firstLine.getInt(UNIT_TYPE);
        if (firstUnitType != NEW_ARRAY) {
            return unitStrings;
        }

        JSONObject secondLine = content.get(1);
        int secondUnitType = secondLine.getInt(UNIT_TYPE);
        JSONObject lastLine = content.get(content.size() - 1);
        int lastUnitType = lastLine.getInt(UNIT_TYPE);

        String length = obj.has(TARGET_CONSTANT_LENGTH) ? obj.getString(TARGET_CONSTANT_LENGTH) : null;
        String size = obj.has(TARGET_CONSTANT_SIZE) ? obj.getString(TARGET_CONSTANT_SIZE) : null;
        if (length != null || size != null) {
            String unitStr = firstLine.getString(UNIT_STRING);
            String arraySize = getArraySize(unitStr, firstUnitType);
            if (isVariableStr(arraySize)) {
                return unitStrings;
            }

            Argument argument = new Argument("x=" + arraySize);
            String expression = (length == null) ? size : length;
            Expression e = new Expression(expression, argument);
            if (e.calculate() == 1) {
                unitStrings.add(unitStr);
            }

            return unitStrings;
        }

        if (secondUnitType == ASSIGN_ARRAY_CONSTANT && lastUnitType == ASSIGN_SIGNATURE_VARIABLE) {
            for (JSONObject l : content) {
                String unitStr = l.getString(UNIT_STRING);
                unitStrings.add(unitStr);
            }
        } else {
            String unitStr = firstLine.getString(UNIT_STRING);
            unitStrings.add(unitStr);
        }

        return unitStrings;
    }

    private Object getValue(Object object, String key) {
        if (object instanceof JSONObject) {
            JSONObject obj = (JSONObject) object;
            if (obj.has(key)) {
                return obj;
            } else {
                Set<String> keys = obj.keySet();
                for (String k : keys) {
                    Object value = getValue(obj.get(k), key);
                    if (value == null) {
                        continue;
                    }

                    return value;
                }
            }
        } else if (object instanceof JSONArray) {
            JSONArray array = (JSONArray) object;
            for (Object o : array) {
                Object value = getValue(o, key);
                if (value == null) {
                    continue;
                }

                return value;
            }
        }

        return null;
    }

    private HashMap<String, String> getTargetSignatureMap(ArrayList<JSONObject> slices) {
        boolean isCipher = false;
        boolean isMac = false;
        HashMap<String, String> targetSignatureMap = new HashMap<>();

        for (JSONObject s : slices) {
            String callerName = getCallerName(s);
            JSONArray content = s.getJSONArray(CONTENT);
            for (Object o : content) {
                JSONObject line = (JSONObject) o;
                int unitType = line.getInt(UNIT_TYPE);
                if ((unitType & INVOKE) != INVOKE) {
                    continue;
                }

                String unitStr = line.getString(UNIT_STRING);
                String signature = getSignature(unitStr);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                if (className.equals("javax.crypto.Cipher") && (methodName.equals("update") || methodName.equals("doFinal"))) {
                    isCipher = true;
                    targetSignatureMap.put(className, callerName);
                } else if (className.equals("javax.crypto.Mac") && (methodName.equals("update") || methodName.equals("doFinal"))) {
                    isMac = true;
                    targetSignatureMap.put(className, callerName);
                }
            }

            if (isCipher && isMac) {
                break;
            }
        }

        return (isCipher && isMac) ? targetSignatureMap : new HashMap<>();
    }

    private boolean hasCipherAndMac(String callerName) {
        List<String> query1 = List.of(String.format("%s==%s", CALLER_NAME, callerName), String.format("%s in %s", UNIT_STRING, "javax.crypto.Cipher"));
        List<String> query2 = List.of(String.format("%s==%s", CALLER_NAME, callerName), String.format("%s in %s", UNIT_STRING, "javax.crypto.Mac"));
        ArrayList<JSONObject> cipherResults = sliceDatabase.selectAll(query1);
        ArrayList<JSONObject> macResults = sliceDatabase.selectAll(query2);

        return !cipherResults.isEmpty() && !macResults.isEmpty();
    }

    private String getCallerName(JSONObject slice) {
        String callerName;

        if (slice.has(CALLER_NAME)) {
            callerName = slice.getString(CALLER_NAME);
        } else {
            String nodeId = slice.getString(NODE_ID);
            List<String> query = List.of(String.format("%s==%s", NODE_ID, nodeId), String.format("/%s!=null", CALLER_NAME));
            JSONObject targetSlice = sliceDatabase.selectOne(query);
            callerName = targetSlice == null ? null : targetSlice.getString(CALLER_NAME);
        }

        return callerName;
    }

    private String findTargetString(JSONObject slice) {
        String callerName = getCallerName(slice);
        String className = getClassName(callerName);

        ArrayList<String> targetSignatures = new ArrayList<>();
        targetSignatures.add("<javax.crypto.Mac: byte[] doFinal()>");
        targetSignatures.add("<javax.crypto.Mac: byte[] doFinal(byte[])>");
        targetSignatures.add("<javax.crypto.Mac: void doFinal(byte[],int)>");

        for (String s : targetSignatures) {
            List<String> query1 = List.of(String.format("%s in %s", CALLER_NAME, className), String.format("%s==%s", TARGET_STATEMENT, s));
            JSONObject targetSlice1 = sliceDatabase.selectOne(query1);
            if (targetSlice1 == null) {
                continue;
            }

            String nodeId = targetSlice1.getString(NODE_ID);
            List<String> query2 = List.of(String.format("%s==%s", NODE_ID, nodeId), String.format("/%s!=null", TARGET_STRING));
            JSONObject targetSlice2 = sliceDatabase.selectOne(query2);
            if (targetSlice2 == null) {
                continue;
            }

            return targetSlice2.getString(TARGET_STRING);
        }

        return null;
    }

    private HashSet<String> getTargetKeys(JSONObject obj) {
        HashSet<String> strings = new HashSet<>();
        if (obj.has(TARGET_SCHEME_TYPES) || obj.has(REQUIRED_SCHEME_TYPES)) {
            strings.add(TARGET_SCHEME_TYPES);
        }

        if (obj.has(TARGET_ALGORITHMS)) {
            strings.add(TARGET_ALGORITHMS);
        }

        if (obj.has(TARGET_SIGNATURES)) {
            strings.add(TARGET_SIGNATURES);
        }

        if (obj.has(TARGET_CONSTANT)) {
            strings.add(TARGET_CONSTANT);
        }

        return strings;
    }

    private void printResult(String ruleId, String description, String callerName, String targetStatement, HashMap<String, LinkedHashSet<String>> misusedLinesMap) {
        System.out.println();
        System.out.println("=======================================");
        System.out.println("[*] Rule ID: " + ruleId);
        System.out.println("[*] Description: " + description);
        System.out.println("[*] Caller name: " + callerName);
        System.out.println("[*] Target statement: " + targetStatement);
        System.out.println("[*] Target lines:");
        misusedLinesMap.forEach((key, value) -> {
            System.out.println(key + ":");
            for (String s : value) {
                System.out.println(s);
            }
        });
        System.out.println("=======================================");
    }

    private String findLateUnitString(JSONArray content, String unitStr1, String unitStr2) {
        JSONObject line1 = findLine(content, unitStr1);
        JSONObject line2 = findLine(content, unitStr2);
        if (line1 == null || line2 == null || line1.equals(line2)) {
            return unitStr1;
        }

        return line1.getString(CALLER_NAME).equals(line2.getString(CALLER_NAME)) && line1.getInt(LINE_NUMBER) <= line2.getInt(LINE_NUMBER) ? null : unitStr1;
    }

    private JSONObject findLine(JSONArray content, String targetUnitStr) {
        if (targetUnitStr == null) {
            return null;
        }

        for (Object o : content) {
            JSONObject line = (JSONObject) o;
            String unitStr = line.getString(UNIT_STRING);
            if (unitStr.contains(targetUnitStr)) {
                return line;
            }
        }

        return null;
    }

    private String findSecureUnitString(JSONArray content, Object targetSignatures) {
        String targetUnitStr = checkSignatures(content, targetSignatures);
        if (targetUnitStr != null) {
            return targetUnitStr;
        }

        int length = content.length();
        for (int i = 0; i < length; i++) {
            JSONObject line = (JSONObject) (content.get(i));
            int unitType = line.getInt(UNIT_TYPE);
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            JSONObject nextLine = (i + 1 < length) ? (JSONObject) content.get(i + 1) : new JSONObject();
            int nextUnitType = (i + 1 < length) ? nextLine.getInt(UNIT_TYPE) : -1;
            if (nextUnitType == PARAMETER) {
                continue;
            }

            String unitStr = line.getString(UNIT_STRING);
            String signature = getSignature(unitStr);
            List<String> query = List.of(String.format("%s==%s", CALLER_NAME, signature));
            JSONObject targetSlice = sliceDatabase.selectOne(query);
            if (targetSlice == null) {
                continue;
            }

            JSONArray targetContent = targetSlice.getJSONArray(CONTENT);
            targetUnitStr = checkSignatures(targetContent, targetSignatures);
            if (targetUnitStr == null) {
                continue;
            }

            targetUnitStr = unitStr;
            break;
        }

        return targetUnitStr;
    }

    private boolean isAlgorithm(String constant) {
        constant = constant.toLowerCase();

        try {
            Cipher.getInstance(constant);
            return true;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ignored) {

        }

        try {
            SecretKeyFactory.getInstance(constant);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        try {
            MessageDigest.getInstance(constant);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        try {
            Mac.getInstance(constant);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        return false;
    }

    private boolean isNumber(String constant) {
        try {
            Integer.parseInt(constant);
        } catch (NumberFormatException ignored) {
            return false;
        }

        return true;
    }

    private RSAKey convertToRSAKey(String str) {
        String s = str.replace("\"", "");
        s = s.replace("\\r", "").replace("\\n", "");

        byte[] bytes = null;
        if (isBase64String(s)) {
            bytes = DatatypeConverter.parseBase64Binary(s);
        } else if (isHexString(s)) {
            if (s.length() % 2 == 1) {
                s = "0" + s;
            }

            bytes = DatatypeConverter.parseHexBinary(s);
        }

        return (bytes == null) ? null : getRSAKey(bytes);
    }

    private boolean isBase64String(String str) {
        Matcher matcher = BASE64_PATTERN.matcher(str);

        return matcher.matches();
    }

    private boolean isHexString(String str) {
        Matcher matcher = HEX_PATTERN.matcher(str);

        return matcher.matches();
    }

    private RSAKey getRSAKey(byte[] bytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return (RSAPublicKey) publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {

        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return (RSAPrivateKey) privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {

        }

        return null;
    }

    private static class Holder {
        private static final RuleChecker instance = new RuleChecker();
    }
}