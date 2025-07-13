package com.ccadroid.check;

import com.ccadroid.inspect.ApkParser;
import com.ccadroid.inspect.SlicingCriterion;
import com.ccadroid.slice.ProgramSlicer;
import com.ccadroid.slice.SliceDatabase;
import com.ccadroid.util.Argparse4j;
import jakarta.xml.bind.DatatypeConverter;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import javax.crypto.*;
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

import static com.ccadroid.check.RuleConstant.*;
import static com.ccadroid.slice.SliceConstant.*;
import static com.ccadroid.util.Common.*;
import static com.ccadroid.util.MathParser.calculateExpression;
import static com.ccadroid.util.soot.SootUnit.*;

public class RuleChecker {
    private static final ApkParser apkParser;
    private static final ProgramSlicer programSlicer;
    private static final SliceDatabase sliceDatabase;
    private static final Pattern BASE64_PATTERN = Pattern.compile("^([A-Za-z\\d+/]{4})*([A-Za-z\\d+/]{3}=|[A-Za-z\\d+/]{2}==)?$");
    private static final Pattern HEX_PATTERN = Pattern.compile("^[\\da-fA-F]+$");

    static {
        apkParser = ApkParser.getInstance();
        programSlicer = ProgramSlicer.getInstance();
        sliceDatabase = SliceDatabase.getInstance();
    }

    private final ArrayList<JSONObject> rules;
    private final HashMap<String, HashMap<JSONObject, JSONObject>> foundLineMap;
    private final HashMap<String, ArrayList<JSONObject>> sliceMap;
    private Object secureAlgorithms;
    private Object randomSignatures;

    public RuleChecker() {
        rules = new ArrayList<>();
        foundLineMap = new HashMap<>();
        sliceMap = new HashMap<>();

        loadRuleFiles();
    }

    public static RuleChecker getInstance() {
        return SingletonHolder.instance;
    }

    public ArrayList<JSONObject> getRules() {
        return rules;
    }

    public void checkRules(SlicingCriterion slicingCriterion) {
        ArrayList<JSONObject> targetRules = findTargetRules(slicingCriterion);

        for (JSONObject root : targetRules) {
            setSecureValues(root);

            ArrayList<JSONObject> slices = findCombinedSlices(slicingCriterion);
            for (JSONObject s : slices) {
                checkRules(slicingCriterion, root, INSECURE_RULE, s);
                checkRules(slicingCriterion, root, SECURE_RULE, s);
            }
        }
    }

    public boolean isAlgorithm(String str) {
        String s = str.toLowerCase();

        try {
            Cipher.getInstance(s);
            return true;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ignored) {

        }

        try {
            SecretKeyFactory.getInstance(s);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        try {
            SecureRandom.getInstance(s);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        try {
            KeyAgreement.getInstance(s);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        try {
            MessageDigest.getInstance(s);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        try {
            Mac.getInstance(s);
            return true;
        } catch (NoSuchAlgorithmException ignored) {

        }

        return false;
    }

    private void loadRuleFiles() {
        File ruleFileDir = new File(Argparse4j.getString(Argparse4j.RULE_PATH));
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
                printf(getClass(), String.format("Cannot import rule file: %s", f.getName()));
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

    private ArrayList<JSONObject> findTargetRules(SlicingCriterion slicingCriterion) {
        String targetStatement = slicingCriterion.getTargetStatement();
        ArrayList<Integer> targetParamNumbers = slicingCriterion.getTargetParamNumbers();
        ArrayList<JSONObject> targetRules = new ArrayList<>();

        for (JSONObject root : rules) {
            JSONObject signatures = root.getJSONObject(SLICING_SIGNATURES);
            Map<String, Object> map = signatures.toMap();
            Object o = map.get(targetStatement);
            if (o == null) {
                continue;
            }

            if (targetParamNumbers.toString().equals(o.toString())) {
                targetRules.add(root);
            }
        }

        return targetRules;
    }

    private void setSecureValues(JSONObject root) {
        if (root != null && root.has(SECURE_RULE)) {
            JSONObject rule = root.getJSONObject(SECURE_RULE);
            secureAlgorithms = getJsonValue(rule, TARGET_ALGORITHMS);
            randomSignatures = getJsonValue(rule, TARGET_SIGNATURES);
        }
    }

    private ArrayList<JSONObject> findCombinedSlices(SlicingCriterion slicingCriterion) {
        String id = slicingCriterion.getId();
        List<String> query = List.of(String.format("%s==%s", NODE_ID, id), String.format("%s==null", CALLER_NAME), String.format("%s!=null", CONTENTS));

        return sliceDatabase.selectAll(query);
    }

    private void checkRules(SlicingCriterion slicingCriterion, JSONObject root, String ruleName, JSONObject combinedSlice) {
        if (root == null) {
            return;
        }

        String callerName = slicingCriterion.getCallerName();
        JSONObject rule = root.getJSONObject(ruleName);
        String ruleId = rule.getString(RULE_ID);
        Object conditions = rule.get(CONDITIONS);
        JSONArray contents = combinedSlice.getJSONArray(CONTENTS);
        String ruleNumber = ruleId.split("-")[0];
        String key = String.format("%s-%s", callerName, ruleNumber);

        HashMap<JSONObject, JSONObject> map = foundLineMap.getOrDefault(key, new HashMap<>());
        if (hasIntersection(contents, map)) {
            return;
        }

        LinkedHashSet<JSONObject> lines = findTargetLines(callerName, ruleName, conditions, contents, map);
        if (lines.isEmpty()) {
            return;
        }

        foundLineMap.put(key, map);

        String description = rule.getString(DESCRIPTION);
        String targetStatement = combinedSlice.getString(TARGET_STATEMENT);

        printResult(ruleId, description, callerName, targetStatement, lines);
    }

    private Object getJsonValue(Object object, String key) {
        if (object instanceof JSONObject) {
            JSONObject obj = (JSONObject) object;
            Set<String> keys = obj.keySet();

            if (keys.contains(key)) {
                return obj.get(key);
            }

            for (String k : keys) {
                Object value = getJsonValue(obj.get(k), key);
                if (value == null) {
                    continue;
                }

                return value;
            }
        } else if (object instanceof JSONArray) {
            JSONArray arr = (JSONArray) object;

            for (Object o : arr) {
                Object value = getJsonValue(o, key);
                if (value == null) {
                    continue;
                }

                return value;
            }
        }

        return null;
    }

    private LinkedHashSet<JSONObject> findTargetLines(String callerName, String ruleName, Object conditions, JSONArray combinedContents, HashMap<JSONObject, JSONObject> foundLineMap) {
        LinkedHashSet<JSONObject> foundLines = new LinkedHashSet<>();
        HashSet<String> foundKeys = new HashSet<>();

        Object targetSchemeTypes = getJsonValue(conditions, TARGET_SCHEME_TYPES);
        ArrayList<JSONObject> lines1 = checkSchemeTypes(callerName, combinedContents, targetSchemeTypes, foundLineMap);
        if (lines1 != null) {
            foundLines.addAll(lines1);
            foundKeys.add(TARGET_SCHEME_TYPES);
        }

        Object targetAlgorithms = getJsonValue(conditions, TARGET_ALGORITHMS);
        JSONObject line2 = checkAlgorithms(ruleName, combinedContents, targetAlgorithms, foundLineMap);
        if (line2 != null) {
            foundLines.add(line2);
            foundKeys.add(TARGET_ALGORITHMS);
        }

        Object targetSignatures = getJsonValue(conditions, TARGET_SIGNATURES);
        JSONObject line3 = checkSignatures(ruleName, combinedContents, targetSignatures, foundLineMap);
        if (line3 != null) {
            foundLines.add(line3);
            foundKeys.add(TARGET_SIGNATURES);
        }

        Object targetConstRegex = getJsonValue(conditions, TARGET_CONSTANT_REGEX);
        Object targetConstLen = getJsonValue(conditions, TARGET_CONSTANT_LENGTH);
        Object targetConstSize = getJsonValue(conditions, TARGET_CONSTANT_SIZE);
        JSONObject line4 = checkConstant(ruleName, combinedContents, targetConstRegex, targetConstLen, targetConstSize, foundLineMap);
        if (line4 != null) {
            foundLines.add(line4);
            foundKeys.add(TARGET_CONSTANT_REGEX);
        }

        JSONObject line5 = checkArray(ruleName, combinedContents, targetConstRegex, targetConstLen, targetConstSize, foundLineMap);
        if (line5 != null) {
            foundLines.add(line5);
            foundKeys.add(TARGET_CONSTANT_REGEX);
        }

        if (conditions instanceof JSONObject) {
            JSONObject obj = (JSONObject) conditions;
            HashSet<String> targetKeys = getTargetKeys(obj);
            if (!foundKeys.containsAll(targetKeys) || !targetKeys.containsAll(foundKeys)) {
                foundLines.clear();
            }
        } else {
            boolean flag = false;

            JSONArray arr = (JSONArray) conditions;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject obj = arr.getJSONObject(i);
                HashSet<String> targetKeys = getTargetKeys(obj);
                if (foundKeys.containsAll(targetKeys) && (foundKeys.containsAll(obj.keySet()) || obj.keySet().containsAll(foundKeys))) {
                    flag = true;
                    break;
                }
            }

            if (!flag) {
                foundLines.clear();
            }
        }

        return foundLines;
    }

    private boolean hasIntersection(JSONArray contents, HashMap<JSONObject, JSONObject> foundLineMap) {
        HashMap<String, String> map = new HashMap<>();

        for (int i = 0; i < contents.length(); i++) {
            JSONObject line = contents.getJSONObject(i);
            map.put(line.getString(UNIT_STRING), line.getString(CALLER_NAME));
        }

        Set<Map.Entry<JSONObject, JSONObject>> entries = foundLineMap.entrySet();
        for (Map.Entry<JSONObject, JSONObject> e : entries) {
            JSONObject foundLine = e.getValue();
            String unitString = foundLine.getString(UNIT_STRING);
            if (map.containsKey(unitString) && map.get(unitString).equals(foundLine.getString(CALLER_NAME))) {
                return true;
            }
        }

        return false;
    }

    private void printResult(String ruleId, String description, String callerName, String targetStatement, LinkedHashSet<JSONObject> foundLines) {
        ArrayList<String> strings = new ArrayList<>();
        strings.add("=======================================\n");
        strings.add(String.format("[*] Rule ID: %s\n", ruleId));
        strings.add(String.format("[*] Description: %s\n", description));
        strings.add(String.format("[*] Caller name: %s\n", callerName));
        strings.add(String.format("[*] Target statement: %s\n", targetStatement));
        strings.add("[*] Target lines:\n");
        foundLines.forEach(l -> {
            String signature = l.getString(CALLER_NAME);
            strings.add(String.format("%s, callerName=%s", l.getString(UNIT_STRING), signature));
            strings.add("\n");
        });
        strings.add("=======================================\n");
        strings.add("\n");

        String outputPath = Argparse4j.getString(Argparse4j.OUTPUT_PATH);
        if (outputPath == null) {
            for (String s : strings) {
                System.out.printf(s);
            }
        } else {
            printToFile(outputPath, strings);
        }
    }

    private ArrayList<JSONObject> checkSchemeTypes(String callerName, JSONArray combinedContents, Object targetSchemeTypes, HashMap<JSONObject, JSONObject> foundLineMap) {
        JSONArray cipherSignatures = new JSONArray(Arrays.asList("<javax.crypto.Cipher: byte[] doFinal(byte[])>", "<javax.crypto.Cipher: byte[] doFinal(byte[],int,int)>", "<javax.crypto.Cipher: int doFinal(byte[],int)>", "<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[])>", "<javax.crypto.Cipher: int doFinal(byte[],int,int,byte[],int)>"));
        JSONArray macSignatures = new JSONArray(Arrays.asList("<javax.crypto.Mac: void update(byte[])>", "<javax.crypto.Mac: void update(byte[],int,int)>", "<javax.crypto.Mac: void update(java.nio.ByteBuffer)>", "<javax.crypto.Mac: byte[] doFinal(byte[])>", "<javax.crypto.Mac: void doFinal(byte[],int)"));
        HashMap<JSONObject, JSONObject> foundLineMap1 = checkSignatures(combinedContents, cipherSignatures);
        HashMap<JSONObject, JSONObject> foundLineMap2 = checkSignatures(combinedContents, macSignatures);
        if (!foundLineMap1.isEmpty() && !foundLineMap2.isEmpty()) {
            foundLineMap.putAll(foundLineMap1);
            foundLineMap.putAll(foundLineMap2);
        }

        ArrayList<JSONObject> foundLines = new ArrayList<>();
        foundLines.addAll(foundLineMap1.keySet());
        foundLines.addAll(foundLineMap2.keySet());

        if (targetSchemeTypes == null) {
            return (foundLineMap1.isEmpty() || foundLineMap2.isEmpty()) ? null : foundLines;
        }

        ArrayList<String> callerParameters = findCallerParameters(callerName, combinedContents);
        List<Object> schemeTypes = arrayToList(targetSchemeTypes);
        String schemeType = checkSchemeTypes(foundLineMap1, foundLineMap2, callerParameters);

        return schemeTypes.contains(schemeType) ? foundLines : null;
    }

    private JSONObject checkAlgorithms(String ruleName, JSONArray combinedContents, Object targetAlgorithms, HashMap<JSONObject, JSONObject> foundLineMap) {
        if (targetAlgorithms == null) {
            return null;
        }

        HashMap<JSONObject, JSONObject> foundLineMap1 = checkAlgorithms(combinedContents, targetAlgorithms);
        HashMap<JSONObject, JSONObject> foundLineMap2 = checkAlgorithms(combinedContents, secureAlgorithms);
        foundLineMap.putAll(foundLineMap1);
        foundLineMap.putAll(foundLineMap2);

        JSONObject lastLine = findLastLine(foundLineMap1, foundLineMap2);

        return getResultLine(ruleName, foundLineMap1, foundLineMap2, lastLine);
    }

    private JSONObject checkSignatures(String ruleName, JSONArray combinedContents, Object targetSignatures, HashMap<JSONObject, JSONObject> foundLineMap) {
        if (targetSignatures == null) {
            return null;
        }

        HashMap<JSONObject, JSONObject> foundLineMap1 = checkSignatures(combinedContents, targetSignatures);
        HashMap<JSONObject, JSONObject> foundLineMap2 = checkSignatures(combinedContents, randomSignatures);
        foundLineMap.putAll(foundLineMap1);
        foundLineMap.putAll(foundLineMap2);

        JSONObject lastLine = findLastLine(foundLineMap1, foundLineMap2);

        return getResultLine(ruleName, foundLineMap1, foundLineMap2, lastLine);
    }

    private JSONObject checkConstant(String ruleName, JSONArray combinedContents, Object targetConstRegex, Object targetConstLen, Object targetConstSize, HashMap<JSONObject, JSONObject> foundLineMap) {
        if (targetConstRegex == null) {
            return null;
        }

        HashMap<JSONObject, JSONObject> foundLineMap1 = checkConstant(combinedContents, targetConstRegex, targetConstLen, targetConstSize);
        HashMap<JSONObject, JSONObject> foundLineMap2 = checkSignatures(combinedContents, randomSignatures);
        foundLineMap.putAll(foundLineMap1);
        foundLineMap.putAll(foundLineMap2);

        JSONObject lastLine = findLastLine(foundLineMap1, foundLineMap2);

        return getResultLine(ruleName, foundLineMap1, foundLineMap2, lastLine);
    }

    private JSONObject checkArray(String ruleName, JSONArray combinedContents, Object targetConstRegex, Object targetConstLen, Object targetConstSize, HashMap<JSONObject, JSONObject> foundLineMap) {
        if (targetConstRegex == null || !targetConstRegex.equals(".*")) {
            return null;
        }

        HashMap<JSONObject, JSONObject> foundLineMap1 = checkArray(combinedContents, targetConstLen, targetConstSize);
        HashMap<JSONObject, JSONObject> foundLineMap2 = checkSignatures(combinedContents, randomSignatures);
        foundLineMap.putAll(foundLineMap1);
        foundLineMap.putAll(foundLineMap2);

        JSONObject lastLine = findLastLine(foundLineMap1, foundLineMap2);

        return getResultLine(ruleName, foundLineMap1, foundLineMap2, lastLine);
    }

    private ArrayList<String> findCallerParameters(String targetCallerName, JSONArray combinedContents) {
        ArrayList<String> parameters = new ArrayList<>();

        for (int i = combinedContents.length() - 1; i > 0; i--) {
            JSONObject line = combinedContents.getJSONObject(i);
            String callerName = line.getString(CALLER_NAME);
            if (!targetCallerName.equals(callerName)) {
                continue;
            }

            int unitType = line.getInt(UNIT_TYPE);
            if (unitType != PARAMETER) {
                continue;
            }

            String unitString = line.getString(UNIT_STRING);
            String leftOpStr = getLeftOpStr(unitString, unitType);
            parameters.add(leftOpStr);
        }

        return parameters;
    }

    private String checkSchemeTypes(HashMap<JSONObject, JSONObject> foundLineMap1, HashMap<JSONObject, JSONObject> foundLineMap2, ArrayList<String> callerParameters) {
        if (foundLineMap1.isEmpty() || foundLineMap2.isEmpty()) {
            return null;
        }

        JSONObject line1 = getJSONObject(foundLineMap1.keySet());
        String unitString1 = line1.getString(UNIT_STRING);
        String signature1 = getSignature(unitString1);
        String className1 = getClassName(signature1);
        ArrayList<String> parameters1 = getParameters(unitString1);
        int unitType1 = line1.getInt(UNIT_TYPE);

        JSONObject line2 = getJSONObject(foundLineMap2.keySet());
        String unitString2 = line2.getString(UNIT_STRING);
        ArrayList<String> parameters2 = getParameters(unitString2);

        String leftOpStr = getLeftOpStr(unitString1, unitType1);
        if (callerParameters.contains(leftOpStr) || parameters2.contains(leftOpStr)) {
            return className1.equals("javax.crypto.Cipher") ? ENCRYPT_THEN_MAC : MAC_THEN_ENCRYPT;
        }

        callerParameters.retainAll(parameters2);
        parameters1.retainAll(parameters2);

        return (callerParameters.isEmpty() && parameters1.isEmpty()) ? null : ENCRYPT_AND_MAC;
    }

    private HashMap<JSONObject, JSONObject> checkAlgorithms(JSONArray combinedContents, Object targetAlgorithms) {
        HashMap<JSONObject, JSONObject> foundLineMap = new HashMap<>();
        if (targetAlgorithms == null) {
            return foundLineMap;
        }

        JSONArray algorithms = (targetAlgorithms instanceof JSONObject) ? ((JSONObject) targetAlgorithms).getJSONArray(TARGET_ALGORITHMS) : (JSONArray) targetAlgorithms;

        for (int i = combinedContents.length() - 1; i > -1; i--) {
            JSONObject line = combinedContents.getJSONObject(i);
            String unitString = line.getString(UNIT_STRING);
            int unitType = line.getInt(UNIT_TYPE);

            LinkedHashSet<JSONObject> slices = new LinkedHashSet<>();

            if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unitString);

                List<String> query = List.of(String.format("%s==%s", CALLER_NAME, signature), String.format("%s==%s", TARGET_STATEMENT, "return"));
                for (JSONObject s : sliceDatabase.selectAll(query)) {
                    String nodeId = s.getString(NODE_ID);
                    slices.addAll(getSlices(nodeId));
                }
            } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                String signature = getSignature(unitString);
                List<String> query = List.of(String.format("%s==%s", TARGET_STATEMENT, signature));
                for (JSONObject s : sliceDatabase.selectAll(query)) {
                    String nodeId = s.getString(NODE_ID);
                    slices.addAll(getSlices(nodeId));
                }
            }

            for (JSONObject s : slices) {
                JSONArray contents = s.getJSONArray(CONTENTS);
                if (isJSONArrayARetainsAll(combinedContents, contents)) {
                    continue;
                }

                JSONObject foundLine = checkAlgorithms(contents, algorithms);
                if (foundLine != null) {
                    foundLineMap.put(foundLine, line);
                    return foundLineMap;
                }
            }

            ArrayList<String> strings = getStrings(unitString, unitType);
            if (hasTargetAlgorithm(strings, algorithms)) {
                foundLineMap.put(line, line);
                return foundLineMap;
            }
        }

        return foundLineMap;
    }

    private HashMap<JSONObject, JSONObject> checkSignatures(JSONArray combinedContents, Object targetSignatures) {
        HashMap<JSONObject, JSONObject> foundLineMap = new HashMap<>();
        if (targetSignatures == null) {
            return foundLineMap;
        }

        List<Object> signatures = arrayToList(targetSignatures);

        for (int i = combinedContents.length() - 1; i > -1; i--) {
            JSONObject line = combinedContents.getJSONObject(i);
            String unitString = line.getString(UNIT_STRING);
            int unitType = line.getInt(UNIT_TYPE);
            LinkedHashSet<JSONObject> slices = new LinkedHashSet<>();

            if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unitString);
                ArrayList<Integer> targetParamNumbers = programSlicer.getRetainParamNumbers(unitString);
                if (signatures.contains(signature) && targetParamNumbers != null) {
                    foundLineMap.put(line, line);
                    return foundLineMap;
                }

                List<String> query = List.of(String.format("%s==%s", CALLER_NAME, signature), String.format("%s==%s", TARGET_STATEMENT, "return"));
                for (JSONObject s : sliceDatabase.selectAll(query)) {
                    String nodeId = s.getString(NODE_ID);
                    slices.addAll(getSlices(nodeId));
                }
            } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                String signature = getSignature(unitString);
                List<String> query = List.of(String.format("%s==%s", TARGET_STATEMENT, signature));
                for (JSONObject s : sliceDatabase.selectAll(query)) {
                    String nodeId = s.getString(NODE_ID);
                    slices.addAll(getSlices(nodeId));
                }
            }

            for (JSONObject s : slices) {
                JSONArray contents = s.getJSONArray(CONTENTS);
                if (isJSONArrayARetainsAll(combinedContents, contents)) {
                    continue;
                }

                JSONObject lowerLine1 = checkSignatures(contents, signatures);
                if (lowerLine1 != null) {
                    foundLineMap.put(lowerLine1, line);
                    return foundLineMap;
                }
            }
        }

        return foundLineMap;
    }

    private HashMap<JSONObject, JSONObject> checkConstant(JSONArray combinedContents, Object targetConstRegex, Object targetConstLen, Object targetConstSize) {
        HashMap<JSONObject, JSONObject> foundLineMap = new HashMap<>();
        if (targetConstRegex == null) {
            return foundLineMap;
        }

        String regex = (String) targetConstRegex;
        String lenExpr = (targetConstLen == null) ? null : (String) targetConstLen;
        String sizeExpr = (targetConstSize == null) ? null : (String) targetConstSize;

        for (int i = combinedContents.length() - 1; i > -1; i--) {
            JSONObject line = combinedContents.getJSONObject(i);
            String unitString = line.getString(UNIT_STRING);
            int unitType = line.getInt(UNIT_TYPE);

            LinkedHashSet<JSONObject> slices = new LinkedHashSet<>();
            if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unitString);
                String className = getClassName(signature);
                String returnType = getReturnType(signature);

                List<String> query = List.of(String.format("%s==%s", CALLER_NAME, signature));
                for (JSONObject s : sliceDatabase.selectAll(query)) {
                    String nodeId = s.getString(NODE_ID);
                    slices.addAll(getSlices(nodeId));
                }

                if (lenExpr == null && sizeExpr == null && slices.isEmpty() && !apkParser.isBuiltInClassName(className) && (returnType.equals("int") || returnType.equals("java.lang.String"))) {
                    foundLineMap.put(line, line);
                    return foundLineMap;
                } else if (checkConstant(line, regex, lenExpr, sizeExpr)) {
                    foundLineMap.put(line, line);
                    return foundLineMap;
                }
            } else if (unitType == ASSIGN_VARIABLE_CONSTANT) {
                if (checkConstant(line, regex, lenExpr, sizeExpr)) {
                    foundLineMap.put(line, line);
                    return foundLineMap;
                }
            } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                String signature = getSignature(unitString);
                List<String> query = List.of(String.format("%s==%s", TARGET_STATEMENT, signature));
                for (JSONObject s : sliceDatabase.selectAll(query)) {
                    String nodeId = s.getString(NODE_ID);
                    slices.addAll(getSlices(nodeId));
                }
            }

            for (JSONObject s : slices) {
                JSONArray contents = s.getJSONArray(CONTENTS);
                if (isJSONArrayARetainsAll(combinedContents, contents)) {
                    continue;
                }

                JSONObject lowerLine = checkConstant(contents, regex, lenExpr, sizeExpr);
                if (lowerLine != null) {
                    foundLineMap.put(lowerLine, line);
                    return foundLineMap;
                }
            }
        }

        return foundLineMap;
    }

    private HashMap<JSONObject, JSONObject> checkArray(JSONArray combinedContents, Object targetConstLen, Object targetConstSize) {
        String lenExpr = (targetConstLen == null) ? (targetConstSize == null) ? null : (String) targetConstSize : (String) targetConstLen;
        HashMap<JSONObject, JSONObject> foundLineMap = new HashMap<>();

        for (int i = combinedContents.length() - 1; i > -1; i--) {
            JSONObject line = combinedContents.getJSONObject(i);
            String unitString = line.getString(UNIT_STRING);
            int unitType = line.getInt(UNIT_TYPE);

            LinkedHashSet<JSONObject> slices = new LinkedHashSet<>();
            if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unitString);
                List<String> query = List.of(String.format("%s==%s", CALLER_NAME, signature), String.format("%s==%s", TARGET_STATEMENT, "return"));
                for (JSONObject s : sliceDatabase.selectAll(query)) {
                    String nodeId = s.getString(NODE_ID);
                    slices.addAll(getSlices(nodeId));
                }
            } else if (unitType == NEW_ARRAY) {
                if (isTargetArrayLine(line, lenExpr)) {
                    foundLineMap.put(line, line);
                    return foundLineMap;
                }
            } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                String signature = getSignature(unitString);
                List<String> query = List.of(String.format("%s==%s", TARGET_STATEMENT, signature));
                for (JSONObject s : sliceDatabase.selectAll(query)) {
                    String nodeId = s.getString(NODE_ID);
                    slices.addAll(getSlices(nodeId));
                }
            }

            for (JSONObject s : slices) {
                JSONArray contents = s.getJSONArray(CONTENTS);
                if (isJSONArrayARetainsAll(combinedContents, contents)) {
                    continue;
                }

                if (isTargetArrayLines(contents, lenExpr)) {
                    foundLineMap.put(contents.getJSONObject(0), line);
                    return foundLineMap;
                }

                JSONObject lowerLine = findArrayLine(contents, lenExpr);
                if (lowerLine != null) {
                    foundLineMap.put(lowerLine, line);
                    return foundLineMap;
                }
            }
        }

        return foundLineMap;
    }

    private JSONObject checkAlgorithms(JSONArray contents, JSONArray algorithms) {
        for (int i = contents.length() - 1; i > -1; i--) {
            JSONObject line = contents.getJSONObject(i);
            String unitString = line.getString(UNIT_STRING);
            int unitType = line.getInt(UNIT_TYPE);

            if ((unitType & INVOKE) == INVOKE) {
                String signature = getSignature(unitString);
                String className = getClassName(signature);
                String methodName = getMethodName(signature);
                if (className.equals("javax.crypto.spec.SecretKeySpec") && methodName.equals("<init>")) {
                    continue;
                }
            }

            ArrayList<String> strings = getStrings(unitString, unitType);

            if (hasTargetAlgorithm(strings, algorithms)) {
                return line;
            }
        }

        return null;
    }

    private JSONObject checkSignatures(JSONArray contents, List<Object> targetSignatures) {
        JSONObject result = null;

        for (int i = contents.length() - 1; i >= 0; i--) {
            JSONObject line = contents.getJSONObject(i);
            int unitType = line.getInt(UNIT_TYPE);
            if ((unitType & INVOKE) != INVOKE) {
                continue;
            }

            String unitString = line.getString(UNIT_STRING);
            String signature = getSignature(unitString);
            if (targetSignatures.contains(signature)) {
                result = line;
                break;
            }
        }

        return result;
    }

    private JSONObject checkConstant(JSONArray contents, String regex, String lenExpr, String sizeExpr) {
        for (int i = contents.length() - 1; i > -1; i--) {
            JSONObject line = contents.getJSONObject(i);
            if (checkConstant(line, regex, lenExpr, sizeExpr)) {
                return line;
            }
        }

        return null;
    }

    private boolean checkConstant(JSONObject line, String regex, String lenExpr, String sizeExpr) {
        Pattern targetPattern = Pattern.compile(regex);
        int unitType = line.getInt(UNIT_TYPE);
        String unitString = line.getString(UNIT_STRING);

        ArrayList<String> strings = new ArrayList<>();
        if ((unitType & INVOKE) == INVOKE) {
            ArrayList<Integer> targetParamNumbers = programSlicer.getRetainParamNumbers(unitString);
            ArrayList<String> parameters = getParameters(unitString);
            if (targetParamNumbers.isEmpty() || (targetParamNumbers.size() > 1 && targetParamNumbers.contains(-1))) {
                return false;
            } else if ((targetParamNumbers.size() == 1 && targetParamNumbers.contains(-1))) {
                strings.addAll(parameters);
            } else {
                parameters.forEach(s -> {
                    if (targetParamNumbers.contains(parameters.indexOf(s))) {
                        strings.add(s);
                    }
                });
            }
        } else if (unitType == ASSIGN_VARIABLE_CONSTANT || unitType == RETURN_VALUE) {
            String rightOpStr = getRightOpStr(unitString, unitType);
            strings.add(rightOpStr);
        }

        for (String s : strings) {
            if (isVariableStr(s)) {
                continue;
            }

            boolean isNumber = isNumber(s);
            if (s.toLowerCase().endsWith("f") && isNumber) {
                s = String.valueOf((int) Double.parseDouble(s));
            }

            if (s.isEmpty() || s.equals("null")) {
                continue;
            }

            Matcher matcher = targetPattern.matcher(s);
            if (!matcher.matches()) {
                continue;
            }

            if (isAlgorithm(s)) {
                continue;
            }

            if (regex.equals(".*") && sizeExpr == null && isNumber) {
                continue;
            }

            if (lenExpr == null && sizeExpr == null) {
                return true;
            }

            if (lenExpr != null) {
                s = String.valueOf(s.length());
            } else {
                RSAKey rsaKey = convertToRSAKey(s);

                if (rsaKey == null) {
                    s = (isNumber) ? s : String.valueOf(s.length());
                } else {
                    BigInteger modulus = rsaKey.getModulus();
                    int bitLength = modulus.bitLength();
                    s = String.valueOf(bitLength);
                }
            }

            String expressionString = (lenExpr == null) ? sizeExpr : lenExpr;
            if (calculateExpression("x=" + s, expressionString) == 1) {
                return true;
            }
        }

        return false;
    }

    private List<Object> arrayToList(Object o) {
        return ((JSONArray) o).toList();
    }

    private ArrayList<String> getStrings(String unitString, int unitType) {
        ArrayList<String> strings = new ArrayList<>();

        if ((unitType & INVOKE) == INVOKE) {
            ArrayList<String> parameters = getParameters(unitString);
            strings.addAll(parameters);
        } else if (unitType == ASSIGN_VARIABLE_CONSTANT) {
            String rightOpStr = getRightOpStr(unitString, unitType);
            strings.add(rightOpStr);
        } else if (unitType == RETURN_VALUE) {
            String rightOpStr = getRightOpStr(unitString, unitType);
            strings.add(rightOpStr);
        }

        return strings;
    }

    private boolean hasTargetAlgorithm(ArrayList<String> strings, JSONArray targetAlgorithms) {
        int count = targetAlgorithms.length();

        for (String s : strings) {
            String str = s.toUpperCase();
            if (!isAlgorithm(str)) {
                continue;
            }

            for (int j = 0; j < count; j++) {
                String algorithm = targetAlgorithms.getString(j);
                String[] strArr = algorithm.split("-");
                Pattern pattern = Pattern.compile("(?i)^(" + (algorithm.contains("-") ? strArr[0] : algorithm) + ")?(/.*)?$");
                Matcher matcher = pattern.matcher(str);
                if ((matcher.matches() && (!algorithm.contains("-") || !s.toLowerCase().contains(strArr[1].toLowerCase()))) || (str.contains("PBE") && str.contains(algorithm))) {
                    return true;
                }
            }
        }

        return false;
    }

    private JSONObject findArrayLine(JSONArray contents, String lenExpr) {
        for (int i = contents.length() - 1; i > -1; i--) {
            JSONObject line = contents.getJSONObject(i);
            int unitType = line.getInt(UNIT_TYPE);
            if (unitType != NEW_ARRAY) {
                continue;
            }

            if (isTargetArrayLine(line, lenExpr)) {
                return line;
            }
        }

        return null;
    }

    private boolean isTargetArrayLine(JSONObject line, String lenExpr) {
        String unitString = line.getString(UNIT_STRING);
        int unitType = line.getInt(UNIT_TYPE);
        String arraySize = getArraySize(unitString, unitType);
        if (isVariableStr(arraySize)) {
            return false;
        }

        return (lenExpr == null && isNumber(arraySize)) || (lenExpr != null && calculateExpression("x=" + arraySize, lenExpr) == 1);
    }

    private boolean isTargetArrayLines(JSONArray content, String lenExpr) {
        JSONObject line1 = content.getJSONObject(0);
        int unitType1 = line1.getInt(UNIT_TYPE);
        if (unitType1 != NEW_ARRAY) {
            return false;
        }

        JSONObject line2 = content.getJSONObject(1);
        JSONObject line3 = content.getJSONObject(content.length() - 1);
        int unitType2 = line2.getInt(UNIT_TYPE);
        int unitType3 = line3.getInt(UNIT_TYPE);

        return isTargetArrayLine(line1, lenExpr) && (unitType2 & ASSIGN_ARRAY) == ASSIGN_ARRAY && unitType3 == ASSIGN_SIGNATURE_VARIABLE;
    }

    private HashSet<String> getTargetKeys(JSONObject condition) {
        HashSet<String> keys = new HashSet<>();

        if (condition.has(TARGET_SCHEME_TYPES) || condition.has(REQUIRED_SCHEME_TYPES)) {
            keys.add(TARGET_SCHEME_TYPES);
        }

        if (condition.has(TARGET_ALGORITHMS)) {
            keys.add(TARGET_ALGORITHMS);
        }

        if (condition.has(TARGET_SIGNATURES)) {
            keys.add(TARGET_SIGNATURES);
        }

        if (condition.has(TARGET_CONSTANT_REGEX)) {
            keys.add(TARGET_CONSTANT_REGEX);
        }

        return keys;
    }

    private JSONObject getJSONObject(Set<JSONObject> set) {
        ArrayList<JSONObject> objects = new ArrayList<>(set);

        return objects.get(0);
    }

    private JSONObject getResultLine(String ruleName, HashMap<JSONObject, JSONObject> foundLineMap1, HashMap<JSONObject, JSONObject> foundLineMap2, JSONObject line) {
        if (ruleName.equals(INSECURE_RULE) && foundLineMap1 != null && (foundLineMap1.containsKey(line) || foundLineMap1.containsValue(line))) {
            return line;
        } else if (ruleName.equals(SECURE_RULE) && (foundLineMap1 != null || (foundLineMap2 != null && (foundLineMap2.containsKey(line) || foundLineMap2.containsValue(line))))) {
            return line;
        } else {
            return null;
        }
    }

    private ArrayList<JSONObject> getSlices(String nodeId) {
        ArrayList<JSONObject> slices = sliceMap.get(nodeId);
        if (slices == null) {
            slices = new ArrayList<>();
        } else {
            return slices;
        }

        ArrayList<String> queue = new ArrayList<>();
        queue.add(nodeId);

        while (!queue.isEmpty()) {
            String id = queue.remove(0);
            List<String> query = List.of(String.format("%s==%s", NODE_ID, id), String.format("%s!=null", CALLER_NAME));
            JSONObject slice = sliceDatabase.selectOne(query);
            if (slice == null) {
                continue;
            }

            if (slices.contains(slice)) {
                continue;
            } else {
                slices.add(slice);
            }

            JSONArray content = slice.getJSONArray(CONTENTS);
            for (int i = content.length() - 1; i > -1; i--) {
                JSONObject line = content.getJSONObject(i);
                String unitString = line.getString(UNIT_STRING);
                int unitType = line.getInt(UNIT_TYPE);

                if ((unitType & INVOKE) == INVOKE) {
                    String signature = getSignature(unitString);
                    List<String> query2 = List.of(String.format("%s==%s", CALLER_NAME, signature), String.format("%s==%s", TARGET_STATEMENT, "return"));
                    for (JSONObject s : sliceDatabase.selectAll(query2)) {
                        queue.add(s.getString(NODE_ID));
                    }
                } else if (unitType == ASSIGN_VARIABLE_SIGNATURE) {
                    String signature = getSignature(unitString);
                    List<String> query2 = List.of(String.format("%s==%s", TARGET_STATEMENT, signature));
                    for (JSONObject s : sliceDatabase.selectAll(query2)) {
                        queue.add(s.getString(NODE_ID));
                    }
                } else if (unitType == PARAMETER) {
                    String callerName = line.getString(CALLER_NAME);
                    List<String> query2 = List.of(String.format("%s==%s", TARGET_STATEMENT, callerName));
                    for (JSONObject s : sliceDatabase.selectAll(query2)) {
                        queue.add(s.getString(NODE_ID));
                    }
                }
            }
        }

        sliceMap.put(nodeId, slices);

        return slices;
    }

    private boolean isJSONArrayARetainsAll(JSONArray array1, JSONArray array2) {
        for (int i = 0; i < array1.length(); i++) {
            JSONObject obj1 = array1.getJSONObject(i);
            String unitString1 = obj1.getString(UNIT_STRING);
            int lineNumber1 = obj1.getInt(LINE_NUMBER);

            for (int j = 0; j < array2.length(); j++) {
                JSONObject obj2 = array2.getJSONObject(j);
                String unitString2 = obj2.getString(UNIT_STRING);
                int lineNumber2 = obj2.getInt(LINE_NUMBER);
                if (unitString1.equals(unitString2) && lineNumber1 == lineNumber2) {
                    return true;
                }
            }
        }

        return false;
    }

    private JSONObject findLastLine(HashMap<JSONObject, JSONObject> foundLineMap1, HashMap<JSONObject, JSONObject> foundLineMap2) {
        if (foundLineMap1 == null || foundLineMap1.isEmpty()) {
            return null;
        }

        JSONObject lowerLine1 = getJSONObject(foundLineMap1.keySet());
        if (foundLineMap2 == null || foundLineMap2.isEmpty()) {
            return lowerLine1;
        }

        JSONObject upperLine1 = foundLineMap1.get(lowerLine1);
        JSONObject lowerLine2 = getJSONObject(foundLineMap2.keySet());
        JSONObject upperLine2 = foundLineMap2.get(lowerLine2);

        if (lowerLine1.getString(CALLER_NAME).equals(lowerLine2.getString(CALLER_NAME))) {
            return (lowerLine1.getInt(LINE_NUMBER) > lowerLine2.getInt(LINE_NUMBER)) ? lowerLine1 : lowerLine2;
        } else if (upperLine1.getString(CALLER_NAME).equals(upperLine2.getString(CALLER_NAME))) {
            return (upperLine1.getInt(LINE_NUMBER) > upperLine2.getInt(LINE_NUMBER)) ? upperLine1 : upperLine2;
        }

        return null;
    }

    private RSAKey convertToRSAKey(String str) {
        String s = str.replace("\\r", "").replace("\\n", "");
        byte[] bytes = null;

        if (isBase64String(s)) {
            bytes = DatatypeConverter.parseBase64Binary(s);
        } else if (isHexString(s)) {
            s = (s.length() % 2 == 1) ? "0" + s : s;
            bytes = DatatypeConverter.parseHexBinary(s);
        }

        return (bytes == null) ? null : convertToRSAKey(bytes);
    }

    private RSAKey convertToRSAKey(byte[] bytes) {
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

    private boolean isBase64String(String str) {
        Matcher matcher = BASE64_PATTERN.matcher(str);

        return matcher.matches();
    }

    private boolean isHexString(String str) {
        Matcher matcher = HEX_PATTERN.matcher(str);

        return matcher.matches();
    }

    private static class SingletonHolder {
        private static final RuleChecker instance = new RuleChecker();
    }
}