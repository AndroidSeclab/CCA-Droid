package com.ccadroid.util.soot;

import soot.*;
import soot.jimple.*;
import soot.options.Options;
import soot.tagkit.ConstantValueTag;
import soot.tagkit.Tag;
import soot.util.Chain;

import java.util.*;

import static com.ccadroid.util.soot.SootUnit.getClassName;
import static com.ccadroid.util.soot.SootUnit.getSubSignature;

public class Soot {

    public Soot() throws InstantiationException {
        throw new InstantiationException();
    }

    public static void initialize(String apkPath, String platformDir) {
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_android_jars(platformDir);
        Options.v().set_full_resolver(true);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_ignore_resolving_levels(true);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_process_multiple_dex(true);
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_whole_program(true);
    }

    public static void loadDexClasses(ArrayList<String> dexClassNames) {
        for (String s : dexClassNames) {
            try {
                Scene.v().loadClassAndSupport(s);
            } catch (NoClassDefFoundError | IllegalArgumentException ignored) {

            }
        }

        Scene.v().loadBasicClasses();
        Scene.v().loadNecessaryClasses();
    }

    public static String join(String delimiter, String... elements) {
        return String.join(delimiter, elements);
    }

    public static SootClass getSootClass(String className) {
        return Scene.v().getSootClass(className);
    }

    public static boolean isEnumClass(String className) {
        SootClass sootClass = getSootClass(className);

        return sootClass.isEnum();
    }

    public static String getInterfaceMethodName(String className, String subSignature) {
        SootClass sootClass = getSootClass(className);
        Chain<SootClass> interfaces = sootClass.getInterfaces();

        for (SootClass c : interfaces) {
            SootMethod m = getSootMethod(c, subSignature);
            if (m != null) {
                return m.toString();
            }
        }

        return null;
    }

    public static SootMethod getSootMethod(String signature) {
        String className = getClassName(signature);
        SootClass sootClass = getSootClass(className);
        String subSignature = getSubSignature(signature);

        return getSootMethod(sootClass, subSignature);
    }

    public static boolean hasInterface(String className, String targetClassName) {
        SootClass sootClass = getSootClass(className);
        Chain<SootClass> interfaces = sootClass.getInterfaces();

        return hasInterface(interfaces, targetClassName);
    }

    public static ArrayList<Unit> getUnits(SootMethod sootMethod) {
        ArrayList<Unit> units = new ArrayList<>();

        if (sootMethod == null || sootMethod.isJavaLibraryMethod() || !sootMethod.isConcrete()) {
            return units;
        }

        Body body = sootMethod.retrieveActiveBody();
        units.addAll(body.getUnits());

        return units;
    }

    public static ArrayList<Unit> getUnits(String signature) {
        String className = getClassName(signature);
        SootClass sootClass = getSootClass(className);
        String subSignature = getSubSignature(signature);
        SootMethod sootMethod = getSootMethod(sootClass, subSignature);

        return getUnits(sootMethod);
    }

    public static Chain<Local> getLocals(SootMethod sootMethod) {
        Body body = sootMethod.retrieveActiveBody();

        return body.getLocals();
    }

    public static HashMap<String, Value> getStaticFinalValueMap(SootClass sootClass) {
        Chain<SootField> fields = sootClass.getFields();
        HashMap<String, Value> map = new HashMap<>();

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

            String tagStr = tag.toString();
            StringTokenizer tokenizer = new StringTokenizer(tagStr);
            int length = tokenizer.countTokens();
            String key = f.getSignature();
            Value value;

            if (length > 1) {
                tokenizer.nextToken();
                String returnType = getReturnType(key);
                value = convertToValue(returnType, tokenizer.nextToken());
            } else {
                value = StringConstant.v("");
            }

            map.putIfAbsent(key, value);
        }

        return map;
    }

    public static Value convertToValue(String targetType, String str) {
        if (str.equals("null")) {
            return NullConstant.v();
        }

        Value value = null;
        switch (targetType) {
            case "boolean":
            case "short":
            case "int": {
                value = IntConstant.v(Integer.parseInt(str));
                break;
            }

            case "double": {
                if (str.contains("NaN")) {
                    value = DoubleConstant.v(Double.NaN);
                } else if (str.contains("Infinity")) {
                    value = (str.contains("-")) ? DoubleConstant.v(Double.NEGATIVE_INFINITY) : DoubleConstant.v(Double.POSITIVE_INFINITY);
                } else {
                    value = DoubleConstant.v(Double.parseDouble(str));
                }

                break;
            }

            case "long": {
                String s = str.replace("L", "");
                value = LongConstant.v(Long.parseLong(s));
                break;
            }

            case "float": {
                String s = str.replace("F", "");
                if (s.contains("NaN")) {
                    value = FloatConstant.v(Float.NaN);
                } else if (s.contains("Infinity")) {
                    value = (s.contains("-")) ? FloatConstant.v(Float.NEGATIVE_INFINITY) : FloatConstant.v(Float.POSITIVE_INFINITY);
                } else {
                    value = FloatConstant.v(Float.parseFloat(s));
                }

                break;
            }

            case "char":
            case "byte":
            case "java.lang.String": {
                String s = str.replace("\"", "");
                value = StringConstant.v(s);
                break;
            }

            default: {
                break;
            }
        }

        return value;
    }

    private static boolean hasInterface(Chain<SootClass> interfaces, String targetClassName) {
        for (SootClass c : interfaces) {
            if (c.getName().startsWith(targetClassName) || c.getName().equals(targetClassName)) {
                return true;
            }
        }

        return false;
    }

    private static SootMethod getSootMethod(SootClass sootClass, String subSignature) {
        List<SootMethod> sootMethods = sootClass.getMethods();
        for (SootMethod m : sootMethods) {
            if (m.getSubSignature().equals(subSignature)) {
                return m;
            }
        }

        return null;
    }

    private static String getReturnType(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        tokenizer.nextToken();

        return tokenizer.nextToken();
    }
}