package com.ccadroid.util.soot;

import com.ccadroid.inspect.ApkParser;
import soot.Scene;
import soot.SootClass;
import soot.options.Options;
import soot.util.Chain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

public class Soot {

    private Soot() throws InstantiationException {
        throw new InstantiationException();
    }

    public static void initialize(String apkPath) {
        String sdkHomeDir = System.getenv("ANDROID_SDK_HOME");
        if (sdkHomeDir == null) {
            System.out.println("Please set ANDROID_SDK_HOME environment variable!");
            System.exit(1);
        }

        Options.v().set_process_multiple_dex(true);
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars(sdkHomeDir + "/" + "platforms");
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_full_resolver(true);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_ignore_resolving_levels(true);
    }

    public static void loadDexClasses() {
        ApkParser apkParser = ApkParser.getInstance();
        ArrayList<String> dexClassNames = apkParser.getDexClassNames();
        for (String s : dexClassNames) {
            try {
                Scene.v().loadClassAndSupport(s);
            } catch (NoClassDefFoundError | IllegalArgumentException ignored) {

            }
        }

        Scene.v().loadBasicClasses();
        Scene.v().loadNecessaryClasses();
    }

    public static boolean isInterfaceOf(String typeName, ArrayList<String> targetTypes) {
        SootClass class1 = getSootClass(typeName);
        Chain<SootClass> interfaces = class1.getInterfaces();
        Iterator<SootClass> iterator = interfaces.stream().iterator();

        while (iterator.hasNext()) {
            SootClass interfaceClass = iterator.next();
            String className = interfaceClass.getName();
            if (targetTypes.contains(className)) {
                return true;
            }
        }

        return false;
    }

    public static boolean isEnumClass(String className) {
        SootClass sootClass = getSootClass(className);

        return sootClass.isEnum();
    }

    public static SootClass getSootClass(String className) {
        return Scene.v().getSootClass(className);
    }
}