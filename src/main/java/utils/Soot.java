package utils;

import analyze.ApkParser;
import soot.*;
import soot.options.Options;
import soot.util.Chain;

import java.util.ArrayList;

import static java.util.Collections.singletonList;

public class Soot {

    public static void initialize(String apkPath) {
        String sdkHomeDirStr = System.getenv("ANDROID_SDK_HOME");
        if (sdkHomeDirStr == null) {
            System.err.println("Please set ANDROID_SDK_HOME!");
            System.exit(1);
        }

        Options.v().set_process_multiple_dex(true);
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars(sdkHomeDirStr + "/" + "platforms");
        Options.v().set_process_dir(singletonList(apkPath));
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

    public static boolean isSuperClassOf(String childClassName, String parentClassName) {
        Hierarchy hierarchy = Scene.v().getActiveHierarchy();
        SootClass childClass = Scene.v().getSootClass(childClassName);
        SootClass parentClass = Scene.v().getSootClass(parentClassName);

        return hierarchy.isClassSuperclassOf(parentClass, childClass);
    }

    public static Local findLocal(String signature, String variableName) {
        Local local = null;

        SootMethod sootMethod = Scene.v().getMethod(signature);
        Body body = sootMethod.getActiveBody();
        Chain<Local> locals = body.getLocals();
        for (Local l: locals) {
            String name = l.getName();
            if (name.equals(variableName)) {
                local = l;
                break;
            }
        }

        return local;
    }

    private Soot() throws InstantiationException {
        throw new InstantiationException();
    }
}