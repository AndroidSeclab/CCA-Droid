package com.ccadroid;

import com.ccadroid.check.RuleChecker;
import com.ccadroid.inspect.ApkParser;
import com.ccadroid.inspect.CodeInspector;
import com.ccadroid.inspect.SlicingCriteriaGenerator;
import com.ccadroid.inspect.SlicingCriterion;
import com.ccadroid.slice.ProgramSlicer;
import com.ccadroid.slice.SliceMerger;
import com.ccadroid.util.Argparse4j;
import com.ccadroid.util.soot.Soot;

import java.util.ArrayList;

public class EngineMain {

    public static void main(String[] args) {
        Argparse4j.setArguments(args);
        String apkPath = Argparse4j.getString(Argparse4j.INPUT_PATH);
        String platformDir = Argparse4j.getString(Argparse4j.PLATFORMS_PATH);

        ApkParser apkParser = ApkParser.getInstance();
        apkParser.loadAPKFile(apkPath);
        apkParser.parseManifest();
        ArrayList<String> dexClassNames = apkParser.getDexClassNames();

        Soot.initialize(apkPath, platformDir);
        Soot.loadDexClasses(dexClassNames);

        CodeInspector codeInspector = CodeInspector.getInstance();
        codeInspector.buildCallGraph();

        SlicingCriteriaGenerator slicingCriteriaGenerator = SlicingCriteriaGenerator.getInstance();
        ProgramSlicer programSlicer = ProgramSlicer.getInstance();
        SliceMerger sliceMerger = SliceMerger.getInstance();
        RuleChecker ruleChecker = RuleChecker.getInstance();

        ArrayList<SlicingCriterion> slicingCriteria = slicingCriteriaGenerator.createSlicingCriteria();
        for (SlicingCriterion sc : slicingCriteria) {
            programSlicer.sliceStatements(sc);
            sliceMerger.mergeSlices(sc);
            ruleChecker.checkRules(sc);
        }
    }
}