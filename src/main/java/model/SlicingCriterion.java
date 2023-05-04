package model;

import org.graphstream.graph.Node;
import soot.Unit;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.StringTokenizer;

public class SlicingCriterion implements Cloneable, Comparable<SlicingCriterion> {
    private Node caller;
    private Node caller2;
    private String targetStatement1;
    private String targetStatement2;
    private ArrayList<String> targetParamNums;
    private int targetUnitIndex;
    private ArrayList<String> targetVariables;

    private ArrayList<Unit> wholeUnits;
    private ArrayList<Unit> partialUnits;
    private HashMap<Integer, ArrayList<Unit>> switchTargetsMap;
    private ArrayList<Unit> targetGotoUnits;
    private ArrayList<String> targetParamValues;

    private HashSet<String> callerNames;
    private ArrayList<Unit> targetUnits;
    private ArrayList<String> unitStrings;
    private ArrayList<Unit> targetIfUnits;
    private ArrayList<String> uselessVariables;
    private boolean isInSwitch;
    private ArrayList<String> nextParamNums;

    public SlicingCriterion() {
        targetUnits = new ArrayList<>();
        unitStrings = new ArrayList<>();
        targetIfUnits = new ArrayList<>();
        uselessVariables = new ArrayList<>();
        nextParamNums = new ArrayList<>();
    }

    public Node getCaller() {
        return caller;
    }

    public void setCaller(Node caller) {
        this.caller = caller;
    }

    public Node getCaller2() {
        return caller2;
    }

    public void setCaller2(Node caller2) {
        this.caller2 = caller2;
    }

    public String getTargetStatement1() {
        return targetStatement1;
    }

    public void setTargetStatement1(String targetStatement1) {
        this.targetStatement1 = targetStatement1;
    }

    public String getTargetStatement2() {
        return targetStatement2;
    }

    public void setTargetStatement2(String targetStatement2) {
        this.targetStatement2 = targetStatement2;
    }

    public ArrayList<String> getTargetParamNums() {
        return targetParamNums;
    }

    public void setTargetParamNums(String str) {
        ArrayList<String> paramNums = new ArrayList<>();

        StringTokenizer tokenizer = new StringTokenizer(str, ",");
        while (tokenizer.hasMoreTokens()) {
            String s = tokenizer.nextToken().trim();
            paramNums.add(s);
        }

        setTargetParamNums(paramNums);
    }

    public void setTargetParamNums(ArrayList<String> targetParamNums) {
        this.targetParamNums = targetParamNums;
    }

    public String getTargetParamNum() {
        return (targetVariables == null) ? null : targetParamNums.get(0);
    }

    public int getTargetUnitIndex() {
        return targetUnitIndex;
    }

    public void setTargetUnitIndex(int targetUnitIndex) {
        this.targetUnitIndex = targetUnitIndex;
    }

    public ArrayList<String> getTargetVariables() {
        return targetVariables;
    }

    public void setTargetVariables(ArrayList<String> targetVariables) {
        this.targetVariables = targetVariables;
    }

    public ArrayList<Unit> getWholeUnits() {
        return wholeUnits;
    }

    public void setWholeUnits(ArrayList<Unit> wholeUnits) {
        this.wholeUnits = wholeUnits;
    }

    public ArrayList<Unit> getPartialUnits() {
        return partialUnits;
    }

    public void setPartialUnits(ArrayList<Unit> partialUnits) {
        this.partialUnits = partialUnits;
    }

    public HashMap<Integer, ArrayList<Unit>> getSwitchTargetsMap() {
        return switchTargetsMap;
    }

    public void setSwitchTargetsMap(HashMap<Integer, ArrayList<Unit>> switchTargetsMap) {
        this.switchTargetsMap = switchTargetsMap;
    }

    public ArrayList<Unit> getTargetGotoUnits() {
        return targetGotoUnits;
    }

    public void setTargetGotoUnits(ArrayList<Unit> targetGotoUnits) {
        this.targetGotoUnits = targetGotoUnits;
    }

    public HashSet<String> getCallerNames() {
        return callerNames;
    }

    public void setCallerNames(HashSet<String> callerNames) {
        this.callerNames = callerNames;
    }

    public ArrayList<Unit> getTargetUnits() {
        return targetUnits;
    }

    public void setTargetUnits(ArrayList<Unit> targetUnits) {
        this.targetUnits = targetUnits;
    }

    public ArrayList<String> getUnitStrings() {
        return unitStrings;
    }

    public void setUnitStrings(ArrayList<String> unitStrings) {
        this.unitStrings = unitStrings;
    }

    public ArrayList<Unit> getTargetIfUnits() {
        return targetIfUnits;
    }

    public void setTargetIfUnits(ArrayList<Unit> targetIfUnits) {
        this.targetIfUnits = targetIfUnits;
    }

    public ArrayList<String> getUselessVariables() {
        return uselessVariables;
    }

    public void setUselessVariables(ArrayList<String> uselessVariables) {
        this.uselessVariables = uselessVariables;
    }

    public boolean isInSwitch() {
        return isInSwitch;
    }

    public void setInSwitch(boolean inSwitch) {
        isInSwitch = inSwitch;
    }

    public ArrayList<String> getTargetParamValues() {
        return targetParamValues;
    }

    public void setTargetParamValues(ArrayList<String> targetParamValues) {
        this.targetParamValues = targetParamValues;
    }

    public ArrayList<String> getNextParamNums() {
        return nextParamNums;
    }

    public void setNextParamNums(ArrayList<String> nextParamNums) {
        this.nextParamNums = nextParamNums;
    }

    @Override
    public int hashCode() {
        return wholeUnits.hashCode() + targetStatement1.hashCode() + ((targetVariables == null) ? 0 : targetVariables.hashCode()) + targetUnitIndex;
    }

    @Override
    public String toString() {
        return "SlicingCriterion{caller=" + caller + ", targetStatement=" + targetStatement1 + ", targetVariables=" + targetVariables + "}";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj == null || getClass() != obj.getClass()) {
            return false;
        } else {
            return hashCode() == (obj.hashCode());
        }
    }

    @Override
    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException ignored) {
            return null;
        }
    }

    @Override
    public int compareTo(SlicingCriterion o) {
        String callerName1 = this.getCaller().getId();
        String callerName2 = o.getCaller().getId();
        if (!callerName1.equals(callerName2)) {
            return 0;
        }

        int size1 = this.getPartialUnits().size();
        int size2 = o.getPartialUnits().size();
        return Integer.compare(size2, size1);
    }
}