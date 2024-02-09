package com.ccadroid.inspect;

import soot.Value;

import java.util.ArrayList;

public class SlicingCriterion {
    private String callerName;
    private String targetStatement;
    private int targetUnitIndex;
    private ArrayList<Integer> targetParamNumbers;
    private ArrayList<Value> targetVariables;

    public String getCallerName() {
        return callerName;
    }

    public void setCallerName(String callerName) {
        this.callerName = callerName;
    }

    public String getTargetStatement() {
        return targetStatement;
    }

    public void setTargetStatement(String targetStatement) {
        this.targetStatement = targetStatement;
    }

    public int getTargetUnitIndex() {
        return targetUnitIndex;
    }

    public void setTargetUnitIndex(int targetUnitIndex) {
        this.targetUnitIndex = targetUnitIndex;
    }

    public ArrayList<Integer> getTargetParamNumbers() {
        return targetParamNumbers;
    }

    public void setTargetParamNumbers(ArrayList<Integer> targetParamNumbers) {
        this.targetParamNumbers = targetParamNumbers;
    }

    public ArrayList<Value> getTargetVariables() {
        return targetVariables;
    }

    public void setTargetVariables(ArrayList<Value> targetVariables) {
        this.targetVariables = targetVariables;
    }

    @Override
    public int hashCode() {
        return callerName.hashCode() + targetStatement.hashCode() + targetUnitIndex + targetVariables.hashCode();
    }

    @Override
    public String toString() {
        return "SlicingCriterion{caller=" + callerName + ", targetSignature=" + targetStatement + ", targetVariables=" + targetVariables + "}";
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
}