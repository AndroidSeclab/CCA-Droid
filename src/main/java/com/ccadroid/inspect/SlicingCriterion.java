package com.ccadroid.inspect;

import soot.Unit;
import soot.Value;

import java.util.ArrayList;
import java.util.Collection;

public class SlicingCriterion implements Cloneable {
    private String id;
    private String callerName;
    private String targetStatement;
    private int targetUnitIndex;
    private ArrayList<Integer> targetParamNumbers;
    private Collection<Value> targetVariables;
    private ArrayList<Unit> targetUnits;

    public String getId() {
        return (id == null) ? String.valueOf(hashCode()) : id;
    }

    public void setId(String id) {
        this.id = id;
    }

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

    public Collection<Value> getTargetVariables() {
        return targetVariables;
    }

    public void setTargetVariables(Collection<Value> targetVariables) {
        this.targetVariables = targetVariables;
    }

    public ArrayList<Unit> getTargetUnits() {
        return targetUnits;
    }

    public void setTargetUnits(ArrayList<Unit> targetUnits) {
        this.targetUnits = targetUnits;
    }

    @Override
    public int hashCode() {
        return callerName.hashCode() + targetStatement.hashCode() + targetUnitIndex + targetVariables.hashCode() + targetUnits.hashCode();
    }

    @Override
    public String toString() {
        return "SlicingCriterion{caller=" + callerName + ", targetSignature=" + targetStatement + ", targetVariableMap=" + targetVariables + "}";
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