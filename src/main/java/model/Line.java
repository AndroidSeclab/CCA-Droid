package model;

import soot.Unit;

public class Line implements Comparable<Line>, Cloneable {
    private Unit unit;
    private int unitType;
    private String callerName;
    private int lineNumber;

    public Unit getUnit() {
        return unit;
    }

    public void setUnit(Unit unit) {
        this.unit = unit;
    }

    public int getUnitType() {
        return unitType;
    }

    public void setUnitType(int unitType) {
        this.unitType = unitType;
    }

    public String getCallerName() {
        return callerName;
    }

    public void setCallerName(String callerName) {
        this.callerName = callerName;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(int lineNumber) {
        this.lineNumber = lineNumber;
    }

    @Override
    public String toString() {
        return "Line{unit=" + unit + ", callerName=" + callerName + ", lineNumber=" + lineNumber + "}";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj == null || getClass() != obj.getClass()) {
            return false;
        } else {
            return toString().equals(obj.toString());
        }
    }

    @Override
    public int hashCode() {
        return 31 + ((toString().equals("")) ? 0 : toString().hashCode());
    }

    @Override
    public int compareTo(Line o) {
        String location1 = this.callerName;
        String location2 = o.getCallerName();
        if (!location1.equals(location2)) {
            return 0;
        }

        int number1 = this.lineNumber;
        int number2 = o.getLineNumber();
        return Integer.compare(number1, number2);
    }

    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}