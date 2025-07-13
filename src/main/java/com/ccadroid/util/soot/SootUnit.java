package com.ccadroid.util.soot;

import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.ccadroid.util.OpenCSV.convertToList;

public class SootUnit {
    public static final int INVOKE = 0x00010000;
    public static final int VIRTUAL_INVOKE = INVOKE | 0x0001;
    public static final int STATIC_INVOKE = INVOKE | 0x0002;
    public static final int INTERFACE_INVOKE = INVOKE | 0x0004;
    public static final int SPECIAL_INVOKE = INVOKE | 0x0008;
    public static final int ASSIGN = 0x00020000;
    public static final int ASSIGN_INVOKE = ASSIGN | INVOKE;
    public static final int ASSIGN_VIRTUAL_INVOKE = ASSIGN_INVOKE | VIRTUAL_INVOKE;
    public static final int ASSIGN_STATIC_INVOKE = ASSIGN_INVOKE | STATIC_INVOKE;
    public static final int ASSIGN_INTERFACE_INVOKE = ASSIGN_INVOKE | INTERFACE_INVOKE;
    public static final int ASSIGN_SPECIAL_INVOKE = ASSIGN_INVOKE | SPECIAL_INVOKE;
    public static final int IDENTITY = ASSIGN | 0x0100;
    public static final int PARAMETER = IDENTITY | 0x0001;
    public static final int CAUGHT_EXCEPTION = IDENTITY | 0x0002;
    public static final int NEW = ASSIGN | 0x0200;
    public static final int NEW_INSTANCE = NEW | 0x0001;
    public static final int NEW_ARRAY = NEW | 0x0002;
    public static final int NEW_EXCEPTION = NEW | 0x0004;
    public static final int ASSIGN_VARIABLE = ASSIGN | 0x0400;
    public static final int ASSIGN_VARIABLE_CONSTANT = ASSIGN_VARIABLE | 0x0001;
    public static final int ASSIGN_VARIABLE_VARIABLE = ASSIGN_VARIABLE | 0x0002;
    public static final int ASSIGN_VARIABLE_ARRAY = ASSIGN_VARIABLE | 0x0004;
    public static final int ASSIGN_VARIABLE_SIGNATURE = ASSIGN_VARIABLE | 0x0008;
    public static final int ASSIGN_VARIABLE_OPERATION = ASSIGN_VARIABLE | 0x0010;
    public static final int ASSIGN_ARRAY = ASSIGN | 0x0800;
    public static final int ASSIGN_ARRAY_CONSTANT = ASSIGN_ARRAY | 0x0001;
    public static final int ASSIGN_ARRAY_VARIABLE = ASSIGN_ARRAY | 0x0002;
    public static final int ASSIGN_SIGNATURE = ASSIGN | 0x1000;
    public static final int ASSIGN_SIGNATURE_CONSTANT = ASSIGN_SIGNATURE | 0x0001;
    public static final int ASSIGN_SIGNATURE_VARIABLE = ASSIGN_SIGNATURE | 0x0002;
    public static final int CAST = ASSIGN | 0x1000;
    public static final int LENGTH_OF = ASSIGN | 0x2000;
    public static final int INSTANCE_OF = ASSIGN | 0x4000;
    public static final int IF = 0x00040000;
    public static final int GOTO = 0x00080000;
    public static final int SWITCH = 0x00100000;
    public static final int RETURN = 0x00200000;
    public static final int RETURN_VALUE = RETURN | 0x0001;
    public static final int RETURN_VOID = RETURN | 0x0002;
    public static final int NOP = 0x00000000;
    private static final Pattern LOCAL_VARIABLE_PATTERN = Pattern.compile("[a-z]\\d{1,5}"); // ex: r0, https://www.brics.dk/SootGuide/sootsurvivorsguide.pdf
    private static final Pattern STACK_VARIABLE_PATTERN = Pattern.compile("\\$[a-z]\\d{1,5}"); // ex : $r1, https://www.brics.dk/SootGuide/sootsurvivorsguide.pdf

    public SootUnit() throws InstantiationException {
        throw new InstantiationException();
    }

    public static int getUnitType(Unit unit) {
        int type = -1;

        if (isVirtualInvoke(unit)) {
            type = VIRTUAL_INVOKE;
        } else if (isStaticInvoke(unit)) {
            type = STATIC_INVOKE;
        } else if (isInterfaceInvoke(unit)) {
            type = INTERFACE_INVOKE;
        } else if (isSpecialInvoke(unit)) {
            type = SPECIAL_INVOKE;
        } else if (isAssignVirtualInvoke(unit)) {
            type = ASSIGN_VIRTUAL_INVOKE;
        } else if (isAssignStaticInvoke(unit)) {
            type = ASSIGN_STATIC_INVOKE;
        } else if (isAssignInterfaceInvoke(unit)) {
            type = ASSIGN_INTERFACE_INVOKE;
        } else if (isAssignSpecialInvoke(unit)) {
            type = ASSIGN_SPECIAL_INVOKE;
        } else if (isParameter(unit)) {
            type = PARAMETER;
        } else if (isCaughtException(unit)) {
            type = CAUGHT_EXCEPTION;
        } else if (isNewInstance(unit)) {
            type = NEW_INSTANCE;
        } else if (isNewArray(unit)) {
            type = NEW_ARRAY;
        } else if (isNewException(unit)) {
            type = NEW_EXCEPTION;
        } else if (isAssignVariableConstant(unit)) {
            type = ASSIGN_VARIABLE_CONSTANT;
        } else if (isAssignVariableVariable(unit)) {
            type = ASSIGN_VARIABLE_VARIABLE;
        } else if (isAssignVariableArray(unit)) {
            type = ASSIGN_VARIABLE_ARRAY;
        } else if (isAssignVariableSignature(unit)) {
            type = ASSIGN_VARIABLE_SIGNATURE;
        } else if (isAssignVariableOperation(unit)) {
            type = ASSIGN_VARIABLE_OPERATION;
        } else if (isAssignSignatureConstant(unit)) {
            type = ASSIGN_SIGNATURE_CONSTANT;
        } else if (isAssignSignatureVariable(unit)) {
            type = ASSIGN_SIGNATURE_VARIABLE;
        } else if (isAssignArrayConstant(unit)) {
            type = ASSIGN_ARRAY_CONSTANT;
        } else if (isAssignArrayVariable(unit)) {
            type = ASSIGN_ARRAY_VARIABLE;
        } else if (isCast(unit)) {
            type = CAST;
        } else if (isLengthOf(unit)) {
            type = LENGTH_OF;
        } else if (isInstanceOf(unit)) {
            type = INSTANCE_OF;
        } else if (isIf(unit)) {
            type = IF;
        } else if (isGoto(unit)) {
            type = GOTO;
        } else if (isSwitch(unit)) {
            type = SWITCH;
        } else if (isReturnValue(unit)) {
            type = RETURN_VALUE;
        } else if (isReturnVoid(unit)) {
            type = RETURN_VOID;
        } else if (isAssign(unit)) {
            type = ASSIGN; // other assign unit
        } else if (isNopStmt(unit)) {
            type = NOP;
        }

        return type;
    }

    public static Value getBase(Unit unit, int unitType) {
        Value leftOp = getLeftOp(unit, unitType);
        Value rightOp = getRightOp(unit, unitType);
        Value base = null;

        if ((unitType & INVOKE) == INVOKE) {
            Value op;

            if (rightOp == null) {
                JInvokeStmt stmt = ((JInvokeStmt) unit);
                op = stmt.getInvokeExpr();
            } else {
                op = rightOp;
            }

            if (op instanceof JVirtualInvokeExpr) {
                JVirtualInvokeExpr e = (JVirtualInvokeExpr) op;
                base = e.getBase();
            } else if (op instanceof JInterfaceInvokeExpr) {
                JInterfaceInvokeExpr e = (JInterfaceInvokeExpr) op;
                base = e.getBase();
            } else if (op instanceof JSpecialInvokeExpr) {
                JSpecialInvokeExpr e = (JSpecialInvokeExpr) op;
                base = e.getBase();
            }
        } else if ((unitType & ASSIGN_VARIABLE) == ASSIGN_VARIABLE || (unitType & ASSIGN_SIGNATURE) == ASSIGN_SIGNATURE) {
            if (leftOp instanceof JInstanceFieldRef) {
                InstanceFieldRef ref = (JInstanceFieldRef) leftOp;
                base = ref.getBase();
            } else if (rightOp instanceof JInstanceFieldRef) {
                InstanceFieldRef ref = (JInstanceFieldRef) rightOp;
                base = ref.getBase();
            }
        } else if (unitType == ASSIGN_ARRAY_CONSTANT || unitType == ASSIGN_ARRAY_VARIABLE) {
            JArrayRef ref = (JArrayRef) leftOp;
            base = ref.getBase();
        }

        return base;
    }

    public static String getSignature(Unit unit) {
        String unitString = unit.toString();

        return getSignature(unitString);
    }

    public static String getSignature(String unitString) {
        StringTokenizer tokenizer = new StringTokenizer(unitString, ">");
        String token1 = tokenizer.nextToken();
        int beginIndex = token1.indexOf("<");
        String str = token1.substring(beginIndex);

        StringBuilder builder = new StringBuilder();
        builder.append(str);

        if (unitString.contains("<init>")) {
            String token2 = tokenizer.nextToken();
            builder.append(">");
            builder.append(token2);
        }

        builder.append(">");

        return builder.toString();
    }

    public static String getSubSignature(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        tokenizer.nextToken();

        String token1 = tokenizer.nextToken();
        String token2 = tokenizer.nextToken();
        int beginIndex = 0;
        int endIndex = token2.length() - 1;

        return String.format("%s %s", token1, token2.substring(beginIndex, endIndex));
    }

    public static String getClassName(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        String token = tokenizer.nextToken();

        int beginIndex = 1;
        int endIndex = token.length() - 1;

        return token.substring(beginIndex, endIndex);
    }

    public static String getReturnType(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        tokenizer.nextToken();

        return tokenizer.nextToken();
    }

    public static String getMethodName(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        tokenizer.nextToken();
        tokenizer.nextToken();
        String token = tokenizer.nextToken();

        int beginIndex = 0;
        int endIndex = token.indexOf('(');

        return token.substring(beginIndex, endIndex);
    }

    public static ArrayList<String> getParamTypes(String signature) {
        int beginIndex = signature.indexOf("(") + 1;
        int endIndex = signature.length() - 2;
        String str = signature.substring(beginIndex, endIndex);

        return convertToList(str);
    }

    public static ArrayList<Value> getParameters(Unit unit, int unitType) {
        ArrayList<Value> parameters = new ArrayList<>();

        if ((unitType & INVOKE) != INVOKE) {
            return parameters;
        }

        InvokeExpr expr;
        if ((unitType & ASSIGN) == ASSIGN) {
            Value rightOp = getRightOp(unit, unitType);
            expr = (InvokeExpr) rightOp;
        } else {
            JInvokeStmt stmt = (JInvokeStmt) unit;
            expr = stmt.getInvokeExpr();
        }

        for (int i = 0; i < expr.getArgCount(); i++) {
            Value v = expr.getArg(i);
            parameters.add(v);
        }

        return parameters;
    }

    public static ArrayList<String> getParameters(String unitString) {
        int beginIndex = unitString.indexOf(")>") + 3;
        int endIndex = unitString.length() - 1;
        String str = unitString.substring(beginIndex, endIndex);

        return convertToList(str);
    }

    public static Value getLeftOp(Unit unit, int unitType) {
        Value op = null;

        if ((unitType & IDENTITY) == IDENTITY) {
            IdentityStmt stmt = (JIdentityStmt) unit;
            op = stmt.getLeftOp();
        } else if ((unitType & ASSIGN) == ASSIGN) {
            JAssignStmt stmt = (JAssignStmt) unit;
            op = stmt.getLeftOp();
        }

        return op;
    }

    public static String getLeftOpStr(String unitString, int unitType) {
        String str = ((unitType & ASSIGN) == ASSIGN) ? unitString.split(" ")[0] : "null";

        return str.replace("\"", "");
    }

    public static Value getRightOp(Unit unit, int unitType) {
        Value op = null;

        if ((unitType & IDENTITY) == IDENTITY) {
            JIdentityStmt stmt = (JIdentityStmt) unit;
            op = stmt.getRightOp();
        } else if (unitType == RETURN_VALUE) {
            JReturnStmt stmt = (JReturnStmt) unit;
            op = stmt.getOp();
        } else if ((unitType & ASSIGN) == ASSIGN) {
            JAssignStmt stmt = (JAssignStmt) unit;
            op = stmt.getRightOp();
        }

        return op;
    }

    public static String getRightOpStr(String unitString, int unitType) {
        String str = "null";

        if (unitType == ASSIGN_VARIABLE_CONSTANT) {
            str = unitString.split(" = ")[1];
        } else if (unitType == RETURN_VALUE) {
            str = unitString.split(" ")[1];
        }

        return str.replace("\"", "");
    }

    public static int getParamIndex(Unit unit, int unitType) {
        int index = -1;

        if (unitType == PARAMETER) {
            Value rightOp = getRightOp(unit, unitType);
            ParameterRef ref = (ParameterRef) rightOp;
            index = ref.getIndex();
        }

        return index;
    }

    public static String getArraySize(String unitString, int unitType) {
        return (unitType == NEW_ARRAY) ? unitString.substring(unitString.indexOf("[") + 1, unitString.indexOf("]")) : null;
    }

    public static Value getRightInternalOp(Unit unit, int unitType) {
        Value rightOp = getRightOp(unit, unitType);
        Value op = null;

        if (unitType == CAST) {
            JCastExpr expr = (JCastExpr) rightOp;
            op = expr.getOp();
        } else if (unitType == LENGTH_OF) {
            JLengthExpr expr = (JLengthExpr) rightOp;
            op = expr.getOp();
        }

        return op;
    }

    public static Value getIfCondition(Unit unit, int unitType) {
        Value condition = null;

        if (unitType == IF) {
            JIfStmt stmt = (JIfStmt) unit;
            condition = stmt.getCondition();
        }

        return condition;
    }

    public static ArrayList<Value> getIfConditionValues(Unit unit, int unitType) {
        ArrayList<Value> values = new ArrayList<>();

        Value condition = getIfCondition(unit, unitType);
        if (condition == null) {
            return values;
        }

        List<ValueBox> valueBoxes = condition.getUseBoxes();
        for (ValueBox vb : valueBoxes) {
            Value v = vb.getValue();
            values.add(v);
        }

        return values;
    }

    public static Unit getIfGotoTargetUnit(Unit unit, int unitType) {
        Unit targetUnit = null;

        if (unitType == IF) {
            JIfStmt stmt = (JIfStmt) unit;
            UnitBox unitBox = stmt.getTargetBox();
            targetUnit = unitBox.getUnit();
        } else if (unitType == GOTO) {
            JGotoStmt stmt = (JGotoStmt) unit;
            targetUnit = stmt.getTarget();
        }

        return targetUnit;
    }

    public static boolean isIfElseStatement(ArrayList<Unit> wholeUnit, Unit unit, int unitType) {
        if (isLoopStatement(wholeUnit, unit, unitType)) {
            return false;
        }

        if (unitType == IF) {
            Unit targetUnit = getIfGotoTargetUnit(unit, unitType);
            Unit tempUnit1 = wholeUnit.get(wholeUnit.indexOf(targetUnit) - 1);
            int tempUnitType1 = getUnitType(tempUnit1);
            Unit tempUnit2 = getIfGotoTargetUnit(tempUnit1, tempUnitType1);

            return tempUnit2 != null && !isNewException(tempUnit2);
        }

        return false;
    }

    public static boolean isLoopStatement(ArrayList<Unit> wholeUnit, Unit unit, int unitType) {
        Unit targetUnit = getIfGotoTargetUnit(unit, unitType);
        if (!wholeUnit.contains(targetUnit)) {
            return false;
        }

        if (unitType == IF) {
            int tempUnitIndex = wholeUnit.indexOf(targetUnit) - 1;
            if (tempUnitIndex == -1) {
                return true;
            }

            Unit tempUnitUnit = wholeUnit.get(tempUnitIndex);
            int tempUnitType = getUnitType(tempUnitUnit);
            targetUnit = getIfGotoTargetUnit(tempUnitUnit, tempUnitType);
        }

        int wholeUnitCount = wholeUnit.size();
        int unitIndex = wholeUnit.indexOf(unit);
        int targetUnitIndex = wholeUnit.indexOf(targetUnit);

        return wholeUnitCount > unitIndex + 1 && unitIndex >= targetUnitIndex && targetUnitIndex > -1;
    }

    public static ArrayList<Unit> getSwitchTargetUnits(Unit unit, int unitType) {
        ArrayList<Unit> units = new ArrayList<>();

        if (unitType != SWITCH) {
            return units;
        }

        SwitchStmt stmt = (JLookupSwitchStmt) unit;
        List<Unit> targets = stmt.getTargets();
        units = new ArrayList<>(targets);
        Unit defaultUnit = stmt.getDefaultTarget();
        units.add(defaultUnit);

        return units;
    }

    public static JNopStmt getNopStmt() {
        return new JNopStmt();
    }

    public static void setInvokeUnit(Unit unit, Value base, ArrayList<Value> parameters) {
        JInvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();
        setInvokeBase(expr, base);

        setInvokeParameters(expr, parameters);
        stmt.setInvokeExpr(expr);
    }

    public static void setAssignUnit(Unit unit, Value leftOp, Value rightOp) {
        if (isNullValue(leftOp) || isNullValue(rightOp)) {
            return;
        }

        AssignStmt stmt = (AssignStmt) unit;
        stmt.setLeftOp(leftOp);
        stmt.setRightOp(rightOp);
    }

    public static void setAssignInvokeUnit(Unit unit, Value leftOp, Value base, ArrayList<Value> parameters) {
        Value rightOp = getRightOp(unit, ASSIGN);
        InvokeExpr expr = (InvokeExpr) rightOp;
        setInvokeBase(expr, base);

        setInvokeParameters(expr, parameters);
        setAssignUnit(unit, leftOp, expr);
    }

    public static void setAssignVariableSignatureUnit(Unit unit, Value leftOp, Value rightOp, Value base) {
        if (rightOp instanceof JInstanceFieldRef && base != NullConstant.v()) {
            JInstanceFieldRef ref = (JInstanceFieldRef) rightOp;
            ref.setBase(base);
        }

        setAssignUnit(unit, leftOp, rightOp);
    }

    public static void setArrayBase(Value leftOp, Value base) {
        if (isNullValue(leftOp) || isNullValue(base)) {
            return;
        }

        JArrayRef ref = (JArrayRef) leftOp;
        Local tempBase = (Local) base;
        ref.setBase(tempBase);
    }

    public static void setAssignSignatureVariable(Unit unit, Value leftOp, Value base, Value rightOp) {
        if (leftOp instanceof JInstanceFieldRef && base != NullConstant.v()) {
            JInstanceFieldRef ref = (JInstanceFieldRef) leftOp;
            ref.setBase(base);
        }

        setAssignUnit(unit, leftOp, rightOp);
    }

    public static void setCastUnit(Unit unit, Value leftOp, Value rightOp, Value rightInternalOp) {
        if (isNullValue(leftOp) || isNullValue(rightOp) || isNullValue(rightInternalOp)) {
            return;
        }

        CastExpr expr = (CastExpr) rightOp;
        expr.setOp(rightInternalOp);

        setAssignUnit(unit, leftOp, expr);
    }

    public static void setLengthOfUnit(Unit unit, Value leftOp, Value rightOp, Value rightInternalOp) {
        if (isNullValue(leftOp) || isNullValue(rightOp) || isNullValue(rightInternalOp)) {
            return;
        }

        LengthExpr expr = (LengthExpr) rightOp;
        expr.setOp(rightInternalOp);

        setAssignUnit(unit, leftOp, expr);
    }

    public static void setIfCondition(Unit unit, Value condition, ArrayList<Value> conditionValues) {
        setExpr(condition, conditionValues.get(0), conditionValues.get(1));

        JIfStmt stmt = (JIfStmt) unit;
        stmt.setCondition(condition);
    }

    public static void setReturnValue(Unit unit, Value rightOp) {
        if (isNullValue(rightOp)) {
            return;
        }

        JReturnStmt stmt = (JReturnStmt) unit;
        stmt.setOp(rightOp);
    }

    public static String convertToStr(Value value) {
        String str = (value == null) ? "null" : value.toString();
        str = str.replace("\"", "");

        return str;
    }

    public static boolean isLocalVariable(Value value) {
        return isLocalVariable(convertToStr(value));
    }

    public static boolean isLocalVariable(String str) {
        Matcher matcher = LOCAL_VARIABLE_PATTERN.matcher(str);

        return matcher.matches();
    }

    public static boolean isStackVariable(Value value) {
        return isStackVariable(convertToStr(value));
    }

    public static boolean isStackVariable(String str) {
        Matcher matcher = STACK_VARIABLE_PATTERN.matcher(str);

        return matcher.matches();
    }

    public static boolean isVariable(Value value) {
        return isVariableStr(convertToStr(value));
    }

    public static boolean isVariableStr(String str) {
        return isLocalVariable(str) || isStackVariable(str);
    }

    public static boolean isNumericConstant(Value value) {
        return value instanceof NumericConstant;
    }

    public static HashSet<Value> getVariables(Unit unit) {
        List<ValueBox> useAndDefBoxes = unit.getUseAndDefBoxes();
        HashSet<Value> variables = new HashSet<>();

        for (ValueBox vb : useAndDefBoxes) {
            Value value = vb.getValue();

            if (vb instanceof JAssignStmt.LinkedVariableBox) {
                variables.add(value);
            } else if (vb instanceof JimpleLocalBox && isStackVariable(value)) {
                variables.add(value);
            } else if (vb instanceof RValueBox || vb instanceof ImmediateBox) {
                variables.add(value);
            }
        }

        return variables;
    }

    private static boolean isInvoke(Unit unit) {
        return unit instanceof JInvokeStmt;
    }

    private static boolean isVirtualInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        InvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();

        return expr instanceof JVirtualInvokeExpr;
    }

    private static boolean isStaticInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        InvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();

        return expr instanceof JStaticInvokeExpr;
    }

    private static boolean isInterfaceInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        InvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();

        return expr instanceof JInterfaceInvokeExpr;
    }

    private static boolean isSpecialInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        InvokeStmt stmt = (JInvokeStmt) unit;
        InvokeExpr expr = stmt.getInvokeExpr();

        return expr instanceof JSpecialInvokeExpr;
    }

    private static boolean isAssign(Unit unit) {
        return unit instanceof JAssignStmt;
    }

    private static boolean isAssignVirtualInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, ASSIGN);

        return value instanceof JVirtualInvokeExpr;
    }

    private static boolean isAssignStaticInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, ASSIGN);

        return value instanceof JStaticInvokeExpr;
    }

    private static boolean isAssignInterfaceInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, ASSIGN);

        return value instanceof JInterfaceInvokeExpr;
    }

    private static boolean isAssignSpecialInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, ASSIGN);

        return value instanceof JSpecialInvokeExpr;
    }

    private static boolean isIdentity(Unit unit) {
        return unit instanceof IdentityStmt;
    }

    private static boolean isParameter(Unit unit) {
        if (!isIdentity(unit)) {
            return false;
        }

        Value value = getRightOp(unit, PARAMETER);

        return value instanceof ParameterRef;
    }

    private static boolean isCaughtException(Unit unit) {
        if (!isIdentity(unit)) {
            return false;
        }

        Value value = getRightOp(unit, CAUGHT_EXCEPTION);

        return value instanceof CaughtExceptionRef;
    }

    private static boolean isNewInstance(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, ASSIGN);
        String valueStr = convertToStr(value);

        return (value instanceof JNewExpr) && (!valueStr.endsWith("Exception"));
    }

    private static boolean isNewArray(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, ASSIGN);

        return value instanceof JNewArrayExpr;
    }

    private static boolean isNewException(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, ASSIGN);
        String valueStr = convertToStr(value);

        return (value instanceof JNewExpr) && (valueStr.endsWith("Exception"));
    }

    private static boolean isAssignVariableConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof JimpleLocal) && (rightOp instanceof Constant);
    }

    private static boolean isAssignVariableVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof JimpleLocal) && (rightOp instanceof JimpleLocal);
    }

    private static boolean isAssignVariableArray(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof JimpleLocal) && (rightOp instanceof JArrayRef);
    }

    private static boolean isAssignVariableSignature(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof JimpleLocal) && (rightOp instanceof StaticFieldRef || rightOp instanceof JInstanceFieldRef);
    }

    private static boolean isAssignVariableOperation(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof JimpleLocal) && (rightOp instanceof BinopExpr);
    }

    private static boolean isAssignSignatureConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof StaticFieldRef || leftOp instanceof JInstanceFieldRef) && (rightOp instanceof Constant);
    }

    private static boolean isAssignSignatureVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof StaticFieldRef || leftOp instanceof JInstanceFieldRef) && (rightOp instanceof JimpleLocal);
    }

    private static boolean isAssignArrayConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof JArrayRef) && (rightOp instanceof Constant);
    }

    private static boolean isAssignArrayVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftOp = getLeftOp(unit, ASSIGN);
        Value rightOp = getRightOp(unit, ASSIGN);

        return (leftOp instanceof JArrayRef) && (rightOp instanceof JimpleLocal);
    }

    private static boolean isCast(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, CAST);

        return value instanceof JCastExpr;
    }

    private static boolean isLengthOf(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, LENGTH_OF);

        return value instanceof JLengthExpr;
    }

    private static boolean isInstanceOf(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightOp(unit, INSTANCE_OF);

        return value instanceof JInstanceOfExpr;
    }

    private static boolean isIf(Unit unit) {
        return unit instanceof JIfStmt;
    }

    private static boolean isGoto(Unit unit) {
        return unit instanceof JGotoStmt;
    }

    private static boolean isSwitch(Unit unit) {
        return unit instanceof JLookupSwitchStmt;
    }

    private static boolean isReturnValue(Unit unit) {
        return unit instanceof JReturnStmt;
    }

    private static boolean isReturnVoid(Unit unit) {
        return unit instanceof JReturnVoidStmt;
    }

    private static boolean isNopStmt(Unit unit) {
        return unit instanceof JNopStmt;
    }

    private static void setInvokeBase(InvokeExpr expr, Value base) {
        if (isNullValue(base)) {
            return;
        }

        if (expr instanceof VirtualInvokeExpr) {
            VirtualInvokeExpr e = (VirtualInvokeExpr) expr;
            e.setBase(base);
        } else if (expr instanceof InterfaceInvokeExpr) {
            InterfaceInvokeExpr e = (InterfaceInvokeExpr) expr;
            e.setBase(base);
        } else if (expr instanceof SpecialInvokeExpr) {
            SpecialInvokeExpr e = (SpecialInvokeExpr) expr;
            e.setBase(base);
        }
    }

    private static void setInvokeParameters(InvokeExpr expr, ArrayList<Value> parameters) {
        parameters.forEach(v -> expr.setArg(parameters.indexOf(v), v));
    }

    private static void setExpr(Value value, Value op1, Value op2) {
        if (value instanceof JGtExpr) {
            JGtExpr expr = (JGtExpr) value;
            expr.setOp1(op1);
            expr.setOp2(op2);
        } else if (value instanceof JGeExpr) {
            JGeExpr expr = (JGeExpr) value;
            expr.setOp1(op1);
            expr.setOp2(op2);
        } else if (value instanceof JEqExpr) {
            JEqExpr expr = (JEqExpr) value;
            expr.setOp1(op1);
            expr.setOp2(op2);
        } else if (value instanceof JNeExpr) {
            JNeExpr expr = (JNeExpr) value;
            expr.setOp1(op1);
            expr.setOp2(op2);
        } else if (value instanceof JLeExpr) {
            JLeExpr expr = (JLeExpr) value;
            expr.setOp1(op1);
            expr.setOp2(op2);
        } else if (value instanceof JLtExpr) {
            JLtExpr expr = (JLtExpr) value;
            expr.setOp1(op1);
            expr.setOp2(op2);
        }
    }

    private static boolean isNullValue(Value value) {
        return value == null || value == NullConstant.v();
    }
}