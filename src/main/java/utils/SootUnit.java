package utils;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;
import soot.*;
import soot.jimple.Constant;
import soot.jimple.IdentityStmt;
import soot.jimple.StaticFieldRef;
import soot.jimple.internal.*;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.regex.Pattern.compile;
import static utils.SootUnit.VariableType.*;

public class SootUnit {
    public static final int INVOKE = 0x00100000;
    public static final int VIRTUAL_INVOKE = INVOKE | 0x00001000;
    public static final int STATIC_INVOKE = INVOKE | 0x00002000;
    public static final int INTERFACE_INVOKE = INVOKE | 0x00004000;
    public static final int SPECIAL_INVOKE = INVOKE | 0x00008000;
    public static final int ASSIGN = 0x00200000;
    public static final int ASSIGN_INVOKE = ASSIGN | INVOKE;
    public static final int ASSIGN_VIRTUAL_INVOKE = ASSIGN_INVOKE | VIRTUAL_INVOKE;
    public static final int ASSIGN_STATIC_INVOKE = ASSIGN_INVOKE | STATIC_INVOKE;
    public static final int ASSIGN_INTERFACE_INVOKE = ASSIGN_INVOKE | INTERFACE_INVOKE;
    public static final int ASSIGN_SPECIAL_INVOKE = ASSIGN_INVOKE | SPECIAL_INVOKE;
    public static final int IDENTITY = ASSIGN | 0x00000010;
    public static final int PARAMETER = IDENTITY | 0x00000001;
    public static final int EXCEPTION = IDENTITY | 0x00000002;
    public static final int NEW_INSTANCE = ASSIGN | 0x00000020;
    public static final int NEW_ARRAY = ASSIGN | 0x00000040;
    public static final int NEW_EXCEPTION = ASSIGN | 0x00000080;
    public static final int ASSIGN_VARIABLE_CONSTANT = ASSIGN | 0x00000100;
    public static final int ASSIGN_VARIABLE_VARIABLE = ASSIGN | 0x00000101;
    public static final int ASSIGN_VARIABLE_ARRAY = ASSIGN | 0x00000102;
    public static final int ASSIGN_VARIABLE_SIGNATURE = ASSIGN | 0x00000104;
    public static final int ASSIGN_VARIABLE_ADD  = ASSIGN | 0x00000108;
    public static final int ASSIGN_ARRAY_CONSTANT = ASSIGN | 0x00000200;
    public static final int ASSIGN_ARRAY_VARIABLE = ASSIGN | 0x00000201;
    public static final int ASSIGN_SIGNATURE_CONSTANT = ASSIGN | 0x00000400;
    public static final int ASSIGN_SIGNATURE_VARIABLE = ASSIGN | 0x00000401;
    public static final int CAST = ASSIGN | 0x00010000;
    public static final int LENGTH_OF = ASSIGN | 0x00020000;
    public static final int INSTANCE_OF = ASSIGN | 0x00040000;
    public static final int IF = 0x00400000;
    public static final int GOTO = 0x008000000;
    public static final int SWITCH = 0x01000000;
    public static final int RETURN = 0x02000000;
    public static final int RETURN_VALUE = RETURN | 0x00000001;
    public static final int RETURN_VOID = RETURN | 0x00000002;

    private static final Pattern LOCAL_VARIABLE_PATTERN = compile("[a-z]\\d{1,5}"); // ex: r0, https://www.brics.dk/SootGuide/sootsurvivorsguide.pdf
    private static final Pattern STACK_VARIABLE_PATTERN = compile("\\$[a-z]\\d{1,5}"); // ex : $r1, https://www.brics.dk/SootGuide/sootsurvivorsguide.pdf

    private SootUnit() throws InstantiationException {
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
        } else if (isException(unit)) {
            type = EXCEPTION;
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
        } else if (isAssignVariableAdd(unit)) {
            type = ASSIGN_VARIABLE_ADD;
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
        }

        return type;
    }

    public enum VariableType {
        ALL, LOCAL, IMMEDIATE
    }

    public static ArrayList<String> getVariables(Unit unit, VariableType variableType) {
        ArrayList<String> list = new ArrayList<>();

        List<ValueBox> valueBoxes = unit.getUseAndDefBoxes();
        for (ValueBox vb : valueBoxes) {
            if (vb instanceof IdentityRefBox || vb instanceof RValueBox || vb instanceof InvokeExprBox) {
                continue;
            }

            Value value = vb.getValue();
            String variable = value.toString();

            if (variableType == ALL) {
                list.add(variable);
            } else if (variableType == LOCAL && vb instanceof JimpleLocalBox) {
                list.add(variable);
            } else if (variableType == IMMEDIATE && vb instanceof ImmediateBox) {
                list.add(variable);
            }
        }

        return list;
    }

    public static String getLocalVariable(Unit unit) {
        ArrayList<String> variables = getVariables(unit, LOCAL);
        if (variables.isEmpty()) {
            return null;
        }

        return variables.get(0);
    }

    public static String getSignature(Unit unit) {
        String unitStr = unit.toString();

        return getSignature(unitStr);
    }

    public static String getSignature(String unitStr) {
        StringTokenizer tokenizer = new StringTokenizer(unitStr, ">");
        String str = tokenizer.nextToken();

        StringBuilder buffer = new StringBuilder();
        buffer.append(str.substring(str.indexOf("<")));
        if (unitStr.contains("<init>")) {
            buffer.append(">");
            buffer.append(tokenizer.nextToken());
        }

        buffer.append(">");
        return buffer.toString();
    }

    public static String getClassName(String signature) {
        StringTokenizer tokenizer = new StringTokenizer(signature);
        String str = tokenizer.nextToken();

        return str.substring(1, str.length() - 1);
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
        String str = tokenizer.nextToken();

        return str.substring(0, str.indexOf('('));
    }

    public static ArrayList<String> getParamTypes(String signature) {
        String str = signature.substring(signature.indexOf("(") + 1, signature.length() - 2);
        return convertStrToList(str);
    }

    public static ArrayList<String> getParamValues(Unit unit) {
        String unitStr = unit.toString();

        return getParamValues(unitStr);
    }

    public static ArrayList<String> getParamValues(String unitStr) {
        String str = unitStr.substring(unitStr.indexOf(")>") + 3, unitStr.length() - 1);
        return convertStrToList(str);
    }

    public static Value getLeftValue(Unit unit, int unitType) {
        Value value = null;

        if ((unitType & IDENTITY) == IDENTITY) {
            value = ((JIdentityStmt) unit).getLeftOp();
        } else if ((unitType & ASSIGN) == ASSIGN) {
            value = ((JAssignStmt) unit).getLeftOp();
        }

        return value;
    }

    public static Value getRightValue(Unit unit, int unitType) {
        Value value = null;

        if ((unitType & IDENTITY) == IDENTITY) {
            value = ((JIdentityStmt) unit).getRightOp();
        } else if (unitType == RETURN_VALUE) {
            value = ((JReturnStmt) unit).getOp();
        } else if ((unitType & ASSIGN) == ASSIGN) {
            value = ((JAssignStmt) unit).getRightOp();
        }

        return value;
    }

    public static String getLeftValueStr(Unit unit, int unitType) {
        Value value = getLeftValue(unit, unitType);

        return (value != null) ? value.toString() : "null";
    }

    public static String getRightValueStr(Unit unit, int unitType) {
        Value value = getRightValue(unit, unitType);

        return (value != null) ? value.toString() : "null";
    }

    public static boolean isLocalVariable(String s) {
        if (s == null) {
            return false;
        }

        Matcher matcher = LOCAL_VARIABLE_PATTERN.matcher(s);

        return matcher.matches();
    }

    public static boolean isStackVariable(String s) {
        if (s == null) {
            return false;
        }

        Matcher matcher = STACK_VARIABLE_PATTERN.matcher(s);

        return matcher.matches();
    }

    public static boolean isVariableStr(String s) {
        return isLocalVariable(s) || isStackVariable(s);
    }

    public static String getParamNum(Unit unit) {
        if (!isParameter(unit)) {
            return null;
        }

        String valueStr = getRightValueStr(unit, PARAMETER);
        Pattern pattern = compile("[0-9]+");
        Matcher matcher = pattern.matcher(valueStr);
        matcher.find();

        return matcher.group();
    }

    public static ArrayList<Unit> getWholeUnits(String signature) {
        SootMethod sootMethod = Scene.v().getMethod(signature);
        Body body = sootMethod.getActiveBody();
        UnitPatchingChain unitPatchingChain = body.getUnits();

        return new ArrayList<>(unitPatchingChain);
    }

    public static Unit getTargetUnit(Unit unit) {
        Unit targetUnit;

        if (isIf(unit)) {
            JIfStmt stmt = (JIfStmt) unit;
            UnitBox unitBox = stmt.getTargetBox();
            targetUnit = unitBox.getUnit();
        } else {
            JGotoStmt stmt = (JGotoStmt) unit;
            targetUnit = stmt.getTarget();
        }

        return targetUnit;
    }

    public static String getArraySize(Unit unit) {
        int unitType = getUnitType(unit);
        JNewArrayExpr expr = (JNewArrayExpr) getRightValue(unit, unitType);
        Value size = expr.getSize();

        return size.toString();
    }

    public static String getArrayIndex(Unit unit) {
        int unitType = getUnitType(unit);
        JArrayRef ref = (JArrayRef) getLeftValue(unit, unitType);
        Value index = ref.getIndex();

        return index.toString();
    }

    private static boolean isInvoke(Unit unit) {
        return unit instanceof JInvokeStmt;
    }

    private static boolean isVirtualInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        Value value = ((JInvokeStmt) unit).getInvokeExpr();

        return value instanceof JVirtualInvokeExpr;
    }

    private static boolean isStaticInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        Value value = ((JInvokeStmt) unit).getInvokeExpr();

        return value instanceof JStaticInvokeExpr;
    }

    private static boolean isInterfaceInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        Value value = ((JInvokeStmt) unit).getInvokeExpr();

        return value instanceof JInterfaceInvokeExpr;
    }

    private static boolean isSpecialInvoke(Unit unit) {
        if (!isInvoke(unit)) {
            return false;
        }

        Value value = ((JInvokeStmt) unit).getInvokeExpr();

        return value instanceof JSpecialInvokeExpr;
    }

    private static boolean isAssign(Unit unit) {
        return unit instanceof JAssignStmt;
    }

    private static boolean isAssignVirtualInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JVirtualInvokeExpr;
    }

    private static boolean isAssignStaticInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JStaticInvokeExpr;
    }

    private static boolean isAssignInterfaceInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JInterfaceInvokeExpr;
    }

    private static boolean isAssignSpecialInvoke(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JSpecialInvokeExpr;
    }

    private static boolean isIdentity(Unit unit) {
        return unit instanceof IdentityStmt;
    }

    private static boolean isParameter(Unit unit) {
        if (!isIdentity(unit)) {
            return false;
        }

        String valueStr = getRightValueStr(unit, PARAMETER);

        return valueStr.contains("@parameter");
    }

    private static boolean isException(Unit unit) {
        if (!isIdentity(unit)) {
            return false;
        }

        String valueStr = getRightValueStr(unit, EXCEPTION);

        return valueStr.contains("@caughtexception");
    }

    private static boolean isNewInstance(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);
        String valueStr = value.toString();

        return (value instanceof JNewExpr) && (!valueStr.endsWith("Exception"));
    }

    private static boolean isNewArray(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);

        return value instanceof JNewArrayExpr;
    }

    private static boolean isNewException(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, ASSIGN);
        String valueStr = value.toString();

        return (value instanceof JNewExpr) && (valueStr.endsWith("Exception"));
    }

    private static boolean isAssignVariableConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof Constant);
    }

    private static boolean isAssignVariableVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof JimpleLocal);
    }

    private static boolean isAssignVariableArray(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof JArrayRef);
    }

    private static boolean isAssignVariableSignature(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof StaticFieldRef || rightValue instanceof JInstanceFieldRef);
    }

    private static boolean isAssignVariableAdd(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JimpleLocal) && (rightValue instanceof JAddExpr);
    }

    private static boolean isAssignSignatureConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof StaticFieldRef || leftValue instanceof JInstanceFieldRef) && (rightValue instanceof Constant);
    }

    private static boolean isAssignSignatureVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof StaticFieldRef || leftValue instanceof JInstanceFieldRef) && (rightValue instanceof JimpleLocal);
    }

    private static boolean isAssignArrayConstant(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JArrayRef) && (rightValue instanceof Constant);
    }

    private static boolean isAssignArrayVariable(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value leftValue = getLeftValue(unit, ASSIGN);
        Value rightValue = getRightValue(unit, ASSIGN);

        return (leftValue instanceof JArrayRef) && (rightValue instanceof JimpleLocal);
    }

    private static boolean isCast(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, CAST);

        return value instanceof JCastExpr;
    }

    private static boolean isLengthOf(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, LENGTH_OF);

        return value instanceof JLengthExpr;
    }

    private static boolean isInstanceOf(Unit unit) {
        if (!isAssign(unit)) {
            return false;
        }

        Value value = getRightValue(unit, INSTANCE_OF);

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

    private static ArrayList<String> convertStrToList(String str) {
        ArrayList<String> list = new ArrayList<>();

        try {
            CSVReader reader = new CSVReader(new StringReader(str));
            String[] tokens = reader.readNext();
              for (String t : tokens) {
                t = t.trim();
                list.add(t);
            }
        } catch (IOException | CsvValidationException | NullPointerException ignored) {

        }

        return list;
    }
}