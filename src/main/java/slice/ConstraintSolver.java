package slice;

import org.chocosolver.solver.Model;
import org.chocosolver.solver.Solver;
import org.chocosolver.solver.constraints.Constraint;
import org.chocosolver.solver.expression.discrete.relational.ReExpression;
import org.chocosolver.solver.variables.BoolVar;
import org.chocosolver.solver.variables.IntVar;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.internal.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.chocosolver.solver.variables.IntVar.MAX_INT_BOUND;
import static org.chocosolver.solver.variables.IntVar.MIN_INT_BOUND;
import static utils.SootUnit.*;

public class ConstraintSolver {

    public static ConstraintSolver getInstance() {
        return ConstraintSolver.Holder.instance;
    }

    public ArrayList<Unit> findInfeasibleUnits(HashMap<String, ArrayList<Unit>> targetUnitsMap) {
        ArrayList<Unit> infeasibleUnits = new ArrayList<>();
        Set<Map.Entry<String, ArrayList<Unit>>> entries = targetUnitsMap.entrySet();
        for (Map.Entry<String, ArrayList<Unit>> e : entries) {
            String signature = e.getKey();
            ArrayList<Unit> targetUnits = e.getValue();

            ArrayList<Unit> tempUnits = findInfeasibleUnits(signature, targetUnits);
            infeasibleUnits.addAll(tempUnits);
        }

        return infeasibleUnits;
    }

    public ArrayList<Unit> findInfeasibleUnits(String signature, ArrayList<Unit> targetUnits) {
        ArrayList<Unit> wholeUnits = getWholeUnits(signature);
        ArrayList<Unit> infeasibleUnits = new ArrayList<>();

        for (Unit u : targetUnits) {
            int unitType = getUnitType(u);

            if (unitType == IF) {
                int result = getIfStatementResult(u);
                if (result == -1) {
                    continue;
                }

                int unitIndex = wholeUnits.indexOf(u);
                Unit targetUnit = getTargetUnit(u);
                int targetUnitIndex = wholeUnits.indexOf(targetUnit);

                int startTargetUnitIndex = -1;
                int endTargetUnitIndex = -1;
                boolean flag = result == 1;
                if (flag) {
                    startTargetUnitIndex = unitIndex;
                    endTargetUnitIndex = targetUnitIndex - 2;
                } else {
                    int tempUnitIndex1 = targetUnitIndex - 1;
                    Unit tempUnit1 = wholeUnits.get(tempUnitIndex1);
                    boolean isGoto = (getUnitType(tempUnit1) == GOTO);
                    if (isGoto) {
                        Unit tempUnit2 = getTargetUnit(tempUnit1);
                        int tempUnitIndex2 = wholeUnits.indexOf(tempUnit2);
                        if (tempUnitIndex2 < tempUnitIndex1) {
                            continue;
                        }

                        startTargetUnitIndex = tempUnitIndex1;
                        endTargetUnitIndex = tempUnitIndex2;
                    }
                }

                if (startTargetUnitIndex > 0 && endTargetUnitIndex > 0) {
                    for (int j = startTargetUnitIndex; j < endTargetUnitIndex; j++) {
                        infeasibleUnits.add(wholeUnits.get(j));
                    }
                }
            }
        }

        return infeasibleUnits;
    }

    private int getIfStatementResult(Unit unit) {
        JIfStmt stmt = (JIfStmt) unit;
        ValueBox conditionBox = stmt.getConditionBox();
        Value conditionValue = conditionBox.getValue();

        AbstractJimpleIntBinopExpr expr = (AbstractJimpleIntBinopExpr) conditionValue;
        ValueBox op1Box = expr.getOp1Box();
        Value op1 = op1Box.getValue();
        String op1Str = op1.toString();

        ValueBox op2Box = expr.getOp2Box();
        Value op2 = op2Box.getValue();
        String op2Str = op2.toString();

        Model model = new Model();
        IntVar v1 = convertStringToIntVar(model, op1Str);
        IntVar v2 = convertStringToIntVar(model, op2Str);
        ReExpression expression = getExpression(v1, conditionValue, v2);
        Constraint constraint = expression.decompose();
        constraint.post();

        int result;
        Solver solver = model.getSolver();
        boolean isSolve = solver.solve();
        if (isSolve) {
            BoolVar boolVar = expression.boolVar();
            result = boolVar.getValue();
        } else {
            result = 1; // default result
        }

        return result;
    }

    private IntVar convertStringToIntVar(Model model, String value) {
        if (value.equals("null")) {
            return model.intVar(0);
        }

        int minIntBound = MIN_INT_BOUND;
        int maxIntBound = MAX_INT_BOUND;

        try {
            int n = Integer.parseInt(value);
            if (n < minIntBound) {
                n = minIntBound;
            } else if (n > maxIntBound) {
                n = maxIntBound;
            }

            return model.intVar(n);
        } catch (NumberFormatException ignored) {
            return model.intVar(new int[]{minIntBound, maxIntBound});
        }
    }

    private ReExpression getExpression(IntVar n1, Value conditionValue, IntVar n2) {
        ReExpression e = null;

        if (conditionValue instanceof JGeExpr) {
            e = n1.ge(n2);
        } else if (conditionValue instanceof JGtExpr) {
            e = n1.gt(n2);
        } else if (conditionValue instanceof JEqExpr) {
            e = n1.eq(n2);
        } else if (conditionValue instanceof JNeExpr) {
            e = n1.ne(n2);
        } else if (conditionValue instanceof JLtExpr) {
            e = n1.lt(n2);
        } else if (conditionValue instanceof JLeExpr) {
            e = n1.le(n2);
        }

        return e;
    }

    private static class Holder {
        private static final ConstraintSolver instance = new ConstraintSolver();
    }
}