package com.ccadroid.util;

import org.chocosolver.solver.Model;
import org.chocosolver.solver.Solver;
import org.chocosolver.solver.constraints.Constraint;
import org.chocosolver.solver.variables.IntVar;
import org.chocosolver.util.ESat;

public class ChocoSolver {
    private static final long TIMEOUT = 180L;

    public ChocoSolver() throws InstantiationException {
        throw new InstantiationException();
    }

    public static int getResolveResult(String str1, String operand, String str2) {
        Model model = new Model();
        IntVar v1 = convertToIntVar(model, str1);
        IntVar v2 = convertToIntVar(model, str2);
        Constraint constraint = model.arithm(v1, operand, v2);
        constraint.post();

        Solver solver = model.getSolver();
        solver.limitTime(TIMEOUT);
        if (solver.isFeasible() == ESat.FALSE) {
            return -1;
        }

        return solver.solve() ? 1 : 0;
    }

    private static IntVar convertToIntVar(Model model, String str) {
        if (str == null) {
            return model.intVar(IntVar.MIN_INT_BOUND, IntVar.MAX_INT_BOUND);
        } else if (Integer.parseInt(str) <= IntVar.MIN_INT_BOUND) {
            return model.intVar(IntVar.MIN_INT_BOUND);
        } else if (IntVar.MAX_INT_BOUND <= Integer.parseInt(str)) {
            return model.intVar(IntVar.MAX_INT_BOUND);
        } else {
            return model.intVar(Integer.parseInt(str));
        }
    }
}