package com.ccadroid.util;

import org.mariuszgromada.math.mxparser.Argument;
import org.mariuszgromada.math.mxparser.Expression;
import org.mariuszgromada.math.mxparser.License;

public class MathParser {

    static {
        License.iConfirmNonCommercialUse("CCA-Droid");
    }

    public MathParser() throws InstantiationException {
        throw new InstantiationException();
    }

    public static Double calculateExpression(String argumentString, String expressionString) {
        Argument argument = new Argument(argumentString);
        Expression e = new Expression(expressionString, argument);

        return e.calculate();
    }
}