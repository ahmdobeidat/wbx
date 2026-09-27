package com.x;
import org.springframework.expression.*;
import org.springframework.expression.spel.standard.SpelExpressionParser;
public class RuleEngine {
    private final ExpressionParser parser = new SpelExpressionParser();
    public Object evaluate(String rule) {
        Expression expr = parser.parseExpression(rule);   // SpEL injection -> RCE
        return expr.getValue();
    }
}
