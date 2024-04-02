package me.bechberger.cast;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static me.bechberger.cast.CAST.Declarator.*;
import static me.bechberger.cast.CAST.Expression.constant;
import static me.bechberger.cast.CAST.Expression.variable;
import static me.bechberger.cast.CAST.OperatorExpression.binary;
import static me.bechberger.cast.CAST.PrimaryExpression.CAnnotation.sec;
import static me.bechberger.cast.CAST.Statement.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Basic AST tests
 */
public class ASTTest {

    static Stream<Arguments> exprAstAndExpectedCode() {
        return Stream.of(Arguments.of(expression(binary("+", constant(1), constant(2))), "1 + 2;"));
    }

    @ParameterizedTest
    @MethodSource("exprAstAndExpectedCode")
    void testExpr(CAST.Statement statement, String expectedCode) {
        assertEquals(expectedCode, statement.toPrettyString());
    }

    static Stream<Arguments> declAstAndExpectedCode() {
        return Stream.of(Arguments.of(variableDefinition(struct(variable("myStruct"),
                List.of(structMember(CAST.Declarator.identifier("int"), variable("b")))), variable("myVar", sec("a")))
                , "struct myStruct {\n  int b;\n} myVar SEC(\"a\");"),
                Arguments.of(variableDefinition(struct(variable("myStruct"),
                                List.of(structMember(CAST.Declarator.identifier("int"), variable("b"), constant(1)))),
                                variable(
                                        "myVar", sec("a")))
                        , "struct myStruct {\n  int (b, 1);\n} myVar SEC(\"a\");"),
                Arguments.of(
                        struct(variable("x"),
                            List.of(structMember(array(identifier("a"),
                                    constant(10)),
                                    variable("x")))).toStatement(),
                """
                struct x {
                  a x[10];
                };"""));
    }

    @ParameterizedTest
    @MethodSource("declAstAndExpectedCode")
    void testDecl(Statement ast, String expectedCode) {
        assertEquals(expectedCode, ast.toPrettyString());
    }
}