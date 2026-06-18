package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Declarator;
import me.bechberger.cast.CAST.Declarator.FunctionParameter;
import me.bechberger.cast.CAST.Declarator.IdentifierDeclarator;
import me.bechberger.cast.CAST.PrimaryExpression.Constant;
import me.bechberger.cast.CAST.PrimaryExpression.Constant.IntegerConstant;
import me.bechberger.cast.CAST.PrimaryExpression.Variable;
import me.bechberger.cast.CAST.Statement.CompoundStatement;
import me.bechberger.cast.CAST.Statement.VerbatimStatement;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument.Lambda;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument.Value;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.CallArgs;
import me.bechberger.ebpf.bpf.compiler.MethodTemplateCache.TemplateRenderException;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.List;

import static me.bechberger.cast.CAST.Expression.constant;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

class MethodTemplateTest {

    @Test
    public void testBasic() {
        assertRendered("$name", "func(1, 2)", List.of(1, 2));
        assertRendered("func($args)", "func(1, 2)", List.of(1, 2));
        assertRendered("func($args)", "func(1)", List.of(1));
        assertRendered("func($args)", "func()", List.of());
        assertRendered("((int)function($args))", "((int)function(1, 2))", List.of(1, 2));
    }

    @Test
    public void testSubArgs() {
        assertRendered("func($args2_, $arg1)", "func(2, 3, 1)", List.of(1, 2, 3));
    }

    @Test
    public void testArg() {
        assertRendered("func($arg1)", "func(1)", List.of(1));
        assertRendered("func($arg1, $arg2)", "func(2, 3)", List.of(2, 3));
    }

    @Test
    public void testThis() {
        assertRendered("func($this)", "func(\"this\")", "this", List.of());
        assertRendered("$this[$arg1]", "\"this\"[\"a\"]", "this", List.of("a"));
    }

    @Test
    public void testStrLen() {
        assertRendered("$strlen$arg1", "1", null, List.of("a"));
        assertRendered("$strlen$this", "4", "abcd", List.of(""));
    }

    @Test
    public void testStr() {
        assertRendered("$str$arg1", "a", null, List.of("a"));
    }

    @Test
    public void testTypeArguments() {
        assertRenderedWithTA("func($T1)", "func(int)", List.of("int"));
        assertThrowsExactly(TemplateRenderException.class, () -> assertRenderedWithTA("func($T1)", "func(s32)",
                List.of()));
    }

    @Test
    public void testTypeof() {
        assertRendered("$typeof$arg1 *x = $arg1", "__typeof__(1) *x = 1", List.of(1));
        assertRendered("$typeof$arg2", "__typeof__(2)", List.of(1, 2));
    }

    @Test
    public void testSizeof() {
        assertRendered("$sizeof$arg1", "sizeof(1)", List.of(1));
        assertRendered("buf_len = $sizeof$arg2", "buf_len = sizeof(2)", List.of(1, 2));
    }

    @Test
    public void testDeref() {
        assertRendered("$deref$arg1", "*(1)", List.of(1));
        assertRendered("$deref$arg1 + $deref$arg2", "*(1) + *(2)", List.of(1, 2));
    }

    @Test
    public void testTypeofInGnuStatement() {
        // Simulates the pattern used in bpf_increment / bpf_getOrDefault templates
        assertRendered("({ $typeof$arg2 *___v = $arg1; ___v ? *___v : $arg2; })",
                "({ __typeof__(2) *___v = 1; ___v ? *___v : 2; })",
                List.of(1, 2));
    }

    @Test
    public void testLambda() {
        assertRendered("$arg2 $lambda1:param1 $lambda1:param1:type $lambda1:param1:name1 $lambda1:code",
                        "1 T a T a1 x = a;",
                new Lambda(List.of(new FunctionParameter(new Variable("a"),
                        new IdentifierDeclarator(new Variable("T")))),
                        new CompoundStatement(List.of(new VerbatimStatement("x = a;")))),
                new Value(CAST.Expression.constant(1)));
    }

    static void assertRendered(String template, String expected, List<Integer> arguments) {
        assertEquals(expected, MethodTemplate.parse("func", template)
                .call(new CallArgs(null, arguments.stream().map(CAST.Expression::constant).map(Value::new).toList(), List.of()))
                .toPrettyString());
    }

    static void assertRendered(String template, String expected, Argument... arguments) {
        assertEquals(expected, MethodTemplate.parse("func", template)
                .call(new CallArgs(null, List.of(arguments), List.of()))
                .toPrettyString());
    }

    static void assertRendered(String template, String expected, @Nullable String thisString, List<String> arguments) {
    assertEquals(expected, MethodTemplate.parse("func", template)
            .call(new CallArgs(thisString == null ? null : constant(thisString),
                    arguments.stream().map(CAST.Expression::constant).map(Value::new).toList(), List.of()))
            .toPrettyString());
    }

    static void assertRenderedWithTA(String template, String expected, List<String> typeArguments) {
        assertEquals(expected, MethodTemplate.parse("func", template)
                .call(new CallArgs(null, List.of(),
                        typeArguments.stream().map(Declarator::identifier).toList()))
                .toPrettyString());
    }
}