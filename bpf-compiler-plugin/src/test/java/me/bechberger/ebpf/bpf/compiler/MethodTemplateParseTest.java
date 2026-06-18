package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Expression;
import me.bechberger.cast.CAST.PrimaryExpression.Constant;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.Argument.Value;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.CallArgs;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.TemplatePart;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.TemplatePart.Args;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.TemplatePart.Arg;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.TemplatePart.Name;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.TemplatePart.SubArgs;
import me.bechberger.ebpf.bpf.compiler.MethodTemplate.TemplatePart.Verbatim;
import me.bechberger.ebpf.bpf.compiler.MethodTemplateCache.TemplateRenderException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pins the parse behavior of {@link MethodTemplate#parse(String, String)}. The parser is the
 * heart of the {@code @BuiltinBPFFunction} template language, so anchor the tricky edge cases
 * (empty input, special-cased {@code $name}, $argN/$argsN, escape patterns, malformed input).
 */
class MethodTemplateParseTest {

    @Test
    void emptyTemplateProducesEmptyParts() {
        var t = MethodTemplate.parse("foo", "");
        assertTrue(t.parts().isEmpty(), "empty template → no parts");
    }

    @Test
    void verbatimOnlyTemplate() {
        var t = MethodTemplate.parse("foo", "hello world");
        assertEquals(1, t.parts().size());
        assertInstanceOf(Verbatim.class, t.parts().get(0));
        assertEquals("hello world", ((Verbatim) t.parts().get(0)).verb());
    }

    @Test
    void bareDollarNameExpandsToCanonicalCallShape() {
        // Special case in parser: a template that is exactly $name expands to $name($args).
        var t = MethodTemplate.parse("foo", "$name");
        assertEquals(4, t.parts().size(), "expected: Name, '(', Args, ')'");
        assertInstanceOf(Name.class, t.parts().get(0));
        assertEquals("(", ((Verbatim) t.parts().get(1)).verb());
        assertInstanceOf(Args.class, t.parts().get(2));
        assertEquals(")", ((Verbatim) t.parts().get(3)).verb());
    }

    @Test
    void nameWithSuffixDoesNotExpandToCanonicalCallShape() {
        // Only a *single* Name part triggers the canonical expansion. $name() -> Name + "()".
        var t = MethodTemplate.parse("foo", "$name()");
        assertEquals(2, t.parts().size());
        assertInstanceOf(Name.class, t.parts().get(0));
        assertEquals("()", ((Verbatim) t.parts().get(1)).verb());
    }

    @Test
    void argNumbersAreOneIndexedInTemplateZeroIndexedInArg() {
        // $arg1 → Arg(0), $arg2 → Arg(1).
        var t = MethodTemplate.parse("foo", "f($arg1, $arg2)");
        assertEquals(0, ((Arg) t.parts().get(1)).n());
        assertEquals(1, ((Arg) t.parts().get(3)).n());
    }

    @Test
    void argsAndSubArgsParseDistinctly() {
        // $args → Args (all args). $args2 → SubArgs(1) (args from index 1 to end).
        var t = MethodTemplate.parse("foo", "f($args)");
        assertInstanceOf(Args.class, t.parts().get(1));

        var t2 = MethodTemplate.parse("foo", "f($args2)");
        var sub = (SubArgs) t2.parts().get(1);
        assertEquals(1, sub.n());
    }

    @Test
    void argNUnderscoreIsTreatedAsSubArgsFromN() {
        // $arg1_ → SubArgs(0): "all args starting from index 0", with the underscore consumed.
        var t = MethodTemplate.parse("foo", "f($arg1_)");
        var sub = (SubArgs) t.parts().get(1);
        assertEquals(0, sub.n());
    }

    @Test
    void thisIsRecognised() {
        var t = MethodTemplate.parse("foo", "$this->$name");
        assertInstanceOf(TemplatePart.This.class, t.parts().get(0));
        assertEquals("->", ((Verbatim) t.parts().get(1)).verb());
        assertInstanceOf(Name.class, t.parts().get(2));
    }

    @Test
    void unknownPlaceholderThrowsTemplateRenderException() {
        assertThrows(TemplateRenderException.class,
                () -> MethodTemplate.parse("foo", "$bogus"));
    }

    @Test
    void typeArgumentParsesAsExpected() {
        // $T1 → TypeArgument(0).
        var t = MethodTemplate.parse("foo", "($T1*)null");
        assertEquals(3, t.parts().size());
        assertInstanceOf(TemplatePart.TypeArgument.class, t.parts().get(1));
    }

    @Test
    void classTypeArgumentParsesAsExpected() {
        var t = MethodTemplate.parse("foo", "($C1*)null");
        assertInstanceOf(TemplatePart.ClassTypeArgument.class, t.parts().get(1));
    }

    @Test
    void strlenWithoutArgIsRejected() {
        // $strlen must be followed by $argN or $this. $strlen$name should fail.
        assertThrows(TemplateRenderException.class,
                () -> MethodTemplate.parse("foo", "$strlen$name"));
    }

    @Test
    void strlenWithThisProducesStrLenThis() {
        var t = MethodTemplate.parse("foo", "$strlen$this");
        assertInstanceOf(TemplatePart.StrLenThis.class, t.parts().get(0));
    }

    @Test
    void strlenWithArgProducesStrLenArg() {
        var t = MethodTemplate.parse("foo", "$strlen$arg2");
        var part = (TemplatePart.StrLenArg) t.parts().get(0);
        assertEquals(1, part.n());
    }

    @Test
    void multipleVerbatimAndArgsRoundTripThroughRender() {
        // End-to-end smoke test of parse + render with no lambdas/typeargs.
        var t = MethodTemplate.parse("bpf_foo", "$name($args)");
        Argument a1 = new Value(new Constant.IntegerConstant(1));
        Argument a2 = new Value(new Constant.IntegerConstant(2));
        var rendered = t.call(new CallArgs(null, List.of(a1, a2), List.of())).toPrettyString();
        assertEquals("bpf_foo(1, 2)", rendered);
    }

    @Test
    void renderArgsEmptyDropsTrailingComma() {
        // The renderer special-cases "verbatim ending in comma + empty $argsN": drops the comma.
        var t = MethodTemplate.parse("bpf_foo", "$name(0, $args2)");
        Argument a1 = new Value(new Constant.IntegerConstant(7));
        // Only one arg → $args2 (SubArgs(1)) renders empty, comma should be dropped.
        var rendered = t.call(new CallArgs(null, List.of(a1), List.of())).toPrettyString();
        assertEquals("bpf_foo(0)", rendered);
    }

    @Test
    void funcRefPlaceholderParsesArgIndex() {
        // $func1 → FuncRef(0, PLAIN).
        var t = MethodTemplate.parse("foo", "bpf_loop(n, $func1, NULL, 0)");
        var func = (TemplatePart.FuncRef) t.parts().get(1);
        assertEquals(0, func.n());
        assertEquals(MethodTemplate.FuncShape.PLAIN, func.shape());
    }

    @Test
    void funcRefMapelemShapeIsParsed() {
        var t = MethodTemplate.parse("foo", "bpf_for_each_map_elem(map, $func2:mapelem, NULL, 0)");
        var func = (TemplatePart.FuncRef) t.parts().get(1);
        assertEquals(1, func.n());
        assertEquals(MethodTemplate.FuncShape.MAPELEM, func.shape());
    }

    @Test
    void lambdaCodePlaceholderParses() {
        var t = MethodTemplate.parse("foo", "{ $lambda1:code }");
        // Parts: Verbatim("{ "), LambdaCode(0), Verbatim(" }")
        assertEquals(3, t.parts().size());
        var code = (TemplatePart.LambdaCode) t.parts().get(1);
        assertEquals(0, code.n());
    }

    @Test
    void lambdaParamWithoutSuffixParses() {
        // $lambda1:param2 → LambdaParam(0, 1)
        var t = MethodTemplate.parse("foo", "$lambda1:param2");
        var lp = (TemplatePart.LambdaParam) t.parts().get(0);
        assertEquals(0, lp.n());
        assertEquals(1, lp.m());
    }

    @Test
    void lambdaParamTypeAndNameParse() {
        var tType = MethodTemplate.parse("foo", "$lambda1:param1:type");
        assertInstanceOf(TemplatePart.LambdaParamType.class, tType.parts().get(0));

        var tName = MethodTemplate.parse("foo", "$lambda1:param1:name");
        assertInstanceOf(TemplatePart.LambdaParamName.class, tName.parts().get(0));
    }

    @Test
    void lambdaWithoutColonAfterNumberRejected() {
        // $lambda1foo → missing ':' after number → exception.
        assertThrows(TemplateRenderException.class,
                () -> MethodTemplate.parse("foo", "$lambda1foo"));
    }

    @Test
    void unknownLambdaSuffixRejected() {
        assertThrows(TemplateRenderException.class,
                () -> MethodTemplate.parse("foo", "$lambda1:bogus"));
    }

    @Test
    void rawTemplateIsPreservedOnTheRecord() {
        var t = MethodTemplate.parse("foo", "$name($args)");
        assertEquals("$name($args)", t.raw());
        assertEquals("foo", t.methodName());
    }

    @Test
    void escapingViaDoubleDollarEatsTheDollar() {
        // KNOWN BEHAVIOR: '$$' splits to ["", "", "..."] → the empty middle part is skipped,
        // so '$$name' renders as the special bare-name case (Name → expanded to Name(args)).
        // Pin this so future refactors don't silently change it.
        var t = MethodTemplate.parse("foo", "$$name");
        // Parts after special-case expansion: Name, "(", Args, ")".
        assertEquals(4, t.parts().size());
        assertInstanceOf(Name.class, t.parts().get(0));
    }

    // ── $autosize$argN ──────────────────────────────────────────────────────

    @Test
    void autosizeArgParsesAsAutoSizeArgPart() {
        var t = MethodTemplate.parse("foo", "$autosize$arg1");
        assertEquals(1, t.parts().size());
        assertInstanceOf(MethodTemplate.TemplatePart.AutoSizeArg.class, t.parts().get(0));
        assertEquals(0, ((MethodTemplate.TemplatePart.AutoSizeArg) t.parts().get(0)).n());
    }

    @Test
    void autosizeArgRendersResolvedSize() {
        var t = MethodTemplate.parse("bpf_get_current_comm",
                "bpf_get_current_comm($arg1, $autosize$arg1)");
        Argument bufArg = new Value(new CAST.PrimaryExpression.VerbatimExpression("&comm"));
        var args = new CallArgs(null, List.of(bufArg), List.of(), List.of(), null,
                index -> index == 0 ? 16 : null);
        assertEquals("bpf_get_current_comm(&comm, 16)", t.call(args).toPrettyString());
    }

    @Test
    void autosizeArgWithoutResolverThrows() {
        var t = MethodTemplate.parse("foo", "$autosize$arg1");
        Argument a = new Value(new CAST.PrimaryExpression.VerbatimExpression("x"));
        var args = new CallArgs(null, List.of(a), List.of());
        var ex = assertThrows(TemplateRenderException.class, () -> t.call(args));
        assertTrue(ex.getMessage().contains("no size resolver"), ex.getMessage());
    }

    @Test
    void autosizeArgWhenResolverReturnsNullThrowsHelpfulError() {
        var t = MethodTemplate.parse("bpf_get_current_comm",
                "bpf_get_current_comm($arg1, $autosize$arg1)");
        Argument a = new Value(new CAST.PrimaryExpression.VerbatimExpression("x"));
        var args = new CallArgs(null, List.of(a), List.of(), List.of(), null, index -> null);
        var ex = assertThrows(TemplateRenderException.class, () -> t.call(args));
        assertTrue(ex.getMessage().contains("Add @Size(N)"), ex.getMessage());
        assertTrue(ex.getMessage().contains("bpf_get_current_comm"), ex.getMessage());
    }

    @Test
    void autosizeArgRequiresArgN() {
        // $autosize without $argN is a parse error, like $sizeof / $deref.
        var ex = assertThrows(TemplateRenderException.class,
                () -> MethodTemplate.parse("foo", "$autosize"));
        assertTrue(ex.getMessage().contains("autosize"), ex.getMessage());
    }
}
