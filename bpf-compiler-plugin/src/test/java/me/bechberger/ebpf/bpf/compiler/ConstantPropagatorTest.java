package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.flow.ConstantValue;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link ConstantPropagator}. */
class ConstantPropagatorTest {

    /** Run propagation on the body of {@code methodName} and return the populated context. */
    private static me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext run(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        return ConstantPropagator.propagate(m.getBody());
    }

    /** Find the first sub-expression that is exactly a literal-or-identifier of the given source text. */
    private static ExpressionTree findExpression(Tree subtree, String exactSource) {
        var found = new ArrayList<ExpressionTree>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void scan(Tree t, Void unused) {
                if (t instanceof ExpressionTree e && e.toString().equals(exactSource)) {
                    found.add(e);
                }
                return super.scan(t, unused);
            }
        }.scan(subtree, null);
        if (found.isEmpty()) fail("no expression matched '" + exactSource + "' in:\n" + subtree);
        return found.get(0);
    }

    /** All RHS expressions of variable declarations in source order. */
    private static List<ExpressionTree> initializers(MethodTree m) {
        var out = new ArrayList<ExpressionTree>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(VariableTree node, Void unused) {
                if (node.getInitializer() != null) out.add(node.getInitializer());
                return super.visitVariable(node, unused);
            }
        }.scan(m.getBody(), null);
        return out;
    }

    @Test
    void integerLiteralFolds() {
        var m = JavacTestSupport.parseMethod("class T { void f() { int x = 7; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        var v = ctx.get(ConstantPropagator.CONST, rhs);
        assertNotNull(v);
        assertTrue(v.isConstant());
        assertEquals(7L, v.asLong());
    }

    @Test
    void arithmeticOnLiteralsFolds() {
        var m = JavacTestSupport.parseMethod("class T { void f() { int x = 2 + 3 * 4; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        var v = ctx.get(ConstantPropagator.CONST, rhs);
        assertEquals(14L, v.asLong());
    }

    @Test
    void copyPropagationThroughLocal() {
        var m = JavacTestSupport.parseMethod("""
                class T { int f() { int a = 5; int b = a + 1; return b; } }
                """, "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var bInit = initializers(m).get(1); // 'a + 1'
        var v = ctx.get(ConstantPropagator.CONST, bInit);
        assertEquals(6L, v.asLong());
    }

    @Test
    void reassignmentWidensToTop() {
        var m = JavacTestSupport.parseMethod("""
                class T { int f(int n) { int a = 5; a = n; int b = a + 1; return b; } }
                """, "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        // After `a = n`, `a` is TOP, so `b = a + 1` should not be a recorded constant.
        var bInit = initializers(m).get(1);
        var v = ctx.get(ConstantPropagator.CONST, bInit);
        assertNull(v, "b should not be a known constant after a was widened: " + v);
    }

    @Test
    void unaryMinusOnLiteralFolds() {
        var m = JavacTestSupport.parseMethod("class T { void f() { int x = -42; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        var v = ctx.get(ConstantPropagator.CONST, rhs);
        assertEquals(-42L, v.asLong());
    }

    @Test
    void bitwiseComplementFolds() {
        var m = JavacTestSupport.parseMethod("class T { void f() { int x = ~0; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        assertEquals(-1L, ctx.get(ConstantPropagator.CONST, rhs).asLong());
    }

    @Test
    void shiftAndBitwiseAndFold() {
        var m = JavacTestSupport.parseMethod("class T { void f() { int x = (1 << 4) | 3; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        assertEquals(19L, ctx.get(ConstantPropagator.CONST, rhs).asLong());
    }

    @Test
    void divisionByZeroIsTop() {
        var m = JavacTestSupport.parseMethod("class T { int f(int n) { int x = 10 / 0; return x; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        // div-by-zero should be widened to TOP, not recorded as a fold.
        assertNull(ctx.get(ConstantPropagator.CONST, rhs));
    }

    @Test
    void parameterReadIsTop() {
        var m = JavacTestSupport.parseMethod("class T { int f(int n) { int x = n + 1; return x; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        assertNull(ctx.get(ConstantPropagator.CONST, rhs),
                "x = n + 1 must not be a known constant when n is a parameter");
    }

    @Test
    void comparisonFoldsToBoolean() {
        var m = JavacTestSupport.parseMethod("class T { void f() { boolean b = 5 < 7; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        assertEquals(1L, ctx.get(ConstantPropagator.CONST, rhs).asLong());
    }

    @Test
    void floatLiteralsAreNotTracked() {
        var m = JavacTestSupport.parseMethod("class T { void f() { double x = 3.14; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        // Float/double literals are intentionally TOP (never recorded as a fold).
        assertNull(ctx.get(ConstantPropagator.CONST, rhs));
    }

    @Test
    void booleanLiteralsFold() {
        var m = JavacTestSupport.parseMethod("class T { void f() { boolean t = true; boolean f2 = false; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var inits = initializers(m);
        assertEquals(1L, ctx.get(ConstantPropagator.CONST, inits.get(0)).asLong());
        assertEquals(0L, ctx.get(ConstantPropagator.CONST, inits.get(1)).asLong());
    }

    @Test
    void incrementWidensToTop() {
        var m = JavacTestSupport.parseMethod("""
                class T { int f() { int a = 1; a++; int b = a + 1; return b; } }
                """, "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var bInit = initializers(m).get(1);
        assertNull(ctx.get(ConstantPropagator.CONST, bInit),
                "after a++, a is TOP, so b should not be a recorded constant");
    }

    @Test
    void compoundAssignmentWidensToTop() {
        var m = JavacTestSupport.parseMethod("""
                class T { int f() { int a = 1; a += 5; int b = a + 1; return b; } }
                """, "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var bInit = initializers(m).get(1);
        assertNull(ctx.get(ConstantPropagator.CONST, bInit));
    }

    @Test
    void mergeAfterIfWithDifferingAssignmentsIsTop() {
        var m = JavacTestSupport.parseMethod("""
                class T { int f(boolean c) {
                    int a = 0;
                    if (c) { a = 1; } else { a = 2; }
                    int b = a + 1;
                    return b;
                } }
                """, "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var bInit = initializers(m).get(1);
        // a joins to TOP across the branches → b is also TOP.
        assertNull(ctx.get(ConstantPropagator.CONST, bInit),
                "joined a (1 vs 2) should widen, leaving b unrecorded");
    }

    @Test
    void mergeAfterIfWithEqualAssignmentsKeepsConstant() {
        var m = JavacTestSupport.parseMethod("""
                class T { int f(boolean c) {
                    int a = 0;
                    if (c) { a = 7; } else { a = 7; }
                    int b = a + 1;
                    return b;
                } }
                """, "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var bInit = initializers(m).get(1);
        var v = ctx.get(ConstantPropagator.CONST, bInit);
        assertNotNull(v, "a joins to 7 in both branches, so b should be 8");
        assertEquals(8L, v.asLong());
    }

    @Test
    void loopBodyAssignmentWidensVar() {
        var m = JavacTestSupport.parseMethod("""
                class T { int f() {
                    int a = 5;
                    for (int i = 0; i < 4; i++) { a = a + 1; }
                    int b = a + 1;
                    return b;
                } }
                """, "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        // Variables in declaration order: a, i (loop init), b. Pick b's init.
        var bInit = initializers(m).get(2);
        assertNull(ctx.get(ConstantPropagator.CONST, bInit),
                "after a loop body that mutates a, b cannot be a known constant");
    }

    @Test
    void cleanMethodHasNoConstants() {
        var m = JavacTestSupport.parseMethod("class T { int f(int x) { return x + x; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        // No constants recorded — `x + x` involves an unknown parameter.
        assertNull(ctx.get(ConstantPropagator.CONST, m.getBody()));
    }

    @Test
    void parenthesizedExpressionsFold() {
        var m = JavacTestSupport.parseMethod("class T { void f() { int x = ((1 + 2)) * 3; } }", "f");
        var ctx = ConstantPropagator.propagate(m.getBody());
        var rhs = initializers(m).get(0);
        assertEquals(9L, ctx.get(ConstantPropagator.CONST, rhs).asLong());
    }
}
