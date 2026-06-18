package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link UnboundedLoopPass#detect(com.sun.source.tree.Tree)}. */
class UnboundedLoopPassTest {

    private static List<UnboundedLoopPass.Detection> detect(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        return UnboundedLoopPass.detect(m.getBody());
    }

    private static boolean has(List<UnboundedLoopPass.Detection> ds) {
        return ds.stream().anyMatch(d -> d.category().equals("bounds.unbounded-loop"));
    }

    @Test
    void whileTrueIsRejected() {
        var d = detect("""
                class T { void f() { while (true) { } } }
                """, "f");
        assertTrue(has(d), "while (true) must fire: " + d);
    }

    @Test
    void emptyForIsRejected() {
        var d = detect("""
                class T { void f() { for (;;) { } } }
                """, "f");
        assertTrue(has(d));
    }

    @Test
    void forWithLiteralBoundIsAccepted() {
        var d = detect("""
                class T { void f() { for (int i = 0; i < 16; i++) { } } }
                """, "f");
        assertTrue(d.isEmpty(), "literal-bounded for-loop must not fire: " + d);
    }

    @Test
    void forWithNonLiteralBoundIsRejected() {
        var d = detect("""
                class T { void f(int n) { for (int i = 0; i < n; i++) { } } }
                """, "f");
        assertTrue(has(d), "for(i<n) where n is non-literal must fire: " + d);
    }

    @Test
    void whileWithLiteralBoundIsAccepted() {
        var d = detect("""
                class T { void f() { int i = 0; while (i < 32) { i++; } } }
                """, "f");
        assertTrue(d.isEmpty(), "while(i<32) is bounded: " + d);
    }

    @Test
    void doWhileWithLiteralBoundIsAccepted() {
        var d = detect("""
                class T { void f() { int i = 0; do { i++; } while (i < 8); } }
                """, "f");
        assertTrue(d.isEmpty(), "do-while with literal bound is fine: " + d);
    }

    @Test
    void doWhileWithNonLiteralBoundIsRejected() {
        var d = detect("""
                class T { void f(int n) { int i = 0; do { i++; } while (i < n); } }
                """, "f");
        assertTrue(has(d));
    }

    @Test
    void enhancedForIsAcceptedHere() {
        // Out of scope for this pass; BoundsCheckPass handles dynamic-collection iteration.
        var d = detect("""
                class T { void f(int[] a) { for (int x : a) { } } }
                """, "f");
        assertTrue(d.isEmpty(), "for-each is intentionally not flagged here: " + d);
    }

    @Test
    void compoundConditionWithOneLiteralIsAccepted() {
        // 'i < 16 && cond' — the literal half is enough to bound iteration count.
        var d = detect("""
                class T {
                    void f(boolean cond) {
                        for (int i = 0; i < 16 && cond; i++) { }
                    }
                }
                """, "f");
        assertTrue(d.isEmpty(),
                "compound condition with literal-bounded clause should be accepted: " + d);
    }

    @Test
    void cleanMethodHasNoDetections() {
        var d = detect("""
                class T { int f(int x) { return x + 1; } }
                """, "f");
        assertTrue(d.isEmpty());
    }

    @Test
    void compoundOrConditionIsRejected() {
        // 'i < 16 || cond' — semantically the loop runs whenever EITHER is true, so the
        // literal bound on `i` does NOT bound the loop. The pass treats it as unbounded.
        var d = detect("""
                class T {
                    void f(boolean cond) {
                        for (int i = 0; i < 16 || cond; i++) { }
                    }
                }
                """, "f");
        assertTrue(has(d), "OR-compound condition must be flagged as unbounded: " + d);
    }

    @Test
    void parenthesizedConditionIsAccepted() {
        // Parens around the comparison should not change bounded-ness.
        var d = detect("""
                class T {
                    void f() { for (int i = 0; (i < 16); i++) { } }
                }
                """, "f");
        assertTrue(d.isEmpty(), "parenthesized literal-bounded condition: " + d);
    }

    @Test
    void unaryNegativeLiteralBoundIsAccepted() {
        // i > -1 — '-1' is UnaryTree(MINUS, LiteralTree(1)). Helper should recognise it.
        var d = detect("""
                class T {
                    void f() { for (int i = 10; i > -1; i--) { } }
                }
                """, "f");
        assertTrue(d.isEmpty(), "unary-negative literal bound should be accepted: " + d);
    }

    @Test
    void notEqualLiteralIsBounded() {
        // i != 100 — handled as bounded by the helper.
        var d = detect("""
                class T {
                    void f() { for (int i = 0; i != 100; i++) { } }
                }
                """, "f");
        assertTrue(d.isEmpty(), "i != 100 should be bounded: " + d);
    }

    @Test
    void forWithNonLiteralBoundIncludesBpfLoopFixIt() {
        // Stage 15.1: when bound is `i < n`, suggest BPFJ.bpfLoop(n, i -> ...).
        var d = detect("""
                class T { void f(int n) { for (int i = 0; i < n; i++) { } } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("BPFJ.bpfLoop(n, i -> { ... })"),
                "expected concrete bpfLoop fix-it with N=n, counter=i:\n" + msg);
    }

    @Test
    void forWithCustomCounterAndExpressionBoundEmitsExactFixIt() {
        // Bound is a member-select expression; counter is named 'idx'.
        var d = detect("""
                class T { void f(int[] arr) { for (int idx = 0; idx < arr.length; idx++) { } } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("BPFJ.bpfLoop(arr.length, idx -> { ... })"),
                "expected fix-it with bound=arr.length, counter=idx:\n" + msg);
    }

    @Test
    void whileWithNonLiteralBoundDoesNotIncludeBpfLoopFixIt() {
        // The fix-it heuristic only fires for `for(int i=0; i<N; i++)` shape;
        // while-loops get the generic suggestion (no specific N to plug in).
        var d = detect("""
                class T { void f(int n) { int i = 0; while (i < n) { i++; } } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertFalse(msg.contains("BPFJ.bpfLoop("),
                "while-loops should not get a specific bpfLoop fix-it:\n" + msg);
    }

    @Test
    void forWithLiteralBoundEmitsNoMessage() {
        // Sanity: the fix-it logic only matters for non-literal bounds; literal-bounded
        // for-loops still produce no detection at all.
        var d = detect("""
                class T { void f() { for (int i = 0; i < 16; i++) { } } }
                """, "f");
        assertTrue(d.isEmpty());
    }
}
