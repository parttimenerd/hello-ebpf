package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.ExpressionStatementTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.ReturnTree;
import com.sun.source.tree.StatementTree;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link BoundsCheckPass}'s pure shape-walking helpers
 * ({@code rootIdentifier} / {@code rootMatches}). They unwrap parens and
 * peel back the {@code .add/.sub/.cast/.val} receiver chain to find the
 * leaf identifier — the basis for matching guarded vs unguarded packet
 * dereferences.
 */
class BoundsCheckPassHelpersTest {

    /** Pull the expression out of `return <expr>;` in the parsed method body. */
    private static ExpressionTree firstReturnExpression(String source) {
        MethodTree m = JavacTestSupport.parseMethod(source, "f");
        for (StatementTree s : m.getBody().getStatements()) {
            if (s instanceof ReturnTree r && r.getExpression() != null) {
                return r.getExpression();
            }
            if (s instanceof ExpressionStatementTree es) {
                return es.getExpression();
            }
        }
        throw new AssertionError("no return/expr-stmt in body");
    }

    @Test
    void plainIdentifierIsItsOwnRoot() {
        var e = firstReturnExpression("class T { Object f(Object x) { return x; } }");
        assertEquals("x", BoundsCheckPass.rootIdentifier(e));
    }

    @Test
    void parenthesizedIdentifierIsUnwrapped() {
        var e = firstReturnExpression("class T { Object f(Object x) { return (x); } }");
        assertEquals("x", BoundsCheckPass.rootIdentifier(e));
    }

    @Test
    void doubleParenthesesAreFullyUnwrapped() {
        var e = firstReturnExpression("class T { Object f(Object x) { return ((x)); } }");
        assertEquals("x", BoundsCheckPass.rootIdentifier(e));
    }

    @Test
    void addCallPeelsToReceiver() {
        var e = firstReturnExpression("class T { Object f(Object p) { return p.add(4); } }");
        assertEquals("p", BoundsCheckPass.rootIdentifier(e));
    }

    @Test
    void chainedAddSubValPeelsAllTheWayDown() {
        var e = firstReturnExpression("""
                class T { Object f(Object p) { return p.add(4).sub(1).cast().val(); } }
                """);
        assertEquals("p", BoundsCheckPass.rootIdentifier(e));
    }

    @Test
    void unrelatedMethodCallReturnsNull() {
        // foo() is not in the whitelist add/sub/cast/val — no leaf identifier reachable.
        var e = firstReturnExpression("class T { Object f(Object p) { return p.foo(); } }");
        assertNull(BoundsCheckPass.rootIdentifier(e));
    }

    @Test
    void rootMatchesReturnsTrueForMatchingName() {
        var e = firstReturnExpression("class T { Object f(Object p) { return p.add(1); } }");
        assertTrue(BoundsCheckPass.rootMatches(e, "p"));
        assertFalse(BoundsCheckPass.rootMatches(e, "q"));
    }

    @Test
    void rootMatchesReturnsFalseWhenNoIdentifierReached() {
        var e = firstReturnExpression("class T { int f() { return 1 + 1; } }");
        assertFalse(BoundsCheckPass.rootMatches(e, "anything"));
    }

    @Test
    void parensInsideChainAreUnwrapped() {
        // Parens between calls — the .add receiver is "(p)", which unwrap should peel.
        var e = firstReturnExpression("""
                class T { Object f(Object p) { return ((p)).add(2); } }
                """);
        assertEquals("p", BoundsCheckPass.rootIdentifier(e));
    }

    @Test
    void typeCastIsNotUnwrapped() {
        // KNOWN GAP: unwrap only handles ParenthesizedTree, not TypeCastTree.
        // `((Object) p).add(1)` therefore yields null, even though semantically `p` is the root.
        var e = firstReturnExpression("""
                class T { Object f(Object p) { return ((Object) p).add(1); } }
                """);
        assertNull(BoundsCheckPass.rootIdentifier(e),
                "type cast inside the chain isn't unwrapped — known gap");
    }
}
