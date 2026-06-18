package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.MethodTree;
import com.sun.source.tree.StatementTree;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link NullabilityAnalyzer#alwaysExits} — the reachability helper that lets
 * {@code if (p == null) return; *p;} be analyzed as safe (the post-if env keeps the else-branch's
 * NON_NULL narrowing instead of joining a dead then-branch).
 */
class NullabilityAnalyzerAlwaysExitsTest {

    private static StatementTree firstStmt(String src, String methodName) {
        MethodTree m = JavacTestSupport.parseMethod(src, methodName);
        return m.getBody().getStatements().get(0);
    }

    @Test
    void returnAlwaysExits() {
        var s = firstStmt("class T { void f() { return; } }", "f");
        assertTrue(NullabilityAnalyzer.alwaysExits(s));
    }

    @Test
    void throwAlwaysExits() {
        var s = firstStmt("class T { void f() { throw new RuntimeException(); } }", "f");
        assertTrue(NullabilityAnalyzer.alwaysExits(s));
    }

    @Test
    void plainExpressionDoesNotAlwaysExit() {
        var s = firstStmt("class T { void f() { int x = 1; } }", "f");
        assertFalse(NullabilityAnalyzer.alwaysExits(s));
    }

    @Test
    void blockWithReturnAlwaysExits() {
        var s = firstStmt("""
                class T { void f() {
                    { int x = 1; return; }
                } }
                """, "f");
        assertTrue(NullabilityAnalyzer.alwaysExits(s),
                "a block with a return inside always exits");
    }

    @Test
    void blockWithoutReturnDoesNotAlwaysExit() {
        var s = firstStmt("""
                class T { void f() {
                    { int x = 1; int y = 2; }
                } }
                """, "f");
        assertFalse(NullabilityAnalyzer.alwaysExits(s));
    }

    @Test
    void ifWithoutElseDoesNotAlwaysExit() {
        // if (cond) return; — falls through when cond is false.
        var s = firstStmt("""
                class T { void f(int x) {
                    if (x > 0) return;
                } }
                """, "f");
        assertFalse(NullabilityAnalyzer.alwaysExits(s),
                "if without else can fall through when the condition is false");
    }

    @Test
    void ifWithBothBranchesReturningAlwaysExits() {
        var s = firstStmt("""
                class T { int f(int x) {
                    if (x > 0) return 1; else return 2;
                } }
                """, "f");
        assertTrue(NullabilityAnalyzer.alwaysExits(s));
    }

    @Test
    void ifWithOnlyOneBranchReturningDoesNotAlwaysExit() {
        var s = firstStmt("""
                class T { int f(int x) {
                    if (x > 0) return 1; else { /* nothing */ }
                    return 0;
                } }
                """, "f");
        assertFalse(NullabilityAnalyzer.alwaysExits(s),
                "the else-branch falls through, so the if itself doesn't always exit");
    }

    @Test
    void nestedBlockWithReturnAlwaysExits() {
        var s = firstStmt("""
                class T { void f() {
                    { { return; } }
                } }
                """, "f");
        assertTrue(NullabilityAnalyzer.alwaysExits(s));
    }

    @Test
    void nullStatementIsHandledGracefully() {
        // The actual analyzer never feeds null in, but be defensive.
        assertFalse(NullabilityAnalyzer.alwaysExits(null));
    }
}
