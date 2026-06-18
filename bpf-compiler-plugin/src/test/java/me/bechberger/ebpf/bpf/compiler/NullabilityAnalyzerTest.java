package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the full nullability analysis in {@link NullabilityAnalyzer}.
 *
 * <p>Complements {@link NullabilityAnalyzerAlwaysExitsTest} which only covers the
 * {@code alwaysExits} helper. These tests exercise the real analysis: MAYBE_NULL
 * tracking, null-check narrowing, join semantics after branches, and guard-with-early-return.
 */
class NullabilityAnalyzerTest {

    private static List<NullabilityAnalyzer.Detection> detect(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        return NullabilityAnalyzer.detect(m);
    }

    // ── Basic null literal ───────────────────────────────────────────────

    @Test
    void nullLiteralAssignmentIsMaybeNull() {
        // Assigning null gives MAYBE_NULL; subsequent deref must fire.
        var d = detect("""
                class T { void f() {
                    Object x = null;
                    x.toString();
                } }
                """, "f");
        assertEquals(1, d.size(), "null literal → MAYBE_NULL should produce exactly one detection");
        assertTrue(d.get(0).message().contains("x"), "message should name the variable");
    }

    @Test
    void nonNullAssignmentIsClean() {
        // Non-null initializer should not fire.
        var d = detect("""
                class T {
                    Object safe() { return new Object(); }
                    void f() {
                        Object x = safe();
                        x.toString();
                    }
                }
                """, "f");
        assertEquals(0, d.size(), "non-null source should produce no detection");
    }

    // ── Null-check narrowing: then-branch ────────────────────────────────

    @Test
    void nullCheckNarrowsThenBranch() {
        // `if (x != null)` → inside the then-branch x is NON_NULL → safe to use.
        var d = detect("""
                class T { void f() {
                    Object x = null;
                    if (x != null) {
                        x.toString();   // safe: narrowed in then-branch
                    }
                } }
                """, "f");
        assertEquals(0, d.size(), "x narrowed to NON_NULL inside then-branch — no detection expected");
    }

    @Test
    void afterNullCheckWithoutElseIsMaybeNull() {
        // After the if (no else) the variable is still MAYBE_NULL at the join point.
        var d = detect("""
                class T { void f() {
                    Object x = null;
                    if (x != null) {
                        // some work
                    }
                    x.toString();   // unsafe: x may be null post-if
                } }
                """, "f");
        assertEquals(1, d.size(), "x is MAYBE_NULL after an if without else");
    }

    // ── Guard with early return ──────────────────────────────────────────

    @Test
    void guardWithEarlyReturnMakesPostIfSafe() {
        // Classic BPF pattern: if (p == null) return; then p is safe post-if.
        var d = detect("""
                class T { void f() {
                    Object p = null;
                    if (p == null) return;
                    p.toString();   // safe: the then-branch always exits
                } }
                """, "f");
        assertEquals(0, d.size(), "after null-guard-with-return, p is NON_NULL — no detection");
    }

    @Test
    void guardWithEarlyReturnInsideBlock() {
        // Same pattern but with the guard inside a block.
        var d = detect("""
                class T { void f() {
                    Object p = null;
                    if (p == null) { return; }
                    p.toString();
                } }
                """, "f");
        assertEquals(0, d.size());
    }

    // ── Join semantics after if/else ─────────────────────────────────────

    @Test
    void joinAfterBothBranchesPreservesNarrowing() {
        // Both branches exit → unreachable code after if; no deref follows, so no detection.
        var d = detect("""
                class T { void f() {
                    Object x = null;
                    if (x != null) { return; } else { return; }
                } }
                """, "f");
        assertEquals(0, d.size(), "both branches exit → no post-if dereference possible");
    }

    @Test
    void joinAfterIfElseMergesMaybeNull() {
        // In then-branch x is reassigned (NON_NULL via plain call); else-branch x stays MAYBE_NULL.
        // After the join, x should be MAYBE_NULL → deref fires.
        var d = detect("""
                class T {
                    Object other() { return new Object(); }
                    void f(boolean cond) {
                        Object x = null;
                        if (cond) {
                            x = other();  // NON_NULL in then
                        }
                        // In else x is still null → after join x is MAYBE_NULL
                        x.toString();
                    }
                }
                """, "f");
        assertEquals(1, d.size(), "x is MAYBE_NULL after join (one branch doesn't null-check)");
    }

    // ── Message format ───────────────────────────────────────────────────

    @Test
    void detectionMessageIsFourPart() {
        var d = detect("""
                class T { void f() {
                    Object x = null;
                    x.foo();
                } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("Why:"), "message should contain Why: — got:\n" + msg);
        assertTrue(msg.contains("Fix:"), "message should contain Fix: — got:\n" + msg);
        assertTrue(msg.contains("See:"), "message should contain See: — got:\n" + msg);
    }

    @Test
    void detectionCategoryIsCorrect() {
        var d = detect("""
                class T { void f() {
                    Object x = null;
                    x.bar();
                } }
                """, "f");
        assertEquals(1, d.size());
        assertEquals("nullability.deref-of-nullable", d.get(0).category());
    }

    // ── No false positives on common patterns ────────────────────────────

    @Test
    void cleanMethodHasNoDetections() {
        var d = detect("""
                class T { void f(int x) { int y = x + 1; } }
                """, "f");
        assertEquals(0, d.size());
    }

    @Test
    void unknownVariableIsNotFlagged() {
        // A variable with no explicit null init is UNKNOWN → conservative, no fire.
        var d = detect("""
                class T {
                    Object createSomething() { return new Object(); }
                    void f() {
                        Object x = createSomething();
                        x.hashCode();
                    }
                }
                """, "f");
        assertEquals(0, d.size());
    }
}
