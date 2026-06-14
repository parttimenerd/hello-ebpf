package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ArenaAccessCheckPass}.
 *
 * <p>Verifies that {@code @InArena}-annotated parameters (and locals) calling
 * {@code .asLong()} produce warnings, while non-arena pointers doing the same do not.
 *
 * <p>Note: {@code bpfArenaAllocPages} seeding requires full type-resolution (the pass
 * uses method symbols to identify the BPFJ owner). In parse-only mode, that path is
 * inactive. The {@code @InArena} annotation path is purely syntactic and is fully
 * exercised here.
 */
class ArenaAccessCheckPassTest {

    private static List<ArenaAccessCheckPass.Detection> detect(String source, String methodName) {
        return ArenaAccessCheckPass.detect(JavacTestSupport.parseMethod(source, methodName));
    }

    // ── @InArena parameter triggers warning ─────────────────────────────

    @Test
    void inArenaParamWithAsLongProducesWarning() {
        var d = detect("""
                class T {
                    @interface InArena {}
                    void f(@InArena Object arena) {
                        long x = arena.asLong();
                    }
                }
                """, "f");
        assertEquals(1, d.size(), "@InArena param with .asLong() must produce exactly one warning");
        assertEquals("arena.aslong-leak", d.get(0).category());
        assertTrue(d.get(0).message().contains("arena"), "message should name the variable");
    }

    @Test
    void inArenaParamWithoutAsLongIsClean() {
        var d = detect("""
                class T {
                    @interface InArena {}
                    void f(@InArena Object arena) {
                        Object x = arena;   // no .asLong() call
                    }
                }
                """, "f");
        assertEquals(0, d.size(), "@InArena param without .asLong() should produce no warning");
    }

    // ── @InArena local variable triggers warning ──────────────────────

    @Test
    void inArenaLocalWithAsLongProducesWarning() {
        var d = detect("""
                class T {
                    @interface InArena {}
                    void f() {
                        @InArena Object local = null;
                        long x = local.asLong();
                    }
                }
                """, "f");
        assertEquals(1, d.size(), "@InArena local with .asLong() must produce a warning");
        assertTrue(d.get(0).message().contains("local"), "message should name the variable");
    }

    // ── Non-arena pointers are not flagged ────────────────────────────

    @Test
    void nonArenaPointerAsLongIsNotFlagged() {
        var d = detect("""
                class T {
                    void f(Object p) {
                        long x = p.asLong();   // p is not @InArena → no warning
                    }
                }
                """, "f");
        assertEquals(0, d.size(), "non-arena pointer with .asLong() must not be flagged");
    }

    @Test
    void plainMethodWithoutAsLongIsClean() {
        var d = detect("""
                class T {
                    @interface InArena {}
                    void f(@InArena Object arena) {
                        arena.someOtherMethod();
                    }
                }
                """, "f");
        assertEquals(0, d.size(), ".someOtherMethod() on arena pointer must not fire");
    }

    // ── Multiple arena vars ────────────────────────────────────────────

    @Test
    void multipleArenaVarsEachFireSeparately() {
        var d = detect("""
                class T {
                    @interface InArena {}
                    void f(@InArena Object a, @InArena Object b) {
                        long x = a.asLong();
                        long y = b.asLong();
                    }
                }
                """, "f");
        assertEquals(2, d.size(), "each @InArena var with .asLong() should produce its own warning");
    }

    @Test
    void singleArenaVarCalledTwiceFiresTwice() {
        var d = detect("""
                class T {
                    @interface InArena {}
                    void f(@InArena Object arena) {
                        long x = arena.asLong();
                        long y = arena.asLong();
                    }
                }
                """, "f");
        assertEquals(2, d.size(), "each .asLong() call on an arena var should produce its own warning");
    }

    // ── Shadowing: local shadows class field ────────────────────────────

    @Test
    void nonArenaLocalShadowsArenaParam() {
        // A local with the same name but without @InArena shadows the param → no warning.
        var d = detect("""
                class T {
                    @interface InArena {}
                    void f(@InArena Object x) {
                        Object x = null;         // non-@InArena local shadows param
                        long v = x.asLong();     // should NOT warn (local is not arena)
                    }
                }
                """, "f");
        assertEquals(0, d.size(),
                "non-@InArena local shadowing an @InArena param must not be flagged");
    }

    // ── Message format ───────────────────────────────────────────────────

    @Test
    void warningMessageIsFourPart() {
        var d = detect("""
                class T {
                    @interface InArena {}
                    void f(@InArena Object arena) {
                        long x = arena.asLong();
                    }
                }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("Why:"), "message must contain Why: — got:\n" + msg);
        assertTrue(msg.contains("Fix:"), "message must contain Fix: — got:\n" + msg);
        assertTrue(msg.contains("See:"), "message must contain See: — got:\n" + msg);
    }
}
