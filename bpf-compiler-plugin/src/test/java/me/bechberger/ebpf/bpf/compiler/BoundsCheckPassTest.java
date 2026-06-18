package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the full packet bounds-check analysis in {@link BoundsCheckPass}.
 *
 * <p>Complements {@link BoundsCheckPassHelpersTest} which only tests the pure
 * helpers {@code rootIdentifier} / {@code rootMatches}. These tests drive the full
 * {@link BoundsCheckPass#detect(com.sun.source.tree.MethodTree)} path:
 * packet-origin detection, transitive origin via {@code .cast()}, guard collection
 * via {@code .greaterThan()} / {@code .lessThan()}, and unguarded-deref warnings.
 */
class BoundsCheckPassTest {

    private static List<BoundsCheckPass.Detection> detect(String source, String methodName) {
        return BoundsCheckPass.detect(JavacTestSupport.parseMethod(source, methodName));
    }

    // ── Packet-origin detection ──────────────────────────────────────────

    @Test
    void directDataFieldIsRecognisedAsPacketOrigin() {
        // `p = ctx.data` — the ".data" member-select is the canonical packet-origin shape.
        var d = detect("""
                class T { void f(Object ctx) {
                    Object p = ctx.data;
                    p.val();   // unguarded → warning
                } }
                """, "f");
        assertEquals(1, d.size(), "unguarded .data packet pointer should produce one detection");
        assertEquals("bounds.unguarded-packet-deref", d.get(0).category());
    }

    @Test
    void voidPointerDataIsRecognisedAsPacketOrigin() {
        // `p = Ptr.voidPointer(ctx.data)` — wrapped in member-select voidPointer call.
        var d = detect("""
                class Ptr { static Object voidPointer(Object x) { return x; } }
                class T {
                    void f(Object ctx) {
                        Object p = Ptr.voidPointer(ctx.data);
                        p.val();   // unguarded → warning
                    }
                }
                """, "f");
        assertEquals(1, d.size(), "Ptr.voidPointer(ctx.data) should be a recognised packet origin");
    }

    @Test
    void nonPacketPointerIsNotFlagged() {
        // Normal variable not derived from .data → should not be tracked.
        var d = detect("""
                class T { void f(Object ctx) {
                    Object p = ctx.pid;   // .pid, not .data
                    p.val();
                } }
                """, "f");
        assertEquals(0, d.size(), "non-packet pointer should not be flagged");
    }

    // ── Transitive origin via .cast() ────────────────────────────────────

    @Test
    void transitiveOriginViaCastIsTracked() {
        // q = p.cast() where p is a packet origin → q is also a packet origin.
        var d = detect("""
                class T { void f(Object ctx) {
                    Object p = ctx.data;   // packet origin
                    Object q = p.cast();   // transitive
                    q.val();               // unguarded → warning
                } }
                """, "f");
        assertEquals(1, d.size(), "transitive packet origin via .cast() must be detected");
        assertEquals("bounds.unguarded-packet-deref", d.get(0).category());
    }

    @Test
    void transitiveOriginViaAddIsTracked() {
        var d = detect("""
                class T { void f(Object ctx) {
                    Object p = ctx.data;
                    Object q = p.add(4);
                    q.val();               // unguarded → warning
                } }
                """, "f");
        assertEquals(1, d.size(), "transitive packet origin via .add() must be detected");
    }

    // ── Guard collection ─────────────────────────────────────────────────

    @Test
    void greaterThanGuardSuppressesWarning() {
        // p.greaterThan(end) anywhere in the method → p is guarded → no warning.
        var d = detect("""
                class T { void f(Object ctx) {
                    Object end = ctx.data_end;
                    Object p = ctx.data;
                    if (p.greaterThan(end)) return;
                    p.val();   // guarded → no warning
                } }
                """, "f");
        assertEquals(0, d.size(), ".greaterThan guard should suppress the warning");
    }

    @Test
    void lessThanGuardSuppressesWarning() {
        var d = detect("""
                class T { void f(Object ctx) {
                    Object end = ctx.data_end;
                    Object p = ctx.data;
                    if (end.lessThan(p)) return;
                    p.val();
                } }
                """, "f");
        assertEquals(0, d.size(), ".lessThan guard (on end, with p as arg) should suppress warning");
    }

    @Test
    void guardOnTransitivePointerSuppressesAll() {
        // Guard on q (derived from p) should guard q; p is still unguarded → still warns for p.
        var d = detect("""
                class T { void f(Object ctx) {
                    Object end = ctx.data_end;
                    Object p = ctx.data;
                    Object q = p.cast();
                    if (q.greaterThan(end)) return;
                    p.val();   // p is NOT guarded (only q is) → warning for p
                    q.val();   // q IS guarded → no warning
                } }
                """, "f");
        // p.val() should warn; q.val() should not.
        assertEquals(1, d.size(), "only p (unguarded) should warn; q (guarded) should not");
    }

    @Test
    void multiplePacketPointersOnlyUnguardedWarn() {
        // Two packet pointers: one guarded, one not.
        var d = detect("""
                class T { void f(Object ctx) {
                    Object end = ctx.data_end;
                    Object p = ctx.data;
                    Object q = p.add(4);
                    p.greaterThan(end);    // guard for p
                    p.val();               // guarded → no warn
                    q.val();               // unguarded → warn
                } }
                """, "f");
        assertEquals(1, d.size(), "only q is unguarded — should produce exactly one detection");
    }

    // ── Unguarded dereference ────────────────────────────────────────────

    @Test
    void unguardedValFiresOnce() {
        var d = detect("""
                class T { void f(Object ctx) {
                    Object p = ctx.data;
                    p.val();
                } }
                """, "f");
        assertEquals(1, d.size());
    }

    @Test
    void multipleUnguardedDerefsFireMultipleTimes() {
        var d = detect("""
                class T { void f(Object ctx) {
                    Object p = ctx.data;
                    p.val();
                    p.val();
                    p.val();
                } }
                """, "f");
        assertEquals(3, d.size(), "each unguarded .val() should produce its own detection");
    }

    @Test
    void noDataAccessMeansNoDetections() {
        var d = detect("""
                class T { void f(int x) { int y = x + 1; } }
                """, "f");
        assertEquals(0, d.size(), "method with no .data access should produce no detections");
    }

    // ── Message format ───────────────────────────────────────────────────

    @Test
    void detectionMessageIsFourPart() {
        var d = detect("""
                class T { void f(Object ctx) {
                    Object p = ctx.data;
                    p.val();
                } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("Why:"), "message must contain Why: — got:\n" + msg);
        assertTrue(msg.contains("Fix:"), "message must contain Fix: — got:\n" + msg);
        assertTrue(msg.contains("See:"), "message must contain See: — got:\n" + msg);
        assertTrue(msg.contains("p"), "message should name the pointer variable: " + msg);
    }
}
