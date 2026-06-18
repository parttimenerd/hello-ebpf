package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link MissingCoreReadPass#detect(com.sun.source.tree.Tree)}. */
class MissingCoreReadPassTest {

    private static List<MissingCoreReadPass.Detection> detect(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        return MissingCoreReadPass.detect(m.getBody());
    }

    private static boolean has(List<MissingCoreReadPass.Detection> ds) {
        return ds.stream().anyMatch(d -> d.category().equals("region.missing-core-read"));
    }

    @Test
    void directFieldAccessOnCastIsRejected() {
        // p.<Foo>cast().field — canonical Stage 15.3 shape.
        var d = detect("""
                class T { int f(Object p) { return p.<Object>cast().field; } }
                """, "f");
        assertTrue(has(d), "direct field on .cast() result must fire: " + d);
    }

    @Test
    void directFieldAccessOnCastValIsRejected() {
        // p.<Foo>cast().val().field — same shape via .val().
        var d = detect("""
                class T { int f(Object p) { return p.<Object>cast().val().field; } }
                """, "f");
        assertTrue(has(d), "field on cast().val() must fire: " + d);
    }

    @Test
    void parenthesizedCastChainIsRejected() {
        var d = detect("""
                class T { int f(Object p) { return (p.<Object>cast()).field; } }
                """, "f");
        assertTrue(has(d));
    }

    @Test
    void plainFieldAccessIsAccepted() {
        var d = detect("""
                class T { int f(Object o) { return o.field; } }
                """, "f");
        assertTrue(d.isEmpty(), "plain field access must not fire: " + d);
    }

    @Test
    void valWithoutCastIsAccepted() {
        // `.val().field` without an upstream `.cast()` is fine — the auto-emit handles it.
        var d = detect("""
                class T { int f(Object p) { return p.val().field; } }
                """, "f");
        assertTrue(d.isEmpty(), "val()-only chain must not fire: " + d);
    }

    @Test
    void castMethodNameIsNotAField() {
        // `p.cast` (the method reference, not a field access) must not fire.
        var d = detect("""
                class T { Object f(Object p) { return p.<Object>cast(); } }
                """, "f");
        assertTrue(d.isEmpty(), "the cast() invocation itself must not be flagged: " + d);
    }

    @Test
    void messageIsFourPart() {
        var d = detect("""
                class T { int f(Object p) { return p.<Object>cast().myField; } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("Why:"), "missing Why: " + msg);
        assertTrue(msg.contains("Fix:"), "missing Fix: " + msg);
        assertTrue(msg.contains("See:"), "missing See: " + msg);
        assertTrue(msg.contains("myField"), "message should name the field: " + msg);
    }

    @Test
    void cleanMethodHasNoDetections() {
        var d = detect("""
                class T { int f(int x) { return x + 1; } }
                """, "f");
        assertTrue(d.isEmpty());
    }
}
