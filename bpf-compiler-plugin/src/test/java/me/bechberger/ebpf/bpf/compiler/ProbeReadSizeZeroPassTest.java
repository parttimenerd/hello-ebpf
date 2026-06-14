package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link ProbeReadSizeZeroPass#detect(com.sun.source.tree.Tree)}. */
class ProbeReadSizeZeroPassTest {

    private static List<ProbeReadSizeZeroPass.Detection> detect(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        return ProbeReadSizeZeroPass.detect(m.getBody());
    }

    private static boolean has(List<ProbeReadSizeZeroPass.Detection> ds) {
        return ds.stream().anyMatch(d -> d.category().equals("bounds.probe-read-zero"));
    }

    @Test
    void probeReadKernelWithLiteralZeroSizeIsRejected() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_kernel(dst, 0, src); } }
                """, "f");
        assertTrue(has(d), "literal 0 size must fire: " + d);
    }

    @Test
    void probeReadUserWithLiteralZeroSizeIsRejected() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_user(dst, 0, src); } }
                """, "f");
        assertTrue(has(d));
    }

    @Test
    void probeReadKernelStrWithLiteralZeroSizeIsRejected() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_kernel_str(dst, 0, src); } }
                """, "f");
        assertTrue(has(d));
    }

    @Test
    void probeReadUserStrWithLiteralZeroSizeIsRejected() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_user_str(dst, 0, src); } }
                """, "f");
        assertTrue(has(d));
    }

    @Test
    void parenthesizedZeroIsRejected() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_kernel(dst, (0), src); } }
                """, "f");
        assertTrue(has(d), "parenthesised 0 must still fire: " + d);
    }

    @Test
    void unaryMinusZeroIsRejected() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_kernel(dst, -0, src); } }
                """, "f");
        assertTrue(has(d));
    }

    @Test
    void nonZeroLiteralIsAccepted() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_kernel(dst, 16, src); } }
                """, "f");
        assertTrue(d.isEmpty(), "non-zero literal must not fire: " + d);
    }

    @Test
    void nonLiteralSizeIsAccepted() {
        // We only flag a literal 0; runtime-derived 0 is the verifier's job to catch.
        var d = detect("""
                class T { void f(Object dst, Object src, int n) { bpf_probe_read_kernel(dst, n, src); } }
                """, "f");
        assertTrue(d.isEmpty(), "non-literal size must not fire: " + d);
    }

    @Test
    void sizeofExpressionIsAccepted() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_kernel(dst, sizeof(dst), src); } }
                """, "f");
        assertTrue(d.isEmpty(), "sizeof() call must not fire: " + d);
    }

    @Test
    void unrelatedHelperWithZeroIsAccepted() {
        // Other helpers happen to take a literal 0 in their second arg legally.
        var d = detect("""
                class T { void f(Object x) { bpf_map_lookup_elem(x, 0); } }
                """, "f");
        assertTrue(d.isEmpty(), "non-probe-read helper must not be touched: " + d);
    }

    @Test
    void messageHasFourParts() {
        var d = detect("""
                class T { void f(Object dst, Object src) { bpf_probe_read_kernel(dst, 0, src); } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("Why:"), "missing Why: " + msg);
        assertTrue(msg.contains("Fix:"), "missing Fix: " + msg);
        assertTrue(msg.contains("See:"), "missing See: " + msg);
    }
}
