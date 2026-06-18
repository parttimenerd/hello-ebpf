package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link StackBudgetPass}. */
class StackBudgetPassTest {

    private static List<StackBudgetPass.Detection> detect(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        return StackBudgetPass.detect(m);
    }

    @Test
    void smallMethodHasNoWarning() {
        var d = detect("class T { void f() { int a = 1; long b = 2; } }", "f");
        assertEquals(0, d.size());
    }

    @Test
    void warnsAtThreshold() {
        // 384 / 64 = 6 buffers of 64 bytes each = 384 — at warn threshold.
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() {
                    @Size(64) byte[] a = new byte[64];
                    @Size(64) byte[] b = new byte[64];
                    @Size(64) byte[] c = new byte[64];
                    @Size(64) byte[] d_ = new byte[64];
                    @Size(64) byte[] e = new byte[64];
                    @Size(64) byte[] g = new byte[64];
                } }
                """, "f");
        assertEquals(1, d.size());
        assertFalse(d.get(0).error(), "should be a warning, not an error");
        assertTrue(d.get(0).message().contains("approaches"));
        assertTrue(d.get(0).message().contains("384 bytes"));
    }

    @Test
    void belowThresholdIsClean() {
        // Slightly below 384.
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() {
                    @Size(100) byte[] a = new byte[100];
                    @Size(100) byte[] b = new byte[100];
                    @Size(100) byte[] c = new byte[100];
                    @Size(50)  byte[] d_ = new byte[50];
                } }
                """, "f");
        assertEquals(0, d.size());
    }

    @Test
    void errorsPastErrorThreshold() {
        // 1024 well exceeds 614.
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() {
                    @Size(1024) byte[] huge = new byte[1024];
                } }
                """, "f");
        assertEquals(1, d.size());
        assertTrue(d.get(0).error(), "should be an error past the error threshold");
        assertTrue(d.get(0).message().contains("exceeds"));
    }

    @Test
    void primitivesAreSizedCorrectly() {
        // 8 longs × 8 = 64; not enough.
        var d = detect("""
                class T { void f() {
                    long a, b, c, d_, e, g, h, i;
                } }
                """, "f");
        assertEquals(0, d.size());
    }

    @Test
    void messageIsFourPart() {
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() { @Size(700) byte[] big = new byte[700]; } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("Why:"));
        assertTrue(msg.contains("Fix:"));
        assertTrue(msg.contains("See:"));
    }

    @Test
    void unsizedArrayCountsAsPointer() {
        // No @Size — pass under-estimates as 8 bytes (pointer-shaped).
        var d = detect("""
                class T { void f() {
                    byte[] x = new byte[1024];
                    byte[] y = new byte[1024];
                } }
                """, "f");
        // 8 + 8 = 16 — well under threshold.
        assertEquals(0, d.size());
    }

    @Test
    void estimateBytesScalars() {
        var m = JavacTestSupport.parseMethod("""
                class T { void f() {
                    long L; int I; short S; byte B; double D; float F; char C; boolean Z;
                } }
                """, "f");
        var sum = StackBudgetPass.sumLocalStackBytes(m.getBody());
        // 8 + 4 + 2 + 1 + 8 + 4 + 2 + 1 = 30
        assertEquals(30L, sum);
    }
}
