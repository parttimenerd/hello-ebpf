package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link MapValueIndexBoundsPass}. */
class MapValueIndexBoundsPassTest {

    private static List<MapValueIndexBoundsPass.Detection> detect(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        var ctx = ConstantPropagator.propagate(m.getBody());
        return MapValueIndexBoundsPass.detect(m.getBody(), ctx);
    }

    @Test
    void inRangeConstantIndexIsAccepted() {
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() { @Size(8) byte[] buf = new byte[8]; byte b = buf[3]; } }
                """, "f");
        assertEquals(0, d.size());
    }

    @Test
    void outOfRangeConstantIndexIsRejected() {
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() { @Size(8) byte[] buf = new byte[8]; byte b = buf[8]; } }
                """, "f");
        assertEquals(1, d.size());
        assertEquals("bounds.array-index-out-of-range", d.get(0).category());
        assertTrue(d.get(0).message().contains("Array index 8"));
        assertTrue(d.get(0).message().contains("@Size(8)"));
    }

    @Test
    void negativeConstantIndexIsRejected() {
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() { @Size(4) byte[] buf = new byte[4]; byte b = buf[-1]; } }
                """, "f");
        assertEquals(1, d.size());
        assertTrue(d.get(0).message().contains("Array index -1"));
    }

    @Test
    void propagatedConstantIndexIsRejected() {
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() {
                    @Size(4) byte[] buf = new byte[4];
                    int i = 2 + 3;
                    byte b = buf[i];
                } }
                """, "f");
        assertEquals(1, d.size());
        assertTrue(d.get(0).message().contains("Array index 5"));
    }

    @Test
    void nonConstantIndexIsAccepted() {
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f(int i) { @Size(4) byte[] buf = new byte[4]; byte b = buf[i]; } }
                """, "f");
        // i is a parameter → TOP → no detection (runtime check is the verifier's job).
        assertEquals(0, d.size());
    }

    @Test
    void unsizedArrayIsIgnored() {
        var d = detect("class T { void f() { byte[] buf = new byte[8]; byte b = buf[42]; } }", "f");
        // No @Size annotation → pass cannot reason; defer to verifier.
        assertEquals(0, d.size());
    }

    @Test
    void zeroIndexEdgeCase() {
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() { @Size(4) byte[] buf = new byte[4]; byte b = buf[0]; } }
                """, "f");
        assertEquals(0, d.size());
    }

    @Test
    void messageIsFourPart() {
        var d = detect("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() { @Size(2) byte[] buf = new byte[2]; byte b = buf[7]; } }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("Why:"), "missing Why:");
        assertTrue(msg.contains("Fix:"), "missing Fix:");
        assertTrue(msg.contains("See:"), "missing See:");
    }

    @Test
    void emptyContextStillCatchesLiterals() {
        // The pass folds a literal index inline (so it works without a populated context).
        var m = JavacTestSupport.parseMethod("""
                import me.bechberger.ebpf.annotations.Size;
                class T { void f() { @Size(4) byte[] buf = new byte[4]; byte b = buf[10]; } }
                """, "f");
        var d = MapValueIndexBoundsPass.detect(m.getBody(), new AnalysisContext());
        assertEquals(1, d.size());
        assertTrue(d.get(0).message().contains("Array index 10"));
    }
}
