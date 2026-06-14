package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.CaptureAnalyzer.CaptureKind;
import me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link CaptureAnalyzer#classifyByName}. */
class CaptureAnalyzerTest {

    @Test
    void primitiveCapturesByValue() {
        for (var t : new String[]{"int", "long", "short", "byte", "boolean", "char", "float", "double"}) {
            var c = CaptureAnalyzer.classifyByName("x", t, true, MemoryRegion.STACK);
            assertEquals(CaptureKind.VALUE, c.kind(), "primitive " + t + " should be by-value");
        }
    }

    @Test
    void boxedScalarCapturesByValue() {
        for (var t : new String[]{
                "java.lang.Long", "java.lang.Integer", "java.lang.Short", "java.lang.Byte",
                "java.lang.Boolean", "java.lang.Character", "java.lang.Float", "java.lang.Double"}) {
            var c = CaptureAnalyzer.classifyByName("x", t, true, MemoryRegion.STACK);
            assertEquals(CaptureKind.VALUE, c.kind(), t + " should be by-value");
        }
    }

    @Test
    void ptrCapturesByValue() {
        var c = CaptureAnalyzer.classifyByName("p",
                "me.bechberger.ebpf.type.Ptr", true, MemoryRegion.KERNEL_TRACKED);
        assertEquals(CaptureKind.VALUE, c.kind());
    }

    @Test
    void parameterizedPtrCapturesByValue() {
        var c = CaptureAnalyzer.classifyByName("p",
                "me.bechberger.ebpf.type.Ptr<task_struct>", true, MemoryRegion.KERNEL_TRACKED);
        assertEquals(CaptureKind.VALUE, c.kind());
    }

    @Test
    void stackDeclaredTypeCapturesByRef() {
        var c = CaptureAnalyzer.classifyByName("e", "com.example.Event", true, MemoryRegion.STACK);
        assertEquals(CaptureKind.BY_REF, c.kind());
    }

    @Test
    void nonStackJavaObjectIsRejected() {
        var c = CaptureAnalyzer.classifyByName("s", "java.lang.String", true, MemoryRegion.UNKNOWN);
        assertEquals(CaptureKind.REJECT, c.kind());
        assertTrue(c.reason().contains("java.lang.String"));
    }

    @Test
    void unknownTypeFallsBackToValue() {
        // No type info: pass through (the Translator's ad-hoc walk will catch any real bugs).
        var c = CaptureAnalyzer.classifyByName("x", null, false, MemoryRegion.UNKNOWN);
        assertEquals(CaptureKind.VALUE, c.kind());
    }

    @Test
    void rejectMessageQuotesTypeName() {
        var c = CaptureAnalyzer.classifyByName("x", "java.util.HashMap", true, MemoryRegion.UNKNOWN);
        assertEquals(CaptureKind.REJECT, c.kind());
        assertTrue(c.reason().contains("java.util.HashMap"));
    }

    @Test
    void heapDeclaredTypeRejected() {
        // A non-stack region with a declared type triggers REJECT.
        var c = CaptureAnalyzer.classifyByName("e", "com.example.Event", true, MemoryRegion.MAP_VALUE);
        assertEquals(CaptureKind.REJECT, c.kind());
    }

    @Test
    void mapValueRegionWithUserType() {
        var c = CaptureAnalyzer.classifyByName("v", "com.foo.Bar", true, MemoryRegion.MAP_VALUE);
        assertEquals(CaptureKind.REJECT, c.kind());
    }
}
