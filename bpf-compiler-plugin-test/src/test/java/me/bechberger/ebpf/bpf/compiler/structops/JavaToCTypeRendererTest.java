package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Pure-function tests for {@link JavaToCTypeRenderer}. Covers the primitive
 * table, {@code Ptr<X>} unwrapping to {@code struct X *}, {@code String}
 * rendering, and the negative path.
 */
class JavaToCTypeRendererTest {

    @Test
    void primitives() {
        var r = new JavaToCTypeRenderer();
        assertEquals("void", r.render("void"));
        assertEquals("int", r.render("int"));
        assertEquals("long", r.render("long"));
        // Unsigned annotations translate to the correct u<width>.
        assertEquals("__u32", r.renderWithAnnotation("int", true));
        assertEquals("__u64", r.renderWithAnnotation("long", true));
        assertEquals("__u16", r.renderWithAnnotation("short", true));
        assertEquals("__u8", r.renderWithAnnotation("byte", true));
        assertEquals("bool", r.render("boolean"));
    }

    @Test
    void ptrGenericsUnwrapToStructPointer() {
        var r = new JavaToCTypeRenderer();
        assertEquals("struct sock *",
                r.render("me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.runtime.sock>"));
        assertEquals("struct task_struct *",
                r.render("me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.TaskDefinitions.task_struct>"));
    }

    @Test
    void stringRendersAsCharArrayForDataFields() {
        var r = new JavaToCTypeRenderer();
        // The BTF field's exact type wins for `String` → the renderer just
        // returns "char *" here; the synthesizer uses the BTF field type
        // (`char[16]`) as the emit type in the struct instance.
        assertEquals("char *", r.render("java.lang.String"));
    }

    @Test
    void unsupportedTypeThrows() {
        var r = new JavaToCTypeRenderer();
        assertThrows(IllegalArgumentException.class, () -> r.render("java.util.List"));
    }
}
