package me.bechberger.ebpf.compiler;

import me.bechberger.ebpf.annotations.bpf.BPFTailCallTable;
import me.bechberger.ebpf.annotations.bpf.TailCallSlot;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic sanity checks on the annotation shapes; the interesting compile-error
 * assertions arrive in Task 2 once the processor discovers them.
 */
public class TailCallTableCompileErrorTest {

    @Test
    public void tailCallTableTargetsField() {
        Target t = BPFTailCallTable.class.getAnnotation(Target.class);
        assertNotNull(t);
        assertArrayEquals(new ElementType[]{ElementType.FIELD}, t.value());
    }

    @Test
    public void tailCallTableRuntimeRetained() {
        Retention r = BPFTailCallTable.class.getAnnotation(Retention.class);
        assertEquals(RetentionPolicy.RUNTIME, r.value());
    }

    @Test
    public void tailCallSlotTargetsMethod() {
        Target t = TailCallSlot.class.getAnnotation(Target.class);
        assertNotNull(t);
        assertArrayEquals(new ElementType[]{ElementType.METHOD}, t.value());
    }

    @Test
    public void tailCallSlotHasEmptyTableDefault() throws Exception {
        String def = (String) TailCallSlot.class
                .getMethod("table").getDefaultValue();
        assertEquals("", def);
    }

    // ── real processor diagnostic tests ────────────────────────────────────

    private static final String PKG = "tail_call_test";

    private static javax.annotation.processing.Processor newProcessor() {
        return new me.bechberger.ebpf.bpf.processor.Processor();
    }

    private static InMemoryJavaCompiler.Source bpfClass(String simpleName, String body) {
        return new InMemoryJavaCompiler.Source(PKG + "." + simpleName,
                "package " + PKG + ";\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class " + simpleName + " extends BPFProgram {\n"
                        + "  public enum Slot { A, B, C }\n"
                        + body
                        + "\n}\n");
    }

    @Test
    public void errorWhenTableWithoutMapDefinition() {
        var src = bpfClass("T1",
                "@BPFTailCallTable(slots = Slot.class) BPFProgArray t;");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("missing @BPFMapDefinition must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@BPFTailCallTable requires @BPFMapDefinition", "t");
    }

    @Test
    public void errorWhenMaxEntriesMismatch() {
        var src = bpfClass("T2",
                "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 5) BPFProgArray t;");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("maxEntries mismatch must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "3 constant", "maxEntries=5", "set maxEntries = 3");
    }

    @Test
    public void errorWhenSlotConstantUnknown() {
        var src = bpfClass("T3",
                "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 3) BPFProgArray t;\n"
              + "@BPFFunction(section = \"xdp\")\n"
              + "@TailCallSlot(\"Z\")\n"
              + "public int slotZ() { return 0; }");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("unknown slot must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@TailCallSlot(\"Z\")", "no such constant", "[A, B, C]");
    }

    @Test
    public void errorWhenAnnotationOnNonProgArrayField() {
        var src = bpfClass("T4",
                "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 3) BPFHashMap<Integer, Long> t;");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("wrong map type must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@BPFTailCallTable only applies to BPFProgArray",
                "BPFHashMap");
    }

    @Test
    public void errorWhenAmbiguousTable() {
        var src = bpfClass("T5",
                "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 3) BPFProgArray t1;\n"
              + "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 3) BPFProgArray t2;\n"
              + "@BPFFunction(section = \"xdp\")\n"
              + "@TailCallSlot(\"A\")\n"
              + "public int a() { return 0; }");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("ambiguous must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "declares 2 @BPFTailCallTable fields", "disambiguate", "t1", "t2");
    }
}
