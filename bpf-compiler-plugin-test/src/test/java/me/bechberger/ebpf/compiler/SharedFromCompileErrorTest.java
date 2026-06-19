package me.bechberger.ebpf.compiler;

import me.bechberger.ebpf.compiler.InMemoryJavaCompiler.Source;
import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * Compile-time tests for {@code @SharedFrom} structural type checks.
 * Each test compiles a tiny synthetic producer/consumer pair via
 * {@link InMemoryJavaCompiler} with the bpf-processor as the annotation
 * processor and asserts the diagnostic text via
 * {@link DiagnosticAssert#assertContainsAll(java.util.List, String...)}.
 */
public class SharedFromCompileErrorTest {

    private static final String PKG = "shared_from_test";

    private static javax.annotation.processing.Processor newProcessor() {
        return new me.bechberger.ebpf.bpf.processor.Processor();
    }

    /** Build a minimal @BPF abstract class with the supplied body. */
    private static Source bpfClass(String simpleName, String body) {
        return new Source(PKG + "." + simpleName,
                "package " + PKG + ";\n"
                        + "import me.bechberger.ebpf.annotations.*;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class " + simpleName + " extends BPFProgram {\n"
                        + body
                        + "\n}\n");
    }

    // ── #21 producer lacks the named map ────────────────────────────────────

    @Test
    public void testErrorWhenProducerLacksMap() {
        var producer = bpfClass("P21",
                "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> bar;");
        var consumer = bpfClass("C21",
                "@SharedFrom(P21.class)\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> foo;");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("missing map should fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "no @BPFMapDefinition field 'foo'", "bar");
    }

    // ── #22 explicit mapName override missing ───────────────────────────────

    @Test
    public void testErrorWhenMapNameOverrideMissing() {
        var producer = bpfClass("P22",
                "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> realName;");
        var consumer = bpfClass("C22",
                "@SharedFrom(value = P22.class, mapName = \"wrong\")\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> realName;");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("wrong mapName must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "wrong", "realName");
    }

    // ── #23 raw map class differs ───────────────────────────────────────────

    @Test
    public void testErrorWhenMapTypeMismatchHashMapVsLruHashMap() {
        var producer = bpfClass("P23",
                "@BPFMapDefinition(maxEntries = 8) BPFLRUHashMap<Integer, Long> m;");
        var consumer = bpfClass("C23",
                "@SharedFrom(P23.class)\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> m;");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("HashMap vs LRUHashMap must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "BPFHashMap", "BPFLRUHashMap");
    }

    // ── #24 key primitive mismatch ──────────────────────────────────────────

    @Test
    public void testErrorWhenKeyTypeMismatchPrimitives() {
        var producer = bpfClass("P24",
                "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Long, Long> m;");
        var consumer = bpfClass("C24",
                "@SharedFrom(P24.class)\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> m;");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("Long vs Integer key must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "type-parameter", "Integer", "Long");
    }

    // ── #25 value primitive mismatch ────────────────────────────────────────

    @Test
    public void testErrorWhenValueTypeMismatchPrimitives() {
        var producer = bpfClass("P25",
                "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> m;");
        var consumer = bpfClass("C25",
                "@SharedFrom(P25.class)\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Integer> m;");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("Long vs Integer value must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "type-parameter", "Integer", "Long");
    }

    // ── #26 struct field missing on consumer ───────────────────────────────

    @Test
    public void testErrorWhenStructFieldMissingInConsumer() {
        // Producer's @Type has a field consumer's redefinition omits.
        var producer = bpfClass("P26",
                "@Type public static class Stats { @Unsigned int hits; @Unsigned long ts; @Unsigned int extra; }\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Stats> m;");
        var consumer = new Source(PKG + ".C26",
                "package " + PKG + ";\n"
                        + "import me.bechberger.ebpf.annotations.*;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class C26 extends BPFProgram {\n"
                        + "  @Type public static class Stats { @Unsigned int hits; @Unsigned long ts; }\n"
                        + "  @SharedFrom(P26.class)\n"
                        + "  @BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Stats> m;\n"
                        + "}\n");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("consumer missing field must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "extra", "missing");
    }

    // ── #27 struct field missing on producer ───────────────────────────────

    @Test
    public void testErrorWhenStructFieldMissingInProducer() {
        var producer = bpfClass("P27",
                "@Type public static class Stats { @Unsigned int hits; @Unsigned long ts; }\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Stats> m;");
        var consumer = new Source(PKG + ".C27",
                "package " + PKG + ";\n"
                        + "import me.bechberger.ebpf.annotations.*;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class C27 extends BPFProgram {\n"
                        + "  @Type public static class Stats { @Unsigned int hits; @Unsigned long ts; @Unsigned int extra; }\n"
                        + "  @SharedFrom(P27.class)\n"
                        + "  @BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Stats> m;\n"
                        + "}\n");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("consumer extra field must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "extra");
    }

    // ── #28 struct field type differs ──────────────────────────────────────

    @Test
    public void testErrorWhenStructFieldTypeDiffers() {
        var producer = bpfClass("P28",
                "@Type public static class BoostState { @Unsigned int waiterCount; @Unsigned long ts; }\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, BoostState> m;");
        var consumer = new Source(PKG + ".C28",
                "package " + PKG + ";\n"
                        + "import me.bechberger.ebpf.annotations.*;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class C28 extends BPFProgram {\n"
                        + "  @Type public static class BoostState { @Unsigned long waiterCount; @Unsigned long ts; }\n"
                        + "  @SharedFrom(P28.class)\n"
                        + "  @BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, BoostState> m;\n"
                        + "}\n");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("differing field type must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "waiterCount", "BoostState");
    }

    // ── #30 maxEntries mismatch ────────────────────────────────────────────

    @Test
    public void testErrorWhenMaxEntriesMismatch() {
        var producer = bpfClass("P30",
                "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> m;");
        var consumer = bpfClass("C30",
                "@SharedFrom(P30.class)\n"
                        + "@BPFMapDefinition(maxEntries = 16) BPFHashMap<Integer, Long> m;");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("maxEntries mismatch must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "maxEntries", "8", "16");
    }

    // ── #32 SharedFrom value is not a @BPF class ───────────────────────────

    @Test
    public void testErrorWhenSharedFromValueIsNotBPFProgram() {
        var consumer = bpfClass("C32",
                "@SharedFrom(String.class)\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> m;");
        var res = InMemoryJavaCompiler.compile(List.of(consumer), newProcessor())
                .requireFailure("non-@BPF SharedFrom value must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "@BPF");
    }

    // ── #33 helpful message recommends producer's @Type ────────────────────

    @Test
    public void testHelpfulMessageRecommendsProducerType() {
        var producer = bpfClass("P33",
                "@Type public static class BoostState { @Unsigned int waiterCount; @Unsigned long ts; }\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, BoostState> m;");
        var consumer = new Source(PKG + ".C33",
                "package " + PKG + ";\n"
                        + "import me.bechberger.ebpf.annotations.*;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class C33 extends BPFProgram {\n"
                        + "  @Type public static class BoostState { @Unsigned long waiterCount; @Unsigned long ts; }\n"
                        + "  @SharedFrom(P33.class)\n"
                        + "  @BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, BoostState> m;\n"
                        + "}\n");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("type drift must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "BoostState", "share", PKG + ".P33");
    }

    // ── #29 nested struct field type drift ────────────────────────────────

    @Test
    public void testErrorWhenNestedStructFieldDiffers() {
        // Outer @Type embeds Inner @Type; Inner's leaf field type drifts on the
        // consumer side. The diagnostic must point at the leaf field.
        var producer = bpfClass("P29",
                "@Type public static class Inner { @Unsigned int cpu; @Unsigned long ts; }\n"
                        + "@Type public static class Outer { Inner first; @Unsigned long count; }\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Outer> m;");
        var consumer = new Source(PKG + ".C29",
                "package " + PKG + ";\n"
                        + "import me.bechberger.ebpf.annotations.*;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class C29 extends BPFProgram {\n"
                        + "  @Type public static class Inner { @Unsigned long cpu; @Unsigned long ts; }\n"
                        + "  @Type public static class Outer { Inner first; @Unsigned long count; }\n"
                        + "  @SharedFrom(P29.class)\n"
                        + "  @BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Outer> m;\n"
                        + "}\n");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("nested type drift must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "Inner");
    }

    // ── #31 @SharedFrom on a field without @BPFMapDefinition ──────────────

    @Test
    public void testErrorWhenSharedFromOnNonMapField() {
        var producer = bpfClass("P31",
                "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Long> m;");
        var consumer = bpfClass("C31",
                "@SharedFrom(P31.class) int notAMap;");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor())
                .requireFailure("@SharedFrom requires @BPFMapDefinition on the same field");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@SharedFrom", "@BPFMapDefinition");
    }

    // ── #34 correct use compiles ──────────────────────────────────────────

    @Test
    public void testCorrectUseCompiles() {
        // Producer + consumer that reference the producer's @Type directly; should compile.
        var producer = bpfClass("P34",
                "@Type public static class Stats { @Unsigned int hits; @Unsigned long ts; }\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, Stats> m;");
        var consumer = bpfClass("C34",
                "@SharedFrom(P34.class)\n"
                        + "@BPFMapDefinition(maxEntries = 8) BPFHashMap<Integer, P34.Stats> m;");
        var res = InMemoryJavaCompiler.compile(List.of(producer, consumer), newProcessor());
        if (!res.success()) {
            // Surface ERROR diagnostics if the positive path failed.
            var sb = new StringBuilder("Expected positive case to compile, but it failed:\n");
            for (var d : res.diagnostics()) {
                if (d.getKind() == javax.tools.Diagnostic.Kind.ERROR) {
                    sb.append("  ERROR: ").append(d.getMessage(java.util.Locale.ROOT)).append('\n');
                }
            }
            throw new AssertionError(sb.toString());
        }
    }
}
