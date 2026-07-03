package me.bechberger.ebpf.compiler;

import me.bechberger.ebpf.compiler.InMemoryJavaCompiler.Source;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Codegen tests for {@code @InnerMap} — verifies the annotation processor
 * emits {@code setInnerMapFd(outer, inner)} in the generated impl-class's
 * {@code preLoad()} and rejects malformed references.
 */
public class InnerMapProcessorTest {

    private static final String PKG = "inner_map_test";

    private static javax.annotation.processing.Processor newProcessor() {
        return new me.bechberger.ebpf.bpf.processor.Processor();
    }

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

    @Test
    public void preLoadWiresInnerMapFd() {
        var src = bpfClass("MapInMap",
                "@BPFMapDefinition(maxEntries = 1)\n"
                        + "BPFHashMap<Long, Long> innerTemplate;\n"
                        + "@InnerMap(\"innerTemplate\")\n"
                        + "@BPFMapDefinition(maxEntries = 8)\n"
                        + "BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;");
        var res = InMemoryJavaCompiler.compile(List.of(src), newProcessor())
                .requireSuccess("map-in-map codegen should succeed");

        String impl = res.generatedSources().entrySet().stream()
                .filter(e -> e.getKey().endsWith("MapInMapImpl.java"))
                .map(java.util.Map.Entry::getValue)
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "expected MapInMapImpl.java in generated sources, got: "
                                + res.generatedSources().keySet()));
        assertTrue(impl.contains("setInnerMapFd(\"outer\", \"innerTemplate\")"),
                "generated preLoad should call setInnerMapFd; got:\n" + impl);
    }

    @Test
    public void missingSiblingFieldFailsCompile() {
        var src = bpfClass("MissingInner",
                "@InnerMap(\"nope\")\n"
                        + "@BPFMapDefinition(maxEntries = 8)\n"
                        + "BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;");
        var res = InMemoryJavaCompiler.compile(List.of(src), newProcessor())
                .requireFailure("missing sibling field should fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@InnerMap", "nope", "no @BPFMapDefinition field");
    }

    @Test
    public void innerMapOnNonMapFieldFailsCompile() {
        var src = bpfClass("NonMapInner",
                "@BPFMapDefinition(maxEntries = 1)\n"
                        + "BPFHashMap<Long, Long> innerTemplate;\n"
                        + "@InnerMap(\"innerTemplate\")\n"
                        + "int notAMap;");
        var res = InMemoryJavaCompiler.compile(List.of(src), newProcessor())
                .requireFailure("@InnerMap on non-map field should fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@InnerMap", "@BPFMapDefinition");
    }
}
