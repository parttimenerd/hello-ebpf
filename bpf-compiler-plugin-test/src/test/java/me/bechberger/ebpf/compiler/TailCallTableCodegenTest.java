package me.bechberger.ebpf.compiler;

import me.bechberger.ebpf.bpf.compiler.CompilerPlugin;
import org.junit.jupiter.api.Test;

import javax.tools.*;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verify the annotation processor emits the expected register(...) calls
 * into the generated Impl.java. We inspect the emitted source text (not
 * bytecode) because it is stable and easy to read.
 *
 * <p>The C-shape SEC-section test uses the full compilation path (annotation
 * processor + BPFCompilerPlugin) so that the compiler plugin can translate
 * the {@code @BPFFunction} method body to C and attach the SEC annotation.
 * The generated C is retrieved from {@link CompilerPlugin#getLastGeneratedCode()}.
 */
public class TailCallTableCodegenTest {

    // ── helper: full compilation with processor + compiler plugin ────────────

    private static final String PKG = "tct_sec_test";

    private static CompilerPlugin compileWithPluginAndGetPlugin(String simpleName, String body) {
        CompilerPlugin.LAST_PLUGIN.remove();
        String fqn = PKG + "." + simpleName;
        String src = "package " + PKG + ";\n"
                + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                + "import me.bechberger.ebpf.bpf.map.*;\n"
                + "import me.bechberger.ebpf.runtime.PtDefinitions;\n"
                + "import me.bechberger.ebpf.type.Ptr;\n"
                + "@BPF(license = \"GPL\")\n"
                + "public abstract class " + simpleName + " extends BPFProgram {\n"
                + body
                + "\n}\n";
        JavaFileObject srcFile = new SimpleJavaFileObject(
                URI.create("string:///" + fqn.replace('.', '/') + ".java"),
                JavaFileObject.Kind.SOURCE) {
            @Override
            public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return src;
            }
        };

        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException(
                    "No system Java compiler available — run tests on a JDK, not a JRE.");
        }
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        var fileManager = compiler.getStandardFileManager(
                diagnostics, Locale.ROOT, StandardCharsets.UTF_8);

        java.nio.file.Path tmp;
        try {
            tmp = java.nio.file.Files.createTempDirectory("hello-ebpf-tct-sec-test-");
        } catch (IOException e) {
            throw new RuntimeException("could not create temp dir for compiler output", e);
        }

        List<String> options = Arrays.asList(
                "-classpath", System.getProperty("java.class.path"),
                "-Xplugin:BPFCompilerPlugin dumpC=false",
                "-s", tmp.toString(),
                "-d", tmp.toString()
        );

        var output = new StringWriter();
        var task = compiler.getTask(output, fileManager, diagnostics, options, null, List.of(srcFile));
        task.setProcessors(List.of(new me.bechberger.ebpf.bpf.processor.Processor()));
        try {
            task.call();
        } finally {
            try { fileManager.close(); } catch (IOException ignored) {}
            try {
                java.nio.file.Files.walk(tmp)
                        .sorted(java.util.Comparator.reverseOrder())
                        .forEach(p -> {
                            try { java.nio.file.Files.deleteIfExists(p); }
                            catch (IOException ignored) {}
                        });
            } catch (IOException ignored) {}
        }

        var sb = new StringBuilder(output.toString());
        for (var d : diagnostics.getDiagnostics()) {
            if (d.getKind() == Diagnostic.Kind.ERROR
                    || d.getKind() == Diagnostic.Kind.WARNING) {
                sb.append(d.getKind()).append(": ")
                        .append(d.getMessage(Locale.ROOT)).append('\n');
            }
        }
        String compilerOutput = sb.toString();

        var plugin = CompilerPlugin.LAST_PLUGIN.get();
        assertNotNull(plugin,
                "CompilerPlugin.LAST_PLUGIN must be set after compilation.\n"
                + "Compiler output:\n" + compilerOutput);
        return plugin;
    }

    // ── tests ────────────────────────────────────────────────────────────────

    @Test
    public void generatedImplContainsRegisterCallsForEachSlot() {
        var src = new InMemoryJavaCompiler.Source("tct.Prog",
                "package tct;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class Prog extends BPFProgram {\n"
                        + "  public enum Slot { PARSE_ETH, PARSE_IP, COUNT }\n"
                        + "  @BPFTailCallTable(slots = Slot.class)\n"
                        + "  @BPFMapDefinition(maxEntries = 3)\n"
                        + "  BPFProgArray dispatch;\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"PARSE_ETH\")\n"
                        + "  public int parseEthImpl() { return 0; }\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"PARSE_IP\")\n"
                        + "  public int parseIpImpl() { return 0; }\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"COUNT\")\n"
                        + "  public int countImpl() { return 0; }\n"
                        + "}\n");
        var res = InMemoryJavaCompiler.compile(List.of(src),
                new me.bechberger.ebpf.bpf.processor.Processor())
                .requireSuccess("processor should accept a valid @BPFTailCallTable");

        String generated = res.generatedSource("tct.ProgImpl")
                .orElseThrow(() -> new AssertionError("no ProgImpl emitted; generated="
                        + res.generatedSources().keySet()));
        // register calls should appear in the constructor.
        assertTrue(generated.contains("dispatch.register(0, getProgramByName(\"parseEthImpl\"))"),
                "missing register(0, parseEthImpl) in:\n" + generated);
        assertTrue(generated.contains("dispatch.register(1, getProgramByName(\"parseIpImpl\"))"),
                "missing register(1, parseIpImpl) in:\n" + generated);
        assertTrue(generated.contains("dispatch.register(2, getProgramByName(\"countImpl\"))"),
                "missing register(2, parseIpImpl) in:\n" + generated);
    }

    /**
     * Verify that a {@code @BPFFunction} annotated with {@code @TailCallSlot}
     * emits the correct {@code SEC("kprobe/...")} section in the generated C.
     *
     * <p>The annotation processor only generates Java (Impl.java); the compiler
     * plugin translates {@code @BPFFunction} method bodies to C and appends the
     * {@code SEC} annotation.  We therefore run the full compilation path
     * (annotation processor + BPFCompilerPlugin) and inspect the generated C
     * via {@link CompilerPlugin#getLastGeneratedCode()}.
     */
    @Test
    public void tailCallSlotEmitsCorrectBpfSection() {
        var plugin = compileWithPluginAndGetPlugin("KprobeSlotProg",
                "  public enum Slots { OPEN }\n"
                + "  @BPFTailCallTable(slots = Slots.class)\n"
                + "  @BPFMapDefinition(maxEntries = 1)\n"
                + "  BPFProgArray progs;\n"
                + "  @TailCallSlot(\"OPEN\")\n"
                + "  @BPFFunction(section = \"kprobe/do_sys_openat2\")\n"
                + "  public int onOpen(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }\n");

        String code = plugin.getLastGeneratedCode();
        assertTrue(code.contains("SEC(\"kprobe/do_sys_openat2\")"),
                "expected SEC(\"kprobe/do_sys_openat2\") in generated C:\n" + code);
    }

    /**
     * Verifies that the generated Impl constructor contains
     * {@code register(ordinal, getProgramByName("methodName"))} calls for each
     * {@code @TailCallSlot}-annotated method.
     *
     * <p>This behaviour is already fully covered by
     * {@link #generatedImplContainsRegisterCallsForEachSlot()}, which checks all
     * three ordinals (0, 1, 2) for a three-slot table.  No additional assertions
     * are needed here; this method exists as a named entry-point that satisfies
     * the task spec and delegates to the existing test for explanation.
     */
    @Test
    public void tailCallTableRegisterCallsEmitted() {
        // Already covered by generatedImplContainsRegisterCallsForEachSlot().
        // That test compiles a three-slot @BPFTailCallTable fixture and asserts
        // dispatch.register(0, ...), dispatch.register(1, ...), and
        // dispatch.register(2, ...) all appear in the generated ProgImpl constructor.
        // A duplicate fixture here would add noise without new coverage.
        generatedImplContainsRegisterCallsForEachSlot();
    }
}
