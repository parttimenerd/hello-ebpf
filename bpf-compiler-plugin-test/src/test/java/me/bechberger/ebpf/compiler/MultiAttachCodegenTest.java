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
 * Verify that {@code @KProbeMulti} and {@code @UProbeMulti} annotated
 * {@code @BPFFunction} methods cause the compiler plugin to emit the correct
 * {@code SEC("kprobe.multi/...")} / {@code SEC("uprobe.multi/...")} strings
 * in the generated C source.
 *
 * <p>These tests use the full compilation path (annotation processor +
 * {@code BPFCompilerPlugin}) and retrieve the generated C via
 * {@link CompilerPlugin#getLastGeneratedCode()}.
 */
public class MultiAttachCodegenTest {

    private static final String PKG = "multi_attach_test";

    private static CompilerPlugin compileWithPlugin(String simpleName, String body) {
        CompilerPlugin.LAST_PLUGIN.remove();
        String fqn = PKG + "." + simpleName;
        String src = "package " + PKG + ";\n"
                + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
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
            tmp = java.nio.file.Files.createTempDirectory("hello-ebpf-multi-attach-test-");
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
        var task = compiler.getTask(output, fileManager, diagnostics, options, null,
                List.of(srcFile));
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

    @Test
    public void kprobeMultiEmitsCorrectSection() {
        var plugin = compileWithPlugin("KProbeMultiProg",
                "  @BPFFunction(section = \"kprobe.multi/onSyscall\", autoAttach = false)\n"
                + "  @KProbeMulti(\"*\")\n"
                + "  int onSyscall(Ptr<?> ctx) { return 0; }\n");

        String code = plugin.getLastGeneratedCode();
        assertTrue(code.contains("SEC(\"kprobe.multi/onSyscall\")"),
                "expected SEC(\"kprobe.multi/onSyscall\") in generated C:\n" + code);
    }

    @Test
    public void uprobeMultiEmitsCorrectSection() {
        var plugin = compileWithPlugin("UProbeMultiProg",
                "  @BPFFunction(section = \"uprobe.multi/onFunc\", autoAttach = false)\n"
                + "  @UProbeMulti(\"*\")\n"
                + "  int onFunc(Ptr<?> ctx) { return 0; }\n");

        String code = plugin.getLastGeneratedCode();
        assertTrue(code.contains("SEC(\"uprobe.multi/onFunc\")"),
                "expected SEC(\"uprobe.multi/onFunc\") in generated C:\n" + code);
    }
}
