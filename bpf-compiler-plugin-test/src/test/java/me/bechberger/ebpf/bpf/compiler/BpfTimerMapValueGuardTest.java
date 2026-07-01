package me.bechberger.ebpf.bpf.compiler;

import org.junit.jupiter.api.Test;

import javax.tools.*;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@code TypeProcessor} rejects {@code bpf_timer} as a direct map value type
 * at compile time. The kernel requires {@code bpf_timer} to be embedded as a field inside
 * a struct value; a bare-value declaration produces a load-time verifier rejection that
 * is much harder to diagnose than a targeted compile error.
 */
public class BpfTimerMapValueGuardTest {

    private static final String PKG = "bpf_timer_guard_test";

    private static JavaFileObject sourceFile(String fqn, String src) {
        return new SimpleJavaFileObject(
                URI.create("string:///" + fqn.replace('.', '/') + ".java"),
                JavaFileObject.Kind.SOURCE) {
            @Override
            public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return src;
            }
        };
    }

    private static String compileWithProcessor(List<JavaFileObject> sources) {
        var compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler, "No system Java compiler — run on a JDK, not a JRE.");
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        var fileManager = compiler.getStandardFileManager(
                diagnostics, Locale.ROOT, StandardCharsets.UTF_8);

        java.nio.file.Path tmp;
        try {
            tmp = java.nio.file.Files.createTempDirectory("ebpf-bpf-timer-guard-test-");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        List<String> options = Arrays.asList(
                "-classpath", System.getProperty("java.class.path"),
                "-s", tmp.toString(),
                "-d", tmp.toString()
        );

        var output = new StringWriter();
        var task = compiler.getTask(
                output, fileManager, diagnostics, options, null, sources);
        task.setProcessors(
                List.of(new me.bechberger.ebpf.bpf.processor.Processor()));
        try {
            task.call();
        } finally {
            try { fileManager.close(); } catch (IOException ignored) {}
            try {
                java.nio.file.Files.walk(tmp)
                        .sorted(Comparator.reverseOrder())
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
        return sb.toString();
    }

    private static String commonImports() {
        return "import me.bechberger.ebpf.annotations.*;\n"
                + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                + "import me.bechberger.ebpf.bpf.map.BPFHashMap;\n"
                + "import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;\n";
    }

    @Test
    public void directBpfTimerValueTypeIsRejected() {
        var src = sourceFile(PKG + ".DirectBpfTimerVal",
                "package " + PKG + ";\n"
                + commonImports()
                + "@BPF(license = \"GPL\")\n"
                + "public abstract class DirectBpfTimerVal extends BPFProgram {\n"
                + "    @BPFMapDefinition(maxEntries = 1)\n"
                + "    BPFHashMap<Integer, bpf_timer> badTimerMap;\n"
                + "}\n");
        var output = compileWithProcessor(List.of(src));
        assertTrue(output.contains("bpf_timer cannot be used directly as a map value type"),
                "Expected specific bpf_timer rejection message.\nActual output:\n" + output);
    }

    @Test
    public void bpfTimerEmbeddedInStructValueIsAccepted() {
        var src = sourceFile(PKG + ".EmbeddedBpfTimerVal",
                "package " + PKG + ";\n"
                + commonImports()
                + "@BPF(license = \"GPL\")\n"
                + "public abstract class EmbeddedBpfTimerVal extends BPFProgram {\n"
                + "    @Type\n"
                + "    public static class TimerVal {\n"
                + "        public bpf_timer timer;\n"
                + "    }\n"
                + "    @BPFMapDefinition(maxEntries = 1)\n"
                + "    BPFHashMap<Integer, TimerVal> okTimerMap;\n"
                + "}\n");
        var output = compileWithProcessor(List.of(src));
        assertFalse(output.contains("bpf_timer cannot be used directly as a map value type"),
                "Struct-embedded bpf_timer must not trigger the guard.\nActual output:\n" + output);
    }
}
