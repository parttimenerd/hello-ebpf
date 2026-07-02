package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.compiler.InMemoryJavaCompiler;
import me.bechberger.ebpf.compiler.InMemoryJavaCompiler.Source;
import org.junit.jupiter.api.Test;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Shape tests for {@link StructOpsManifestWriter}. Uses the same
 * {@link InMemoryJavaCompiler} + capturing-processor pattern as
 * {@link StructOpsSynthesizerTest} to obtain a live {@link TypeElement}
 * for the {@code @BPF} class we render a manifest for.
 */
class StructOpsManifestWriterTest {

    /** Captures the target class {@link TypeElement} and renders the manifest. */
    @SupportedAnnotationTypes("*")
    @SupportedSourceVersion(SourceVersion.RELEASE_22)
    static final class CapturingProcessor extends AbstractProcessor {
        private final String targetFqn;
        private final List<StructOpsSynthesizer.SynthInstance> instances;
        private final Map<String, StructOpsLayout> layoutsByKind;
        String rendered;
        boolean sawTarget;

        CapturingProcessor(String targetFqn,
                           List<StructOpsSynthesizer.SynthInstance> instances,
                           Map<String, StructOpsLayout> layoutsByKind) {
            this.targetFqn = targetFqn;
            this.instances = instances;
            this.layoutsByKind = layoutsByKind;
        }

        @Override
        public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
            if (roundEnv.processingOver()) return false;
            TypeElement target = processingEnv.getElementUtils().getTypeElement(targetFqn);
            if (target == null) return false;
            sawTarget = true;
            rendered = new StructOpsManifestWriter().render(target, instances, layoutsByKind);
            return false;
        }
    }

    private static void failIfCompileErrors(InMemoryJavaCompiler.Result res) {
        var errs = res.diagnostics().stream()
                .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
                .map(d -> d.getMessage(Locale.ROOT))
                .collect(Collectors.joining("\n"));
        if (!errs.isEmpty()) {
            throw new AssertionError("Fixture compilation had ERROR diagnostics:\n" + errs
                    + "\nCompiler output:\n" + res.compilerOutput());
        }
    }

    @Test
    void rendersSingleTcpCongestionOpsEntry() {
        // The synthesizer would produce exactly this instance for a
        // TcpCongestionControl-implementing @BPF class named "Cc".
        var instances = List.of(new StructOpsSynthesizer.SynthInstance(
                "tcp_congestion_ops", "Cc", "/* c-source not relevant here */"));
        var layouts = Map.of(
                "tcp_congestion_ops", StructOpsLayout.load("tcp_congestion_ops"));

        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.runtime.sock;
            @BPF abstract class Cc extends BPFProgram implements TcpCongestionControl {
                @Override public int ssthresh(Ptr<sock> sk) { return 42; }
            }
            """;
        var proc = new CapturingProcessor("p.Cc", instances, layouts);
        var res = InMemoryJavaCompiler.compile(List.of(new Source("p.Cc", body)), proc);
        failIfCompileErrors(res);
        assertTrue(proc.sawTarget, "processor did not see p.Cc");
        assertNotNull(proc.rendered, "render was not invoked");

        String out = proc.rendered;
        assertTrue(out.contains("package p;"),
                "missing package declaration:\n" + out);
        assertTrue(out.contains("public final class CcStructOpsManifest"),
                "missing class declaration:\n" + out);
        assertTrue(out.contains("implements me.bechberger.ebpf.bpf.structops.StructOpsManifest"),
                "missing implements clause:\n" + out);
        // The 5.6 value comes from the tcp_congestion_ops.json "since" field
        // — this pins the writer to the bundled layout metadata.
        assertTrue(out.contains("new me.bechberger.ebpf.bpf.structops.StructOpsManifest.Entry(\"tcp_congestion_ops\", \"Cc\", \"5.6\")"),
                "missing Entry initializer with expected since=5.6:\n" + out);
    }

    @Test
    void rendersEmptyEntriesForClassWithNoStructOps() {
        // A @BPF class with no @StructOps interfaces still gets a manifest
        // class emitted (keeps the codegen shape uniform). The entries list
        // must be a valid empty List.of(...).
        var instances = List.<StructOpsSynthesizer.SynthInstance>of();
        var layouts = Map.<String, StructOpsLayout>of();

        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.BPFProgram;
            @BPF abstract class Plain extends BPFProgram {}
            """;
        var proc = new CapturingProcessor("p.Plain", instances, layouts);
        var res = InMemoryJavaCompiler.compile(List.of(new Source("p.Plain", body)), proc);
        failIfCompileErrors(res);
        assertTrue(proc.sawTarget);
        assertNotNull(proc.rendered);

        String out = proc.rendered;
        assertTrue(out.contains("public final class PlainStructOpsManifest"),
                "missing class decl:\n" + out);
        assertTrue(out.contains("implements me.bechberger.ebpf.bpf.structops.StructOpsManifest"),
                "missing implements clause:\n" + out);
        // Empty entries → java.util.List.of() with nothing between the parens.
        assertTrue(out.contains("java.util.List.of(\n    );")
                        || out.contains("java.util.List.of(\n)")
                        || out.contains("java.util.List.of()"),
                "expected empty List.of(...) initializer; got:\n" + out);
        // No new Entry(...) call should appear.
        assertTrue(!out.contains("new me.bechberger.ebpf.bpf.structops.StructOpsManifest.Entry("),
                "empty manifest must not emit any Entry:\n" + out);
    }

    /**
     * The rendered manifest source must itself be a valid Java compilation
     * unit — feed it back into {@link InMemoryJavaCompiler} together with
     * the fixture and assert no ERROR diagnostics. This guards against
     * name-resolution regressions in the writer (e.g. an unqualified
     * {@code Entry} reference that can't be resolved outside the SPI's
     * package).
     */
    @Test
    void rendered_source_compiles() {
        var instances = List.of(new StructOpsSynthesizer.SynthInstance(
                "tcp_congestion_ops", "Cc", "/* c-source not relevant here */"));
        var layouts = Map.of(
                "tcp_congestion_ops", StructOpsLayout.load("tcp_congestion_ops"));

        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.runtime.sock;
            @BPF abstract class Cc extends BPFProgram implements TcpCongestionControl {
                @Override public int ssthresh(Ptr<sock> sk) { return 42; }
            }
            """;
        var proc = new CapturingProcessor("p.Cc", instances, layouts);
        var firstRes = InMemoryJavaCompiler.compile(List.of(new Source("p.Cc", body)), proc);
        failIfCompileErrors(firstRes);
        assertNotNull(proc.rendered, "render was not invoked");

        // Now compile the rendered manifest source alongside the fixture.
        // Use a no-op processor since InMemoryJavaCompiler.compile requires one.
        var noop = new AbstractProcessor() {
            @Override
            public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
                return false;
            }
        };
        var res = InMemoryJavaCompiler.compile(List.of(
                new Source("p.Cc", body),
                new Source("p.CcStructOpsManifest", proc.rendered)), noop);
        failIfCompileErrors(res);
    }
}
