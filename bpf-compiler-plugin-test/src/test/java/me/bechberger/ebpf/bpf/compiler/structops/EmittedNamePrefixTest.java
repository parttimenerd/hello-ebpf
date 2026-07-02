package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.annotations.bpf.BPFFunction;
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
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that {@link StructOps#emittedNamePrefix()} is threaded through
 * discovery and applied by the synthesizer to both the emitted function name
 * and the {@code .field = (void *)<name>} initializer entry.
 */
class EmittedNamePrefixTest {

    @SupportedAnnotationTypes("*")
    @SupportedSourceVersion(SourceVersion.RELEASE_22)
    static final class CapturingProcessor extends AbstractProcessor {
        private final String targetFqn;
        StructOpsSynthesizer.Result captured;
        boolean sawTarget;

        CapturingProcessor(String targetFqn) { this.targetFqn = targetFqn; }

        @Override
        public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
            if (roundEnv.processingOver()) return false;
            TypeElement target = processingEnv.getElementUtils().getTypeElement(targetFqn);
            if (target == null) return false;
            sawTarget = true;
            var kinds = StructOpsDiscovery.discover(target, processingEnv);
            captured = new StructOpsSynthesizer(processingEnv).synthesize(target, kinds);
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

    /** An interface that uses emittedNamePrefix = "myprefix_" should cause the synthesizer
     *  to emit {@code myprefix_ssthresh} as both the function symbol and the pointer target
     *  in the struct initializer while keeping {@code .ssthresh} as the field name. */
    @Test
    void prefixAppliedToEmittedSymbolAndInitializer() {
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.annotations.bpf.StructOps;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.runtime.sock;

            @StructOps(value = "tcp_congestion_ops", emittedNamePrefix = "myprefix_")
            interface PrefixedCC {
                int ssthresh(Ptr<sock> sk);
            }

            @BPF abstract class MyCC extends BPFProgram implements PrefixedCC {
                @Override public int ssthresh(Ptr<sock> sk) { return 0; }
            }
            """;
        var proc = new CapturingProcessor("p.MyCC");
        var res = InMemoryJavaCompiler.compile(List.of(new Source("p.MyCC", body)), proc);
        failIfCompileErrors(res);
        assertTrue(proc.sawTarget, "processor did not see p.MyCC");
        assertNotNull(proc.captured, "synthesize was not invoked");

        assertEquals(1, proc.captured.functions().size(),
                "expected exactly one synthesized function");
        BPFFunction bpfFn = proc.captured.functions().get(0).bpfFunction();
        assertEquals("myprefix_ssthresh", bpfFn.name(),
                "emitted function name must carry the prefix");
        assertEquals("struct_ops/ssthresh", bpfFn.section(),
                "section must still use the BTF field name (no prefix)");

        assertEquals(1, proc.captured.instances().size());
        String c = proc.captured.instances().get(0).cSource();
        assertTrue(c.contains("myprefix_ssthresh"),
                "cSource must contain prefixed symbol myprefix_ssthresh:\n" + c);
        assertTrue(c.contains(".ssthresh = (void *)myprefix_ssthresh"),
                "initializer must keep .ssthresh as field name and use prefixed symbol:\n" + c);
    }

    /** Empty prefix (the default) must leave names unchanged — regression guard
     *  for existing consumers that do not set emittedNamePrefix. */
    @Test
    void emptyPrefixLeavesNamesUnchanged() {
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
        var proc = new CapturingProcessor("p.Cc");
        var res = InMemoryJavaCompiler.compile(List.of(new Source("p.Cc", body)), proc);
        failIfCompileErrors(res);
        assertNotNull(proc.captured);

        assertEquals(1, proc.captured.functions().size());
        BPFFunction bpfFn = proc.captured.functions().get(0).bpfFunction();
        assertEquals("ssthresh", bpfFn.name(),
                "empty prefix must leave the function name as bare field name");

        String c = proc.captured.instances().get(0).cSource();
        assertTrue(c.contains(".ssthresh = (void *)ssthresh"),
                "empty prefix: initializer must be bare .ssthresh = (void *)ssthresh:\n" + c);
    }
}
