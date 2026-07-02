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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives javac in-process via {@link InMemoryJavaCompiler} to synthesize
 * struct_ops function proxies + struct-instance C snippets, mirroring
 * {@link StructOpsDiscoveryTest}'s capturing-processor pattern.
 */
class StructOpsSynthesizerTest {

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

    @Test
    void synthesizesSectionAndHeader() {
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
        var res = InMemoryJavaCompiler.compile(
                List.of(new Source("p.Cc", body)), proc);
        failIfCompileErrors(res);
        assertTrue(proc.sawTarget, "processor did not see p.Cc");
        assertNotNull(proc.captured, "synthesize was not invoked");

        var result = proc.captured;
        assertEquals(1, result.functions().size(),
                "expected exactly one synthesized function; got " + result.functions().size());
        var fn = result.functions().get(0);
        BPFFunction bpfFn = fn.bpfFunction();
        assertEquals("struct_ops/ssthresh", bpfFn.section());
        assertEquals("__u32 BPF_PROG($name, struct sock *sk)", bpfFn.headerTemplate(),
                "unexpected headerTemplate: " + bpfFn.headerTemplate());

        // Pin every BPFFunction field the runtime consumes so the proxy shape
        // never silently regresses.
        assertEquals("$name", bpfFn.callTemplate());
        assertEquals("", bpfFn.lastStatement());
        assertFalse(bpfFn.autoAttach(),
                "struct_ops entries attach via bpf_map__attach_struct_ops, not auto-attach");
        assertEquals("ssthresh", bpfFn.name(),
                "name is set to the kernel field name so the initializer can reference it without a camelCase-vs-snake_case gap");
        assertTrue(bpfFn.addDefinition());
        assertFalse(bpfFn.inline(),
                "entry points must not be inlined");
        assertEquals(BPFFunction.class, bpfFn.annotationType());

        assertEquals(1, result.instances().size());
        var inst = result.instances().get(0);
        assertEquals("tcp_congestion_ops", inst.kernelName());
        assertEquals("Cc", inst.mapName());
        String c = inst.cSource();
        assertTrue(c.contains("SEC(\".struct_ops.link\")"),
                "cSource missing SEC(.struct_ops.link):\n" + c);
        assertTrue(c.contains("struct tcp_congestion_ops Cc"),
                "cSource missing struct decl:\n" + c);
        assertTrue(c.contains(".ssthresh"),
                "cSource missing .ssthresh initializer:\n" + c);
        assertTrue(c.contains("(void *)ssthresh"),
                "cSource missing (void *)ssthresh cast:\n" + c);
    }

    @Test
    void dataFieldRendersAsInitializerNotProgram() {
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            @BPF abstract class Named extends BPFProgram implements TcpCongestionControl {
                @Override public String name() { return "hellocc"; }
            }
            """;
        var proc = new CapturingProcessor("p.Named");
        var res = InMemoryJavaCompiler.compile(
                List.of(new Source("p.Named", body)), proc);
        failIfCompileErrors(res);
        assertNotNull(proc.captured);

        var result = proc.captured;
        // "name" is a data field → no synthesized program, no BPF_PROG wrapping.
        assertTrue(result.functions().isEmpty(),
                "data field must not synthesize a function; got " + result.functions());
        assertEquals(1, result.instances().size());
        String c = result.instances().get(0).cSource();
        assertTrue(c.contains(".name = \"hellocc\""),
                "cSource missing .name literal:\n" + c);
    }

    @Test
    void instanceNameOverrideRespected() {
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.annotations.bpf.StructOps;
            import me.bechberger.ebpf.bpf.BPFProgram;

            @StructOps(value = "sched_ext_ops", instanceName = "my_sched")
            interface CustomSchedOps {}

            @BPF abstract class Sched extends BPFProgram implements CustomSchedOps {}
            """;
        var proc = new CapturingProcessor("p.Sched");
        var res = InMemoryJavaCompiler.compile(
                List.of(new Source("p.Sched", body)), proc);
        failIfCompileErrors(res);
        assertNotNull(proc.captured);
        assertEquals(1, proc.captured.instances().size());
        assertEquals("my_sched", proc.captured.instances().get(0).mapName());
    }

    @Test
    void sleepableFlipsSectionPrefixToStructOpsSDot() {
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.runtime.sock;
            @BPF abstract class Cc extends BPFProgram implements TcpCongestionControl {
                @Override @Sleepable public int ssthresh(Ptr<sock> sk) { return 42; }
            }
            """;
        var proc = new CapturingProcessor("p.Cc");
        var res = InMemoryJavaCompiler.compile(
                List.of(new Source("p.Cc", body)), proc);
        failIfCompileErrors(res);
        assertNotNull(proc.captured);

        assertEquals(1, proc.captured.functions().size());
        BPFFunction bpfFn = proc.captured.functions().get(0).bpfFunction();
        assertEquals("struct_ops.s/ssthresh", bpfFn.section(),
                "@Sleepable must flip section prefix to struct_ops.s/");
    }

    @Test
    void nonSleepableKeepsStructOpsSlash() {
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
        var res = InMemoryJavaCompiler.compile(
                List.of(new Source("p.Cc", body)), proc);
        failIfCompileErrors(res);
        assertNotNull(proc.captured);

        BPFFunction bpfFn = proc.captured.functions().get(0).bpfFunction();
        assertEquals("struct_ops/ssthresh", bpfFn.section(),
                "no-@Sleepable default must remain struct_ops/");
    }
}
