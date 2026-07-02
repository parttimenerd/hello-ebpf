package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.compiler.InMemoryJavaCompiler;
import me.bechberger.ebpf.compiler.InMemoryJavaCompiler.Source;
import org.junit.jupiter.api.Test;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.ExecutableElement;
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
 * Tests {@link StructOpsDiscovery} by driving javac in-process via
 * {@link InMemoryJavaCompiler} with a capturing {@link javax.annotation.processing.Processor}
 * that invokes discovery on the target class inside the processing round
 * and stashes the result on a static field the test then asserts on.
 */
class StructOpsDiscoveryTest {

    /** A capturing processor: locates the target FQN and runs discovery on it. */
    @SupportedAnnotationTypes("*")
    @SupportedSourceVersion(SourceVersion.RELEASE_22)
    static final class CapturingProcessor extends AbstractProcessor {
        private final String targetFqn;
        List<StructOpsDiscovery.Kind> captured;
        boolean sawTarget;

        CapturingProcessor(String targetFqn) { this.targetFqn = targetFqn; }

        @Override
        public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
            if (roundEnv.processingOver()) return false;
            TypeElement target = processingEnv.getElementUtils().getTypeElement(targetFqn);
            if (target == null) return false;
            sawTarget = true;
            captured = StructOpsDiscovery.discover(target, processingEnv);
            return false;
        }
    }

    private static Source src(String fqn, String body) { return new Source(fqn, body); }

    private static void failIfCompileErrors(InMemoryJavaCompiler.Result res) {
        // -proc:only compiles are allowed to have non-error diagnostics; only ERRORs abort discovery.
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
    void findsSingleAnnotatedInterface() {
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            @BPF
            abstract class MyCC extends BPFProgram implements TcpCongestionControl {
                @Override public int ssthresh(me.bechberger.ebpf.type.Ptr<
                    me.bechberger.ebpf.runtime.runtime.sock> sk) { return 42; }
                @Override public String name() { return "test_cc"; }
            }
            """;
        var processor = new CapturingProcessor("p.MyCC");
        var res = InMemoryJavaCompiler.compile(List.of(src("p.MyCC", body)), processor);
        failIfCompileErrors(res);
        assertTrue(processor.sawTarget, "processor did not see target element");
        assertNotNull(processor.captured, "discover(...) was not invoked");
        assertEquals(1, processor.captured.size(), "expected exactly one @StructOps kind");
        var kind = processor.captured.get(0);
        assertEquals("tcp_congestion_ops", kind.kernelName());
        assertEquals("struct_ops/", kind.sectionPrefix());
        assertEquals("", kind.instanceName());
        var names = kind.overriddenMethods().stream()
                .map(ExecutableElement::getSimpleName)
                .map(Object::toString)
                .collect(Collectors.toSet());
        assertEquals(Set.of("ssthresh", "name"), names,
                "expected overridden methods: ssthresh, name; got " + names);
    }

    @Test
    void classWithNoStructOpsInterfaceReturnsEmpty() {
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.BPFProgram;
            @BPF abstract class Plain extends BPFProgram {}
            """;
        var processor = new CapturingProcessor("p.Plain");
        var res = InMemoryJavaCompiler.compile(List.of(src("p.Plain", body)), processor);
        failIfCompileErrors(res);
        assertTrue(processor.sawTarget);
        assertNotNull(processor.captured);
        assertTrue(processor.captured.isEmpty(),
                "expected empty discovery result; got " + processor.captured);
    }

    @Test
    void ignoresIndirectInterface() {
        // Class implements Middle, Middle extends TcpCongestionControl.
        // Middle is NOT annotated @StructOps so discovery must ignore it
        // (the spec forbids following the chain).
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            interface Middle extends TcpCongestionControl {}
            @BPF abstract class Indirect extends BPFProgram implements Middle {}
            """;
        var processor = new CapturingProcessor("p.Indirect");
        var res = InMemoryJavaCompiler.compile(List.of(src("p.Indirect", body)), processor);
        failIfCompileErrors(res);
        assertTrue(processor.sawTarget);
        assertNotNull(processor.captured);
        assertTrue(processor.captured.isEmpty(),
                "expected empty (indirect interface); got " + processor.captured);
    }
}
