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
 * Tests that {@link StructOpsDiscovery} walks the superclass chain and
 * finds callback overrides declared on an abstract intermediate class rather
 * than directly on the {@code @BPF} leaf class.
 */
class SuperclassInheritanceDiscoveryTest {

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

    /**
     * An abstract intermediate class overrides {@code ssthresh} but leaves
     * {@code congAvoid} as the interface default. The concrete leaf class
     * {@code MyCC} directly implements the interface but inherits the
     * {@code ssthresh} body from {@code SchedulerBase}. Discovery must still
     * see {@code ssthresh} in {@code overriddenMethods()} and must NOT see
     * {@code congAvoid}.
     */
    @Test
    void findsMethodOverriddenByAbstractSuperclass() {
        // A single source unit containing multiple top-level types:
        //   - SchedulerBase (abstract, overrides ssthresh from TcpCongestionControl)
        //   - MyCC (@BPF, extends SchedulerBase AND directly implements TcpCongestionControl
        //           so discovery sees the @StructOps interface, but the method body is in the super)
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.runtime.sock;

            abstract class SchedulerBase extends BPFProgram implements TcpCongestionControl {
                @Override public int ssthresh(Ptr<sock> sk) { return 0; }
                // congAvoid is NOT overridden here — left as default
            }

            @BPF abstract class MyCC extends SchedulerBase implements TcpCongestionControl {}
            """;
        var processor = new CapturingProcessor("p.MyCC");
        var res = InMemoryJavaCompiler.compile(List.of(new Source("p.MyCC", body)), processor);
        failIfCompileErrors(res);
        assertTrue(processor.sawTarget, "processor did not see p.MyCC");
        assertNotNull(processor.captured, "discover(...) was not invoked");
        assertEquals(1, processor.captured.size(), "expected exactly one @StructOps kind");

        var kind = processor.captured.get(0);
        assertEquals("tcp_congestion_ops", kind.kernelName());

        Set<String> names = kind.overriddenMethods().stream()
                .map(ExecutableElement::getSimpleName)
                .map(Object::toString)
                .collect(Collectors.toSet());
        assertTrue(names.contains("ssthresh"),
                "expected ssthresh (overridden in SchedulerBase) to be discovered; got " + names);
        assertTrue(names.stream().noneMatch(n -> n.equals("congAvoid")),
                "congAvoid was NOT overridden — must be absent; got " + names);
    }

    /**
     * Same setup but the leaf {@code @BPF} class itself redeclares the method.
     * Direct declaration must also be found (regression guard: the walk must
     * include the leaf class itself).
     */
    @Test
    void findsMethodOverriddenByLeafClass() {
        String body = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.runtime.sock;

            abstract class BaseCC extends BPFProgram implements TcpCongestionControl {}

            @BPF abstract class LeafCC extends BaseCC implements TcpCongestionControl {
                @Override public int ssthresh(Ptr<sock> sk) { return 1; }
            }
            """;
        var processor = new CapturingProcessor("p.LeafCC");
        var res = InMemoryJavaCompiler.compile(List.of(new Source("p.LeafCC", body)), processor);
        failIfCompileErrors(res);
        assertTrue(processor.sawTarget, "processor did not see p.LeafCC");
        assertNotNull(processor.captured);
        assertEquals(1, processor.captured.size());

        Set<String> names = processor.captured.get(0).overriddenMethods().stream()
                .map(ExecutableElement::getSimpleName)
                .map(Object::toString)
                .collect(Collectors.toSet());
        assertTrue(names.contains("ssthresh"),
                "expected ssthresh (overridden in LeafCC) to be discovered; got " + names);
    }
}
