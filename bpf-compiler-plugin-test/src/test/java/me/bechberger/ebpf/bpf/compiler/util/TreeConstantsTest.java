package me.bechberger.ebpf.bpf.compiler.util;

import me.bechberger.ebpf.compiler.InMemoryJavaCompiler;
import me.bechberger.ebpf.compiler.InMemoryJavaCompiler.Source;
import org.junit.jupiter.api.Test;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives javac in-process via {@link InMemoryJavaCompiler} to exercise
 * {@link TreeConstants#stringReturnLiteral} against several method-body
 * shapes. Captures each method's extraction result in a map the test
 * then asserts on.
 */
class TreeConstantsTest {

    @SupportedAnnotationTypes("*")
    @SupportedSourceVersion(SourceVersion.RELEASE_22)
    static final class CapturingProcessor extends AbstractProcessor {
        private final String targetFqn;
        final Map<String, Optional<String>> results = new LinkedHashMap<>();
        boolean sawTarget;

        CapturingProcessor(String targetFqn) { this.targetFqn = targetFqn; }

        @Override
        public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
            if (roundEnv.processingOver()) return false;
            TypeElement target = processingEnv.getElementUtils().getTypeElement(targetFqn);
            if (target == null) return false;
            sawTarget = true;
            for (var enc : target.getEnclosedElements()) {
                if (enc.getKind() != ElementKind.METHOD) continue;
                var m = (ExecutableElement) enc;
                results.put(m.getSimpleName().toString(),
                        TreeConstants.stringReturnLiteral(processingEnv, m));
            }
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
    void extractsLiteralAndRejectsOtherShapes() {
        String body = """
            package p;
            abstract class Holder {
                String plainLiteral() { return "hello"; }
                String dynamicConcat(String s) { return "a" + s; }
                String twoStmts()     { int x = 1; return "no"; }
                int    notString()    { return 42; }
                abstract String noBody();
            }
            """;
        var proc = new CapturingProcessor("p.Holder");
        var res = InMemoryJavaCompiler.compile(
                List.of(new Source("p.Holder", body)), proc);
        failIfCompileErrors(res);
        assertTrue(proc.sawTarget, "processor did not see p.Holder");
        assertNotNull(proc.results.get("plainLiteral"));
        assertEquals(Optional.of("hello"), proc.results.get("plainLiteral"),
                "plain literal return should extract");
        assertEquals(Optional.empty(), proc.results.get("dynamicConcat"),
                "runtime concat is not a bare literal");
        assertEquals(Optional.empty(), proc.results.get("twoStmts"),
                "multiple statements must not extract");
        assertEquals(Optional.empty(), proc.results.get("notString"),
                "non-string literal must not extract");
        assertEquals(Optional.empty(), proc.results.get("noBody"),
                "missing method body must not extract");
    }
}
