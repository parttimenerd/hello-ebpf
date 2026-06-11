package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.extension.*;

import java.lang.reflect.Parameter;
import java.util.Optional;

/**
 * JUnit 5 extension that handles the load → (auto-attach) → assert → close lifecycle
 * for BPF programs declared with {@link TestBPFProgram}.
 *
 * <p>Register it on your test class:
 * <pre>{@code
 * @ExtendWith(BPFProgramExtension.class)
 * class MyTest {
 *     @Test
 *     @TestBPFProgram(MyProg.class)
 *     void myTest(MyProg program) { ... }
 * }
 * }</pre>
 *
 * <p>The program is loaded once per test method, injected as a parameter, and
 * closed after the method completes (even on failure).
 */
public class BPFProgramExtension implements ParameterResolver, AfterEachCallback {

    private static final ExtensionContext.Namespace NS =
            ExtensionContext.Namespace.create(BPFProgramExtension.class);
    private static final String KEY = "program";

    @Override
    public boolean supportsParameter(ParameterContext paramCtx, ExtensionContext extCtx)
            throws ParameterResolutionException {
        return getAnnotation(extCtx).isPresent()
                && BPFProgram.class.isAssignableFrom(paramCtx.getParameter().getType());
    }

    @Override
    public Object resolveParameter(ParameterContext paramCtx, ExtensionContext extCtx)
            throws ParameterResolutionException {
        TestBPFProgram ann = getAnnotation(extCtx)
                .orElseThrow(() -> new ParameterResolutionException(
                        "@TestBPFProgram annotation not found on test method"));

        // Check that the declared parameter type is compatible with the program class.
        Parameter param = paramCtx.getParameter();
        Class<?> paramType = param.getType();
        if (!paramType.isAssignableFrom(ann.value()) && !ann.value().isAssignableFrom(paramType)) {
            throw new ParameterResolutionException(
                    "Parameter type " + paramType.getName()
                    + " is not compatible with @TestBPFProgram program class " + ann.value().getName());
        }

        ExtensionContext.Store store = extCtx.getStore(NS);
        BPFProgram existing = store.get(KEY, BPFProgram.class);
        if (existing != null) {
            return existing;
        }

        @SuppressWarnings("unchecked")
        Class<BPFProgram> progClass = (Class<BPFProgram>) ann.value();
        BPFProgram program = BPFProgram.load(progClass);
        if (ann.autoAttach()) {
            program.autoAttachPrograms();
        }
        store.put(KEY, program);
        return program;
    }

    @Override
    public void afterEach(ExtensionContext extCtx) {
        BPFProgram program = extCtx.getStore(NS).remove(KEY, BPFProgram.class);
        if (program != null) {
            program.close();
        }
    }

    private static Optional<TestBPFProgram> getAnnotation(ExtensionContext extCtx) {
        return extCtx.getTestMethod()
                .map(m -> m.getAnnotation(TestBPFProgram.class));
    }
}
