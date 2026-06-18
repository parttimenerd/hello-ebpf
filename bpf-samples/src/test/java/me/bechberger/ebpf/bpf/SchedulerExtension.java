package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.extension.*;

import java.lang.reflect.Parameter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * JUnit 5 extension that handles the load → attach → assert → close lifecycle
 * for sched-ext schedulers declared with {@link TestScheduler}.
 *
 * <p>Register on your test class:
 * <pre>{@code
 * @ExtendWith(SchedulerExtension.class)
 * class SchedulerSmokeTest {
 *     @Test
 *     @Timeout(15)
 *     @TestScheduler(MyScheduler.class)
 *     void myTest(MyScheduler sched) throws Exception {
 *         Thread.sleep(300);
 *         assertTrue(sched.isSchedulerAttachedProperly());
 *     }
 * }
 * }</pre>
 *
 * <p>The scheduler is loaded once per test method, attached (if {@code autoAttach=true}),
 * injected as a parameter, and closed after the method completes (even on failure).
 * Closing a scheduler detaches it from the kernel automatically.
 *
 * <p>If the kernel does not support sched_ext (no {@code /sys/kernel/sched_ext}),
 * the test is <em>skipped</em> rather than failed.
 */
public class SchedulerExtension implements ParameterResolver, AfterEachCallback {

    private static final ExtensionContext.Namespace NS =
            ExtensionContext.Namespace.create(SchedulerExtension.class);
    private static final String KEY = "scheduler";

    private static final boolean SCHED_EXT_AVAILABLE =
            Files.exists(Path.of("/sys/kernel/sched_ext"));

    @Override
    public boolean supportsParameter(ParameterContext paramCtx, ExtensionContext extCtx)
            throws ParameterResolutionException {
        return getAnnotation(extCtx).isPresent()
                && BPFProgram.class.isAssignableFrom(paramCtx.getParameter().getType());
    }

    @Override
    public Object resolveParameter(ParameterContext paramCtx, ExtensionContext extCtx)
            throws ParameterResolutionException {
        if (!SCHED_EXT_AVAILABLE) {
            throw new org.opentest4j.TestAbortedException(
                    "sched_ext not available on this kernel (no /sys/kernel/sched_ext)");
        }

        TestScheduler ann = getAnnotation(extCtx)
                .orElseThrow(() -> new ParameterResolutionException(
                        "@TestScheduler annotation not found on test method"));

        Parameter param = paramCtx.getParameter();
        Class<?> paramType = param.getType();
        if (!paramType.isAssignableFrom(ann.value()) && !ann.value().isAssignableFrom(paramType)) {
            throw new ParameterResolutionException(
                    "Parameter type " + paramType.getName()
                    + " is not compatible with @TestScheduler class " + ann.value().getName());
        }

        ExtensionContext.Store store = extCtx.getStore(NS);
        BPFProgram existing = store.get(KEY, BPFProgram.class);
        if (existing != null) {
            return existing;
        }

        @SuppressWarnings("unchecked")
        Class<BPFProgram> progClass = (Class<BPFProgram>) ann.value();
        BPFProgram program;
        try {
            program = BPFProgram.load(progClass);
        } catch (Exception e) {
            throw new ParameterResolutionException("Failed to load scheduler " + progClass.getName(), e);
        }
        store.put(KEY, program);
        if (ann.autoAttach()) {
            ((Scheduler) program).attachScheduler();
        }
        return program;
    }

    @Override
    public void afterEach(ExtensionContext extCtx) {
        BPFProgram program = extCtx.getStore(NS).remove(KEY, BPFProgram.class);
        if (program != null) {
            program.close();
        }
    }

    private static Optional<TestScheduler> getAnnotation(ExtensionContext extCtx) {
        return extCtx.getTestMethod()
                .map(m -> m.getAnnotation(TestScheduler.class));
    }
}
