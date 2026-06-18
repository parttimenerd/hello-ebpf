package me.bechberger.ebpf.bpf;

import java.lang.annotation.*;

/**
 * Marks a test method as using a sched-ext scheduler that should be loaded,
 * optionally attached, and closed automatically via {@link SchedulerExtension}.
 *
 * <p>Usage:
 * <pre>{@code
 * @ExtendWith(SchedulerExtension.class)
 * class SchedulerSmokeTest {
 *     @Test
 *     @Timeout(15)
 *     @TestScheduler(SimpleScheduler.class)
 *     void simpleSchedulerAttaches(SimpleScheduler s) throws Exception {
 *         Thread.sleep(300);
 *         assertTrue(s.isSchedulerAttachedProperly());
 *     }
 * }
 * }</pre>
 *
 * @see SchedulerExtension
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface TestScheduler {
    /** The scheduler (BPF program) class to load. Must implement {@link Scheduler}. */
    Class<? extends BPFProgram> value();

    /**
     * Whether to call {@link Scheduler#attachScheduler()} after loading.
     * Defaults to {@code true}.
     */
    boolean autoAttach() default true;
}
