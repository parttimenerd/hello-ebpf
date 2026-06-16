package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.samples.sched.ChaosScheduler;
import me.bechberger.ebpf.samples.sched.CPU0Scheduler;
import me.bechberger.ebpf.samples.sched.CentralScheduler;
import me.bechberger.ebpf.samples.sched.DeadlineScheduler;
import me.bechberger.ebpf.samples.sched.FCFSScheduler;
import me.bechberger.ebpf.samples.sched.LotteryScheduler;
import me.bechberger.ebpf.samples.sched.MinimalScheduler;
import me.bechberger.ebpf.samples.sched.NestScheduler;
import me.bechberger.ebpf.samples.sched.PrevCpuScheduler;
import me.bechberger.ebpf.samples.sched.PriorityScheduler;
import me.bechberger.ebpf.samples.sched.RunnableScheduler;
import me.bechberger.ebpf.samples.sched.SMTPairScheduler;
import me.bechberger.ebpf.samples.sched.SimpleScheduler;
import me.bechberger.ebpf.samples.sched.TaskStorageScheduler;
import me.bechberger.ebpf.samples.sched.VTimeScheduler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Smoke tests that verify each sched-ext scheduler can attach to the kernel
 * and remain attached for a short period without crashing or triggering the watchdog.
 *
 * <p>These tests require a kernel with sched_ext support (6.11+).  They are run on
 * the thinkstation CI node via the VNG test runner.
 */
@ExtendWith(SchedulerExtension.class)
class SchedulerSmokeTest {

    @Test
    @Timeout(15)
    @TestScheduler(SimpleScheduler.class)
    void simpleSchedulerAttachesAndRuns(SimpleScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "SimpleScheduler should remain attached 300 ms after start");
        assertTrue(sched.getTotalEnqueued() > 0,
                "SchedulerStats.totalEnqueued should be positive after 300 ms of activity");
        assertTrue(sched.getTotalDispatched() > 0,
                "SchedulerStats.totalDispatched should be positive after 300 ms of activity");
    }

    @Test
    @Timeout(15)
    @TestScheduler(CentralScheduler.class)
    void centralSchedulerAttachesAndRuns(CentralScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "CentralScheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(PriorityScheduler.class)
    void prioritySchedulerAttachesAndRuns(PriorityScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "PriorityScheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(CPU0Scheduler.class)
    void cpu0SchedulerAttachesAndRuns(CPU0Scheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "CPU0Scheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(PrevCpuScheduler.class)
    void prevCpuSchedulerAttachesAndRuns(PrevCpuScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "PrevCpuScheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(DeadlineScheduler.class)
    void deadlineSchedulerAttachesAndRuns(DeadlineScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "DeadlineScheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(value = SMTPairScheduler.class, autoAttach = false)
    void smtPairSchedulerAttachesAndRuns(SMTPairScheduler sched) throws Exception {
        int ncpus = Runtime.getRuntime().availableProcessors();
        sched.configure(ncpus, Math.max(1, ncpus / 2));
        sched.attachScheduler();
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "SMTPairScheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(value = NestScheduler.class, autoAttach = false)
    void nestSchedulerAttachesAndRuns(NestScheduler sched) throws Exception {
        int ncpus = Runtime.getRuntime().availableProcessors();
        sched.configure(ncpus, Math.max(1, ncpus / 2));
        sched.attachScheduler();
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "NestScheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(TaskStorageScheduler.class)
    void taskStorageSchedulerAttachesAndRuns(TaskStorageScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "TaskStorageScheduler should remain attached 300 ms after start");
    }

    /**
     * Exercises Item 1 ({@code @Property("extra_flags")}) and Item 2 ({@code runnable()} ops slot):
     * after 300 ms of normal system activity the kernel should have invoked
     * {@link RunnableScheduler#runnable} at least once.
     */
    @Test
    @Timeout(15)
    @TestScheduler(RunnableScheduler.class)
    void runnableSchedulerInvokesRunnableCallback(RunnableScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "RunnableScheduler should remain attached 300 ms after start");
        assertTrue(sched.getRunnableCalls() > 0,
                "kernel should have called runnable() at least once in 300 ms; got "
                        + sched.getRunnableCalls());
    }

    @Test
    @Timeout(15)
    @TestScheduler(MinimalScheduler.class)
    void minimalSchedulerAttachesAndRuns(MinimalScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "MinimalScheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(FCFSScheduler.class)
    void fcfsSchedulerAttachesAndRuns(FCFSScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "FCFSScheduler should remain attached 300 ms after start");
    }

    @Test
    @Timeout(15)
    @TestScheduler(VTimeScheduler.class)
    void vtimeSchedulerAttachesAndRuns(VTimeScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "VTimeScheduler should remain attached 300 ms after start");
    }

    /**
     * Exercises {@link Scheduler#bpf_for_each_dsq}, {@link Scheduler#tryDispatchToLocalCpu},
     * {@link Scheduler#hasSchedulingConstraints}, and {@link me.bechberger.ebpf.type.Box} usage.
     */
    @Test
    @Timeout(15)
    @TestScheduler(LotteryScheduler.class)
    void lotterySchedulerAttachesAndRuns(LotteryScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "LotteryScheduler should remain attached 300 ms after start");
    }

    /**
     * Exercises {@link ChaosScheduler}: vtime delays, slice degradation, per-task state,
     * and CPU frequency throttling.  Runs system-wide (no targetTgid filter) to maximise
     * coverage.
     */
    @Test
    @Timeout(15)
    @TestScheduler(ChaosScheduler.class)
    void chaosSchedulerAttachesAndRuns(ChaosScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "ChaosScheduler should remain attached 300 ms after start");
    }
}

