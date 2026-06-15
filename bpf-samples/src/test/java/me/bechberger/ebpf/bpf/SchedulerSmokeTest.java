package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.samples.sched.CPU0Scheduler;
import me.bechberger.ebpf.samples.sched.CentralScheduler;
import me.bechberger.ebpf.samples.sched.DeadlineScheduler;
import me.bechberger.ebpf.samples.sched.NestScheduler;
import me.bechberger.ebpf.samples.sched.PrevCpuScheduler;
import me.bechberger.ebpf.samples.sched.PriorityScheduler;
import me.bechberger.ebpf.samples.sched.SMTPairScheduler;
import me.bechberger.ebpf.samples.sched.SimpleScheduler;
import me.bechberger.ebpf.samples.sched.TaskStorageScheduler;
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
}

