package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.samples.sched.CentralScheduler;
import me.bechberger.ebpf.samples.sched.PriorityScheduler;
import me.bechberger.ebpf.samples.sched.SimpleScheduler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Smoke tests that verify each new sched-ext scheduler can attach to the kernel
 * and remain attached for a short period without crashing or triggering the watchdog.
 *
 * <p>These tests require a kernel with sched_ext support (6.11+).  They are run on
 * the thinkstation CI node via {@code sudo mvn test}.
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
}
