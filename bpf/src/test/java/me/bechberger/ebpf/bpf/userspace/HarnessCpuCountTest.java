// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies {@link SchedulerHarness#withCpus(int)} actually drives the scheduler's CPU model,
 * not just a bookkeeping field: it must widen (or narrow) the dispatch-range validation and be
 * visible through {@link UserspaceScheduler#cpuCount()}. Without this, a CPU-targeting scheduler
 * could not be tested for a machine size larger than the host running the test.
 */
class HarnessCpuCountTest {

    /** Dispatches every fed task to the CPU equal to its pid, so we can probe range validation. */
    static final class PidToCpuSched extends FakeSchedulerBase {
        final List<Integer> targeted = new ArrayList<>();
        int reportedCpuCount = -1;

        @Override
        protected void schedule(QueuedTask[] tasks, int count) {
            reportedCpuCount = cpuCount();
            for (int i = 0; i < count; i++) {
                dispatchTask(tasks[i], tasks[i].pid);   // pid doubles as the target CPU
                targeted.add(tasks[i].pid);
            }
        }
    }

    private QueuedTask task(int pid) {
        var t = new QueuedTask();
        t.pid = pid;
        return t;
    }

    @Test
    void withCpusIsVisibleThroughCpuCount() {
        var sched = new PidToCpuSched();
        SchedulerHarness.forScheduler(sched).withCpus(16).feed(task(0)).runBatch();
        assertEquals(16, sched.reportedCpuCount,
                "cpuCount() must reflect the harness withCpus() override inside schedule()");
    }

    @Test
    void withCpusWidensDispatchRangeValidation() {
        var sched = new PidToCpuSched();
        // CPU 10 would be rejected on a typical host, but withCpus(16) makes [0,16) valid.
        assertDoesNotThrow(() ->
                SchedulerHarness.forScheduler(sched).withCpus(16).feed(task(10)).runBatch());
        assertEquals(List.of(10), sched.targeted);
    }

    @Test
    void dispatchAboveModeledRangeStillThrows() {
        var sched = new PidToCpuSched();
        // CPU 20 is out of the modeled [0,16) range → must fail fast.
        var ex = assertThrows(IllegalArgumentException.class, () ->
                SchedulerHarness.forScheduler(sched).withCpus(16).feed(task(20)).runBatch());
        assertTrue(ex.getMessage().contains("out of range"),
                "message should explain the CPU is out of the modeled range: " + ex.getMessage());
    }

    @Test
    void withCpusRejectsNonPositive() {
        var sched = new PidToCpuSched();
        assertThrows(IllegalArgumentException.class,
                () -> SchedulerHarness.forScheduler(sched).withCpus(0));
    }
}
