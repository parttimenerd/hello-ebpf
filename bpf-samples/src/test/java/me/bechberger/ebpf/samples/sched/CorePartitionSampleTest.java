// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.SchedulerHarness;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Offline proof that CorePartitionSample keeps interactive and batch work on disjoint core pools. */
class CorePartitionSampleTest {

    private QueuedTask task(int pid, long weight) {
        var t = new QueuedTask();
        t.pid = pid;
        t.weight = weight;
        return t;
    }

    private int cpuCount() {
        return Runtime.getRuntime().availableProcessors();
    }

    private int split() {
        return Math.max(1, cpuCount() / 2);
    }

    @Test
    void weightDrivesPoolClassification() {
        var sched = new CorePartitionSample();
        assertEquals(CorePartitionSample.Pool.INTERACTIVE, sched.poolOf(task(1, 100)));
        assertEquals(CorePartitionSample.Pool.INTERACTIVE, sched.poolOf(task(2, 5000)));
        assertEquals(CorePartitionSample.Pool.BATCH, sched.poolOf(task(3, 99)));
        assertEquals(CorePartitionSample.Pool.BATCH, sched.poolOf(task(4, 1)));
    }

    @Test
    void interactiveTasksDispatchToLowHalf() {
        var sched = new CorePartitionSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(cpuCount());
        harness.feed(task(1, 100), task(2, 200), task(3, 5000)).runBatch();

        List<Integer> cpus = harness.dispatches().stream()
                .map(SchedulerHarness.Dispatch::targetCpu).toList();
        assertEquals(3, cpus.size());
        for (int cpu : cpus) {
            assertTrue(cpu >= 0 && cpu < split(),
                    "interactive task landed outside the low pool [0," + split() + "): " + cpu);
        }
    }

    @Test
    void batchTasksDispatchToHighHalf() {
        int cpuCount = cpuCount();
        // The high-half assertion is only meaningful when there are >= 2 CPUs to split.
        if (cpuCount < 2) return;

        var sched = new CorePartitionSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(cpuCount);
        harness.feed(task(10, 1), task(11, 50), task(12, 99)).runBatch();

        List<Integer> cpus = harness.dispatches().stream()
                .map(SchedulerHarness.Dispatch::targetCpu).toList();
        assertEquals(3, cpus.size());
        for (int cpu : cpus) {
            assertTrue(cpu >= split() && cpu < cpuCount,
                    "batch task landed outside the high pool [" + split() + "," + cpuCount + "): " + cpu);
        }
    }

    @Test
    void interactiveAndBatchNeverShareACore() {
        int cpuCount = cpuCount();
        if (cpuCount < 2) return;

        var sched = new CorePartitionSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(cpuCount);
        // Interleave classes; each must still stay in its own pool.
        harness.feed(task(1, 200), task(2, 1), task(3, 300), task(4, 5)).runBatch();

        var dispatches = harness.dispatches();
        int interactiveCpu = dispatches.stream()
                .filter(d -> d.pid() == 1 || d.pid() == 3)
                .mapToInt(SchedulerHarness.Dispatch::targetCpu).max().orElseThrow();
        int batchCpu = dispatches.stream()
                .filter(d -> d.pid() == 2 || d.pid() == 4)
                .mapToInt(SchedulerHarness.Dispatch::targetCpu).min().orElseThrow();
        assertTrue(interactiveCpu < split(), "interactive pool leaked into high half");
        assertTrue(batchCpu >= split(), "batch pool leaked into low half");
    }
}
