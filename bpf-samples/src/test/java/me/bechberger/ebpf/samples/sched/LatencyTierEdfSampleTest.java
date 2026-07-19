package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.SchedulerHarness;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Offline proof that latency tiers set EDF order regardless of arrival order. */
class LatencyTierEdfSampleTest {

    private QueuedTask task(int pid, long weight) {
        var t = new QueuedTask();
        t.pid = pid;
        t.weight = weight;
        return t;
    }

    @Test
    void lowerLatencyTierDispatchesFirstDespiteArrivalOrder() {
        var sched = new LatencyTierEdfSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8).withVirtualClock(0);

        // Feed BATCH first, then NORMAL, then INTERACTIVE. EDF must reorder to
        // INTERACTIVE (2 ms) < NORMAL (10 ms) < BATCH (50 ms) deadlines.
        harness.feed(
                task(3, 10),    // BATCH  (weight < 20)
                task(2, 50),    // NORMAL (20 <= weight < 100)
                task(1, 100)    // INTERACTIVE (weight >= 100)
        );
        harness.runBatch();

        List<Integer> order = harness.dispatches().stream()
                .map(SchedulerHarness.Dispatch::pid).toList();
        assertEquals(List.of(1, 2, 3), order,
                "EDF orders by tier latency target, not arrival order");
    }

    @Test
    void allTasksInABatchAreDispatched() {
        var sched = new LatencyTierEdfSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8).withVirtualClock(0);

        harness.feed(task(10, 100), task(11, 50), task(12, 10), task(13, 5));
        harness.runBatch();

        assertEquals(4, harness.dispatches().size(),
                "every task in the batch is dispatched (nothing dropped)");
    }
}
