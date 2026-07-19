package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.SchedulerHarness;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Offline proof points for {@link EdfRateLimitSample}, no kernel.
 *
 * <p>The harness has no virtual clock, so batches run microseconds apart and the
 * millisecond-scale rate-limit gap never elapses between {@code runBatch()} calls.
 * These tests therefore assert the two behaviours that are deterministic without
 * time control: first-appearance tasks dispatch immediately, and a pid is never
 * held twice concurrently in the deferred queue.
 */
class EdfRateLimitSampleTest {

    private QueuedTask task(int pid, long weight) {
        var t = new QueuedTask();
        t.pid = pid;
        t.weight = weight;
        return t;
    }

    @Test
    void firstAppearanceDispatchesImmediately() {
        var sched = new EdfRateLimitSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8);

        harness.feed(task(1, 100), task(2, 100), task(3, 100));
        harness.runBatch();

        List<Integer> pids = harness.dispatches().stream()
                .map(SchedulerHarness.Dispatch::pid).sorted().toList();
        assertEquals(List.of(1, 2, 3), pids,
                "every never-seen pid is time-eligible and dispatches on its first batch");
    }

    @Test
    void samePidNotDoubleDispatchedWithinBatch() {
        var sched = new EdfRateLimitSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8);

        // Same pid twice in one batch: the second occurrence must be coalesced, not
        // dispatched twice (the `held` guard prevents a duplicate queue insertion).
        harness.feed(task(7, 100), task(7, 100));
        harness.runBatch();

        long sevens = harness.dispatches().stream()
                .filter(d -> d.pid() == 7).count();
        assertEquals(1, sevens, "a pid appearing twice in one batch dispatches exactly once");
    }
}
