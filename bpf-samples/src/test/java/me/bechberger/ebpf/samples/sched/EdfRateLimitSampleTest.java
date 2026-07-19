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

    @Test
    void rateLimitHoldsThenReleasesWithVirtualClock() {
        var sched = new EdfRateLimitSample();
        // Virtual clock: time only moves when we advance it, so the ms-scale rate-limit
        // gap is now deterministically observable across batches.
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8).withVirtualClock(0);

        // t=0: first appearance dispatches immediately.
        harness.feed(task(1, 100)).runBatch();
        assertEquals(1, harness.dispatches().size(), "first dispatch at t=0");

        // Same instant: the pid ran <gap ago, so it is held, not dispatched again.
        harness.clear();
        harness.feed(task(1, 100)).runBatch();
        assertEquals(0, harness.dispatches().size(),
                "rate limit holds a pid that just ran (gap not elapsed)");

        // Advance just short of the 4 ms gap (weight 100 → 4 ms): still held.
        harness.clear();
        harness.advanceMillis(3).feed(task(1, 100)).runBatch();
        assertEquals(0, harness.dispatches().size(),
                "still held 3 ms after dispatch (< 4 ms gap)");

        // Cross the gap: the held task becomes eligible and dispatches. Feed an empty
        // batch so schedule() runs (runBatch with no feed is a no-op) and drains the queue.
        harness.clear();
        harness.advanceMillis(2).feed().runBatch();  // now at t=5 ms > 4 ms gap
        assertEquals(1, harness.dispatches().size(),
                "held task drains once the rate-limit gap elapses");
        assertEquals(1, harness.dispatches().get(0).pid());
    }

    @Test
    void evictedHeldPidCanBeReQueuedLater() {
        var sched = new EdfRateLimitSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8).withVirtualClock(0);

        // t=0: dispatch pid 1, recording lastDispatch=0.
        harness.feed(task(1, 100)).runBatch();
        assertEquals(1, harness.dispatches().size());

        // Re-arrive immediately: rate-limited, so pid 1 is now held via deferUntil.
        harness.clear();
        harness.feed(task(1, 100)).runBatch();
        assertEquals(0, harness.dispatches().size(), "held while rate-limited");

        // Jump the clock far enough that tick()'s horizon (now - 20s) evicts the held
        // entry, then let the pid re-arrive. If eviction leaves `held` stuck, the pid can
        // never be re-queued and is starved forever — this asserts it recovers.
        harness.advanceMillis(60_000);   // +60 s: held entry's notBefore (~4 ms) is now < horizon
        harness.tick();                  // evicts the stale held entry
        harness.clear();
        harness.feed(task(1, 100)).runBatch();
        assertEquals(1, harness.dispatches().size(),
                "a pid whose held entry was evicted must be re-dispatchable, not starved");
    }
}
