package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DeferredQueueTest {

    private QueuedTask task(int pid, long vtime) {
        var t = new QueuedTask();
        t.pid = pid;
        t.vtime = vtime;
        t.weight = 100;
        return t;
    }

    @Test
    void deferOrderedDrainsInKeyOrder() {
        var q = new DeferredQueue();
        q.deferOrdered(task(3, 0), 30);
        q.deferOrdered(task(1, 0), 10);
        q.deferOrdered(task(2, 0), 20);

        List<Integer> pids = new ArrayList<>();
        q.drainEligible(0, Integer.MAX_VALUE, t -> pids.add(t.pid));
        assertEquals(List.of(1, 2, 3), pids, "min-key drains first");
        assertEquals(0, q.size());
    }

    @Test
    void deferUntilRespectsTime() {
        var q = new DeferredQueue();
        q.deferUntil(task(1, 0), 100);   // eligible at 100
        q.deferUntil(task(2, 0), 200);   // eligible at 200

        List<Integer> early = new ArrayList<>();
        q.drainEligible(150, Integer.MAX_VALUE, t -> early.add(t.pid));
        assertEquals(List.of(1), early, "only pid 1 is eligible at t=150");
        assertEquals(1, q.size());

        List<Integer> late = new ArrayList<>();
        q.drainEligible(250, Integer.MAX_VALUE, t -> late.add(t.pid));
        assertEquals(List.of(2), late);
        assertEquals(0, q.size());
    }

    @Test
    void drainEligibleRespectsMax() {
        var q = new DeferredQueue();
        for (int i = 1; i <= 5; i++) q.deferOrdered(task(i, 0), i);
        List<Integer> got = new ArrayList<>();
        q.drainEligible(0, 2, t -> got.add(t.pid));
        assertEquals(2, got.size(), "max caps the drain");
        assertEquals(3, q.size());
    }

    @Test
    void evictOlderThanBoundsSize() {
        var q = new DeferredQueue();
        q.deferUntil(task(1, 0), 10);
        q.deferUntil(task(2, 0), 100);
        q.evictOlderThan(50);   // drops entries whose notBefore < 50
        assertEquals(1, q.size());
    }

    @Test
    void evictOlderThanLeavesOrderedEntriesAlone() {
        var q = new DeferredQueue();
        q.deferOrdered(task(1, 0), 10);   // vtime-ordered, no time gate
        q.deferOrdered(task(2, 0), 20);
        q.deferUntil(task(3, 0), 5);      // time-gated, older than the horizon
        q.evictOlderThan(1_000);          // must drop only the time-gated entry
        assertEquals(2, q.size(),
                "deferOrdered entries must survive evictOlderThan (they carry no time gate)");

        List<Integer> got = new ArrayList<>();
        q.drainEligible(0, Integer.MAX_VALUE, t -> got.add(t.pid));
        assertEquals(List.of(1, 2), got, "ordered entries survive and still drain in key order");
    }

    @Test
    void evictOlderThanReportsEvictedTasksToSink() {
        var q = new DeferredQueue();
        q.deferUntil(task(1, 0), 10);     // evicted
        q.deferUntil(task(2, 0), 100);    // survives
        q.deferOrdered(task(3, 0), 5);    // ordered — never evicted, never reported
        List<Integer> evicted = new ArrayList<>();
        q.evictOlderThan(50, t -> evicted.add(t.pid));
        assertEquals(List.of(1), evicted, "only the aged-out time-gated entry is reported");
        assertEquals(2, q.size(), "ordered + still-fresh time-gated entries remain");
    }

    @Test
    void storesCopiesSafeAcrossBatches() {
        var q = new DeferredQueue();
        var t = task(42, 7);
        q.deferOrdered(t, 5);
        t.pid = 999;            // mutate the flyweight after deferring
        List<Integer> got = new ArrayList<>();
        q.drainEligible(0, Integer.MAX_VALUE, x -> got.add(x.pid));
        assertEquals(List.of(42), got, "deferred task is a copy, not the mutated flyweight");
    }
}
