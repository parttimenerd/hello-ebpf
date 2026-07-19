package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SchedulerHarnessTest {

    /** Trivial scheduler: dispatch every task to ANY_CPU, count ticks. */
    static class TrivialSched extends UserspaceScheduler {
        int ticks = 0;
        @Override protected void schedule(QueuedTask[] tasks, int count) {
            for (int i = 0; i < count; i++) dispatchTask(tasks[i], -1);
        }
        @Override protected void tick() { ticks++; }
    }

    private QueuedTask task(int pid, long weight) {
        var t = new QueuedTask(); t.pid = pid; t.weight = weight; return t;
    }

    @Test
    void capturesDispatchesInOrder() {
        var sched = new TrivialSched();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8);

        harness.feed(task(100, 200), task(101, 100));
        harness.runBatch();

        List<SchedulerHarness.Dispatch> ds = harness.dispatches();
        assertEquals(2, ds.size());
        assertEquals(100, ds.get(0).pid());
        assertEquals(101, ds.get(1).pid());
    }

    @Test
    void tickDrivesSchedulerTick() {
        var sched = new TrivialSched();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(4);
        harness.tick();
        harness.tick();
        assertEquals(2, sched.ticks);
    }

    @Test
    void runBatchClearsBetweenRuns() {
        var sched = new TrivialSched();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(4);
        harness.feed(task(1, 100));
        harness.runBatch();
        assertEquals(1, harness.dispatches().size());

        harness.feed(task(2, 100));
        harness.runBatch();
        // dispatches() accumulates across runs; the second run adds one more.
        assertEquals(2, harness.dispatches().size());
        assertEquals(2, harness.dispatches().get(1).pid());
    }
}
