// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies per-class metrics record the task's runtime distribution, not a constant.
 * {@link ClassMetrics#count()} counts dispatches per class; {@code p50}/{@code p99} must
 * reflect the {@link QueuedTask#execRuntime} values seen, so widely different runtimes land
 * in different log2 buckets (previously the dispatch path recorded a constant 1, making the
 * percentiles meaningless).
 */
class PerClassMetricsTest {

    enum Band { SHORT, LONG }

    /** Dispatches every fed task and classifies by runtime into two bands. */
    static final class MetricSched extends FakeSchedulerBase {
        MetricSched() {
            setClassMetrics(TaskClassifier.<Band>builder()
                    .classify(t -> t.execRuntime < 10_000 ? Band.SHORT : Band.LONG)
                    .policy(Band.SHORT, t -> ANY_CPU)
                    .policy(Band.LONG, t -> ANY_CPU)
                    .build());
        }

        @Override
        protected void schedule(QueuedTask[] tasks, int count) {
            for (int i = 0; i < count; i++) dispatchTask(tasks[i], ANY_CPU);
        }
    }

    private QueuedTask task(int pid, long execRuntime) {
        var t = new QueuedTask();
        t.pid = pid;
        t.execRuntime = execRuntime;
        return t;
    }

    @Test
    void countReflectsDispatchesPerClass() {
        var sched = new MetricSched();
        SchedulerHarness.forScheduler(sched).withCpus(8)
                .feed(task(1, 100), task(2, 200), task(3, 1_000_000))
                .runBatch();

        assertEquals(2, sched.perClass(Band.SHORT).count(), "two short-runtime tasks dispatched");
        assertEquals(1, sched.perClass(Band.LONG).count(), "one long-runtime task dispatched");
    }

    @Test
    void percentilesTrackRuntimeNotConstant() {
        var shortSched = new MetricSched();
        SchedulerHarness.forScheduler(shortSched).withCpus(8)
                .feed(task(1, 100), task(2, 300))          // SHORT: ~hundreds of ns
                .runBatch();
        long shortP50 = shortSched.perClass(Band.SHORT).p50();
        assertTrue(shortP50 > 1,
                "p50 must reflect real runtime, not the old constant 1: " + shortP50);

        // A long-runtime task must land in a strictly higher bucket than the short ones.
        var longSched = new MetricSched();
        SchedulerHarness.forScheduler(longSched).withCpus(8)
                .feed(task(9, 5_000_000)).runBatch();
        long longP50 = longSched.perClass(Band.LONG).p50();
        assertTrue(longP50 > shortP50,
                "a 5 ms task must sit in a higher bucket than sub-microsecond tasks: "
                        + longP50 + " vs " + shortP50);
    }

    @Test
    void unseenClassReturnsNull() {
        var sched = new MetricSched();
        SchedulerHarness.forScheduler(sched).withCpus(8).feed(task(1, 100)).runBatch();
        assertNull(sched.perClass(Band.LONG), "a class never dispatched has no metrics");
    }
}
