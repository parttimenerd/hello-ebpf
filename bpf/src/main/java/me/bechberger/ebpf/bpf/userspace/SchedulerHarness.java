// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Drives a {@link UserspaceScheduler} subclass offline — synthetic batches in, captured
 * decisions out — with no BPF file descriptor and no root. Tests <em>policy decisions</em>,
 * not kernel timing/preemption. Complements the thinkstation smoke tests.
 *
 * <pre>{@code
 * var harness = SchedulerHarness.forScheduler(new MyScheduler()).withCpus(8);
 * harness.feed(task(100, 200), task(101, 100));
 * harness.runBatch();
 * assertThat(harness.dispatches()).extracting(Dispatch::pid).containsExactly(100, 101);
 * }</pre>
 */
public final class SchedulerHarness {

    /** A captured dispatch decision. */
    public record Dispatch(int targetCpu, int pid) {}

    private final UserspaceScheduler sched;
    private final List<Dispatch> dispatches = new ArrayList<>();
    private int cpus = Runtime.getRuntime().availableProcessors();

    private SchedulerHarness(UserspaceScheduler sched) {
        this.sched = sched;
        sched.offlineDispatchSink = arr -> dispatches.add(new Dispatch(arr[0], arr[1]));
    }

    public static SchedulerHarness forScheduler(UserspaceScheduler sched) {
        return new SchedulerHarness(sched);
    }

    public SchedulerHarness withCpus(int n) { this.cpus = n; return this; }

    /** Queue tasks for the next {@link #runBatch}. */
    public SchedulerHarness feed(QueuedTask... tasks) {
        sched.offlineFeed = new ArrayList<>(Arrays.asList(tasks));
        return this;
    }

    /** Run one batch through the scheduler's schedule() path; captured dispatches accumulate. */
    public void runBatch() {
        sched.runBatchOffline();
        sched.offlineFeed = null;
    }

    /** Drive one periodic tick(). */
    public void tick() { sched.tick(); }

    /** All dispatches captured so far, in order. */
    public List<Dispatch> dispatches() { return List.copyOf(dispatches); }

    /** Clear captured dispatches (e.g. between assertion phases). */
    public void clear() { dispatches.clear(); }

    public int cpus() { return cpus; }
}
