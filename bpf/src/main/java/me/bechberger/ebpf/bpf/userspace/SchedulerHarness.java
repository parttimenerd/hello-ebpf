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
 *
 * <p>For time-based policies (rate limiting, EDF, {@code deferUntil}), install a virtual
 * clock so batches don't all run at "now":
 * <pre>{@code
 * var h = SchedulerHarness.forScheduler(new RateLimitedScheduler())
 *         .withVirtualClock(0);
 * h.feed(task(1)).runBatch();          // dispatches at t=0
 * h.feed(task(1)).runBatch();          // still rate-limited, held
 * h.advanceMillis(10).feed(task(1)).runBatch();  // gap elapsed → dispatches
 * }</pre>
 */
public final class SchedulerHarness {

    /** A captured dispatch decision. */
    public record Dispatch(int targetCpu, int pid) {}

    private final UserspaceScheduler sched;
    private final List<Dispatch> dispatches = new ArrayList<>();
    private int cpus = Runtime.getRuntime().availableProcessors();

    /** Virtual clock value in ns; null until {@link #withVirtualClock} is called. */
    private long[] virtualNowNs = null;

    private SchedulerHarness(UserspaceScheduler sched) {
        this.sched = sched;
        sched.offlineDispatchSink = arr -> dispatches.add(new Dispatch(arr[0], arr[1]));
    }

    public static SchedulerHarness forScheduler(UserspaceScheduler sched) {
        return new SchedulerHarness(sched);
    }

    /**
     * Model a machine with {@code n} CPUs. This drives the scheduler's dispatch-range
     * validation and idle-CPU wrap-around, so a CPU-targeting scheduler can be tested for a
     * machine size other than the host running the test (e.g. asserting core-pool placement on
     * a modeled 8-CPU box while the CI runner has 4).
     */
    public SchedulerHarness withCpus(int n) {
        if (n < 1) throw new IllegalArgumentException("withCpus requires at least 1 CPU: " + n);
        this.cpus = n;
        sched.nrCpus = n;
        return this;
    }

    /**
     * Install a virtual clock starting at {@code startNs}, replacing the scheduler's
     * {@code System.nanoTime()} reads (via {@link UserspaceScheduler#nanoTime()}). Time only
     * moves when you call {@link #advanceNanos} / {@link #advanceMillis}, making time-based
     * policies (rate limiting, EDF deadlines, {@code deferUntil}) deterministically testable.
     */
    public SchedulerHarness withVirtualClock(long startNs) {
        long[] now = { startNs };
        this.virtualNowNs = now;
        sched.nanoClock = () -> now[0];
        return this;
    }

    /** Advance the virtual clock by {@code deltaNs}. Requires {@link #withVirtualClock}. */
    public SchedulerHarness advanceNanos(long deltaNs) {
        if (virtualNowNs == null) {
            throw new IllegalStateException(
                    "advanceNanos requires withVirtualClock(startNs) to have been called first");
        }
        if (deltaNs < 0) {
            throw new IllegalArgumentException("cannot move a monotonic clock backwards: " + deltaNs);
        }
        virtualNowNs[0] += deltaNs;
        return this;
    }

    /** Advance the virtual clock by {@code deltaMs} milliseconds. Requires {@link #withVirtualClock}. */
    public SchedulerHarness advanceMillis(long deltaMs) {
        return advanceNanos(deltaMs * 1_000_000L);
    }

    /** Current virtual-clock value in ns. Requires {@link #withVirtualClock}. */
    public long nowNs() {
        if (virtualNowNs == null) {
            throw new IllegalStateException("nowNs requires withVirtualClock(startNs)");
        }
        return virtualNowNs[0];
    }

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
