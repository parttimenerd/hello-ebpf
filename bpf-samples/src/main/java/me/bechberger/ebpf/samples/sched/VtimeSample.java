// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;

import java.util.HashMap;
import java.util.Map;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Weight-proportional vtime fair-share scheduler.
 *
 * <h2>Why this requires {@code schedule()} not {@code policy()}</h2>
 * <p>Fair-share scheduling requires dispatching the task with the <em>lowest
 * virtual time</em> first. With {@code policy(t)} you see one task at a time in
 * arrival order — you cannot pick the minimum-vtime task from the batch because
 * you don't see the others. {@code schedule(tasks, count)} gives you the whole
 * batch at once, so you can sort by vtime and dispatch in order.
 *
 * <p>This is exactly what {@code scx_rustland} does with a {@code BTreeSet}
 * ordered by deadline. Here we do the same with a {@link me.bechberger.ebpf.bpf.userspace.DeferredQueue}.
 *
 * <h2>Algorithm</h2>
 * <p>Each task has a virtual time {@code vtimes[pid]} maintained across batches.
 * On each batch:
 * <ol>
 *   <li>Insert all tasks into a {@link me.bechberger.ebpf.bpf.userspace.DeferredQueue} keyed by vtime.
 *   <li>Dispatch them in vtime order (lowest first) to {@link #ANY_CPU}.
 *   <li>Advance each dispatched task's vtime by {@code slice / weight}, where
 *       {@code slice} is a fixed quantum. Higher-weight tasks advance more slowly,
 *       so they win more often — weight-proportional fair share.
 * </ol>
 *
 * <p>Vtime is initialised to the current minimum across all tracked tasks so that
 * newly woken tasks don't get a huge catch-up burst.
 */
public final class VtimeSample extends UserspaceScheduler {

    private static final long SLICE_NS = 5_000_000L;  // 5 ms base quantum

    /** Per-pid virtual time, in ns units scaled by weight. */
    private final Map<Integer, Long> vtimes = new HashMap<>();

    /** Minimum vtime seen this tick — used to initialise new tasks fairly. */
    private long minVtime = 0;

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        var ordered = new me.bechberger.ebpf.bpf.userspace.DeferredQueue();
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            long vt = vtimes.computeIfAbsent(t.pid, p -> minVtime);
            ordered.deferOrdered(t, vt);
        }
        long[] newMin = { Long.MAX_VALUE };
        ordered.drainEligible(0, Integer.MAX_VALUE, t -> {
            long vt = vtimes.getOrDefault(t.pid, minVtime);
            long weight = Math.max(1, t.weight);
            long step = SLICE_NS * 100 / weight;
            long nextVt = vt + step;
            vtimes.put(t.pid, nextVt);
            if (nextVt < newMin[0]) newMin[0] = nextVt;
            dispatchTask(t, ANY_CPU);
        });
        if (newMin[0] != Long.MAX_VALUE) minVtime = newMin[0];
    }

    /** Evict vtimes for tasks not seen for a while to keep the map bounded. */
    @Override
    protected void tick() {
        // Simple age-out: if a pid hasn't appeared in a long time its vtime
        // entry can accumulate lag. Remove entries far ahead of minVtime —
        // they will be re-initialised at minVtime on next appearance anyway.
        long horizon = minVtime + SLICE_NS * 10_000L;
        vtimes.values().removeIf(vt -> vt > horizon);
    }

    public static void main(String[] args) {
        me.bechberger.ebpf.bpf.userspace.SchedulerRunner.run(new VtimeSample(), args);
    }
}
