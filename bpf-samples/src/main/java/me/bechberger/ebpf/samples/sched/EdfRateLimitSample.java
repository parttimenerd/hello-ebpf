// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.DeferredQueue;
import me.bechberger.ebpf.bpf.userspace.SchedulerRunner;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;

import java.util.HashMap;
import java.util.Map;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Earliest-deadline-first scheduler with per-pid rate limiting.
 *
 * <h2>What this proves about the framework</h2>
 * <p>This is the first sample to exercise the <em>time-gated</em> deferral path:
 * {@link DeferredQueue#deferUntil} plus {@link DeferredQueue#drainEligible} with a
 * real {@code nowNs}. A task that has run too recently is held in the queue with a
 * {@code notBefore} timestamp and only re-dispatched once wall-clock time passes it —
 * across multiple batches. It relies on the {@code schedule()} contract that a
 * {@link QueuedTask#copy()} stored in a data structure stays fully dispatchable in a
 * later batch (tasks not dispatched in a given batch are dropped and re-enqueued by
 * the BPF stall fallback, so re-holding them is safe).
 *
 * <h2>Why {@code schedule()} not {@code policy()}</h2>
 * <p>Two reasons. First, EDF must dispatch the <em>earliest deadline</em> across the
 * whole batch — you cannot pick the minimum while seeing one task at a time. Second,
 * rate limiting requires <em>deferring</em> a task rather than dispatching it, which
 * {@code policy(t)} (return-a-cpu-per-task) cannot express: there is no "not now" cpu.
 *
 * <h2>Algorithm</h2>
 * <ol>
 *   <li>Each pid gets a deadline = arrival time + {@code DEADLINE_NS}.</li>
 *   <li>A pid that was dispatched at time {@code T} may not run again before
 *       {@code T + MIN_GAP_NS} (its rate limit). Until then it is held via
 *       {@code deferUntil}.</li>
 *   <li>Every batch we merge the newly arrived tasks into the deferred queue, then
 *       drain everything that is time-eligible <em>now</em>, in deadline order, and
 *       dispatch each to {@link #ANY_CPU}.</li>
 * </ol>
 *
 * <p>Higher-weight tasks get a proportionally shorter rate-limit gap, so they win
 * more CPU — weight-proportional under a latency ceiling.
 */
public final class EdfRateLimitSample extends UserspaceScheduler {

    private static final long DEADLINE_NS = 20_000_000L;   // 20 ms scheduling deadline
    private static final long MIN_GAP_NS  = 4_000_000L;    // base 4 ms between dispatches

    /** Deferred tasks carried across batches, keyed by deadline. */
    private final DeferredQueue queue = new DeferredQueue();

    /** Last dispatch time per pid, for rate limiting. */
    private final Map<Integer, Long> lastDispatchNs = new HashMap<>();

    /** pids currently held in {@link #queue}, so we don't insert a pid twice. */
    private final Map<Integer, Boolean> held = new HashMap<>();

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        long nowNs = nanoTime();

        // Merge newly-arrived tasks into the deferred queue.
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            if (held.putIfAbsent(t.pid, Boolean.TRUE) != null) {
                continue;  // already sitting in the queue from a prior batch
            }
            long earliest = earliestDispatch(t.pid, nowNs, t.weight);
            long deadline = nowNs + DEADLINE_NS;
            // Key by deadline (EDF), but hold until the rate-limit gap has passed.
            if (earliest <= nowNs) {
                queue.deferOrdered(t, deadline);
            } else {
                queue.deferUntil(t, earliest);
            }
        }

        // Dispatch everything eligible now, earliest deadline first.
        queue.drainEligible(nowNs, Integer.MAX_VALUE, t -> {
            held.remove(t.pid);
            lastDispatchNs.put(t.pid, nowNs);
            dispatchTask(t, ANY_CPU);
        });
    }

    /** Earliest wall-clock time this pid may next be dispatched (rate limit). */
    private long earliestDispatch(int pid, long nowNs, long weight) {
        Long last = lastDispatchNs.get(pid);
        if (last == null) return nowNs;
        // Higher weight → shorter gap. weight defaults ~100; clamp to keep it sane.
        long gap = MIN_GAP_NS * 100 / Math.max(1, Math.min(10_000, weight));
        return last + gap;
    }

    @Override
    protected void tick() {
        // Bound both maps against pid churn: forget rate-limit history for pids we
        // haven't dispatched in a long time. Held pids are cleaned as they drain.
        long horizon = nanoTime() - DEADLINE_NS * 1_000L;
        lastDispatchNs.entrySet().removeIf(e -> e.getValue() < horizon);
        // Drop stale deferred entries whose notBefore is far in the past but which
        // (defensively) never drained; keeps the heap from leaking on edge cases. Clear
        // the matching `held` entry too, or the pid can never be re-queued (starvation).
        queue.evictOlderThan(horizon, t -> held.remove(t.pid));
    }

    @Override
    public String formatStats() {
        return super.formatStats()
                + "  deferred=" + queue.size()
                + " tracked=" + lastDispatchNs.size();
    }

    public static void main(String[] args) {
        SchedulerRunner.run(new EdfRateLimitSample(), args);
    }
}
