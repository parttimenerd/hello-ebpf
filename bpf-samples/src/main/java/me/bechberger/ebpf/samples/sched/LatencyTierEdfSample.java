// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.DeferredQueue;
import me.bechberger.ebpf.bpf.userspace.SchedulerRunner;
import me.bechberger.ebpf.bpf.userspace.TaskClassifier;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>Latency-tiered earliest-deadline-first scheduler.
 *
 * <h2>What this proves about the framework</h2>
 * <p>This is the canonical "real scheduler" shape: it combines the two Sub-project C
 * helpers the way they were designed to be used together.
 * <ul>
 *   <li>{@link TaskClassifier} maps each task to a latency {@link Tier} from its
 *       {@code weight} (kernel-derived from nice level), and — via {@code decide()} —
 *       routes it (here everything goes to {@link #ANY_CPU}; the classifier's real job
 *       is the tier lookup that drives the deadline).</li>
 *   <li>{@link DeferredQueue} orders the whole batch by <em>effective deadline</em>
 *       (arrival + tier latency target) so lower-latency tiers are dispatched first
 *       even when they arrived later — true EDF across tiers.</li>
 * </ul>
 * Neither is possible with {@code policy(t)} alone: EDF needs the whole batch at once,
 * and the tier→deadline mapping is exactly the classify-then-route pattern
 * {@code TaskClassifier} exists to remove the boilerplate from.
 *
 * <h2>Tiers</h2>
 * <ul>
 *   <li>{@code INTERACTIVE} — weight ≥ 100 (nice ≤ 0): 2 ms latency target.</li>
 *   <li>{@code NORMAL} — 20 ≤ weight &lt; 100: 10 ms target.</li>
 *   <li>{@code BATCH} — weight &lt; 20 (nice ≥ ~10): 50 ms target.</li>
 * </ul>
 */
public final class LatencyTierEdfSample extends UserspaceScheduler {

    enum Tier { INTERACTIVE, NORMAL, BATCH }

    /** Per-tier latency target in ns — the deadline offset from arrival. */
    private static long latencyTargetNs(Tier tier) {
        return switch (tier) {
            case INTERACTIVE -> 2_000_000L;
            case NORMAL      -> 10_000_000L;
            case BATCH       -> 50_000_000L;
        };
    }

    private final TaskClassifier<Tier> classifier = TaskClassifier.<Tier>builder()
            .classify(t -> {
                if (t.weight >= 100) return Tier.INTERACTIVE;
                if (t.weight >= 20)  return Tier.NORMAL;
                return Tier.BATCH;
            })
            // All tiers dispatch to any idle CPU; the tier drives the deadline, not placement.
            .policy(Tier.INTERACTIVE, t -> ANY_CPU)
            .policy(Tier.NORMAL,      t -> ANY_CPU)
            .policy(Tier.BATCH,       t -> ANY_CPU)
            .build();

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        long nowNs = nanoTime();
        var queue = new DeferredQueue();
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            Tier tier = classifier.classOf(t);
            long deadline = nowNs + latencyTargetNs(tier);
            queue.deferOrdered(t, deadline);
        }
        // Earliest deadline first across all tiers.
        queue.drainEligible(nowNs, Integer.MAX_VALUE, t -> dispatchTask(t, classifier.decide(t)));
    }

    public static void main(String[] args) {
        SchedulerRunner.run(new LatencyTierEdfSample(), args);
    }
}
