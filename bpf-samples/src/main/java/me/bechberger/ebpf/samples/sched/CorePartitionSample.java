// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.SchedulerRunner;
import me.bechberger.ebpf.bpf.userspace.TaskClassifier;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;

/**
 * <b>Experimental</b> — API may change without notice.
 *
 * <p>CPU-partitioning scheduler: pins interactive work to the low core half and batch
 * work to the high core half, so a burst of {@code nice 19} hogs cannot evict a
 * latency-sensitive task from its cores.
 *
 * <h2>What this proves about the framework</h2>
 * <p>Every other classifier sample routes to {@link #ANY_CPU} and lets BPF place the task;
 * the tier only drives a deadline. This one uses {@link TaskClassifier}'s <em>placement</em>
 * policies for what they are for — mapping a task class to an actual CPU. {@code decide(t)}
 * classifies the task and returns a concrete core from that class's pool, and
 * {@code dispatchTask(t, cpu)} honours it (the framework validates the CPU is in range).
 *
 * <h2>Partitioning</h2>
 * <p>With {@code N} CPUs, cores {@code [0, N/2)} are the INTERACTIVE pool and
 * {@code [N/2, N)} the BATCH pool. Within a pool we round-robin so a class spreads across
 * its cores. A task is INTERACTIVE when its {@code weight} is at least {@link #INTERACTIVE_WEIGHT}
 * (nice ≤ 0), BATCH otherwise. On a single-CPU box both pools collapse to core 0.
 */
public final class CorePartitionSample extends UserspaceScheduler {

    enum Pool { INTERACTIVE, BATCH }

    private static final long INTERACTIVE_WEIGHT = 100;

    // Round-robin cursors, one per pool, so tasks fan out across a pool's cores.
    private int interactiveCursor = 0;
    private int batchCursor = 0;

    private final TaskClassifier<Pool> classifier = TaskClassifier.<Pool>builder()
            .classify(t -> t.weight >= INTERACTIVE_WEIGHT ? Pool.INTERACTIVE : Pool.BATCH)
            .policy(Pool.INTERACTIVE, t -> nextInteractiveCpu())
            .policy(Pool.BATCH, t -> nextBatchCpu())
            .build();

    /** Boundary between the two pools; read lazily so a harness withCpus() override is honoured. */
    private int split() {
        return Math.max(1, cpuCount() / 2);
    }

    /** Cores [0, split) — always at least core 0. */
    private int nextInteractiveCpu() {
        int split = split();
        int cpu = interactiveCursor % split;
        interactiveCursor++;
        return cpu;
    }

    /**
     * Cores [split, cpuCount). When that range is empty (single-CPU box, where split == cpuCount)
     * the batch pool collapses onto core 0.
     */
    private int nextBatchCpu() {
        int split = split();
        int poolSize = cpuCount() - split;
        if (poolSize <= 0) return 0;
        int cpu = split + (batchCursor % poolSize);
        batchCursor++;
        return cpu;
    }

    @Override
    protected int policy(QueuedTask t) {
        return classifier.decide(t);
    }

    /** Test seam: the pool a task would be routed to. */
    Pool poolOf(QueuedTask t) {
        return classifier.classOf(t);
    }

    public static void main(String[] args) {
        SchedulerRunner.run(new CorePartitionSample(), args);
    }
}
