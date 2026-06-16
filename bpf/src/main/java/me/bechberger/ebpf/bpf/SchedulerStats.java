// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.type.Ptr;

/**
 * Optional mixin interface that adds per-CPU enqueue and dispatch counters to any
 * sched-ext scheduler.
 *
 * <p>To use, declare two {@code BPFPerCpuArray<Long>} fields in your scheduler class
 * annotated with {@code @BPFMapDefinition(maxEntries = 1)}, then call
 * {@link #incrementEnqueued(BPFPerCpuArray)} / {@link #incrementDispatched(BPFPerCpuArray)}
 * from your {@code enqueue()} and {@code dispatch()} implementations.
 *
 * <p>Read aggregate totals from Java via {@link #totalEnqueued(BPFPerCpuArray)} and
 * {@link #totalDispatched(BPFPerCpuArray)}.
 *
 * <p>Example:
 * <pre>{@code
 * @BPF(license = "GPL")
 * @Property(name = "sched_name", value = "my_sched")
 * public abstract class MyScheduler extends SchedulerBase {
 *
 *     @BPFMapDefinition(maxEntries = 1)
 *     BPFPerCpuArray<Long> enqueuedCounts;
 *
 *     @BPFMapDefinition(maxEntries = 1)
 *     BPFPerCpuArray<Long> dispatchedCounts;
 *
 *     @Override
 *     public void enqueue(Ptr<task_struct> p, long enq_flags) {
 *         dsqInsert(p, enq_flags);
 *         SchedulerStats.incrementEnqueued(enqueuedCounts);
 *     }
 *
 *     @Override
 *     public void dispatch(int cpu, Ptr<task_struct> prev) {
 *         super.dispatch(cpu, prev);
 *         SchedulerStats.incrementDispatched(dispatchedCounts);
 *     }
 *
 *     public static void main(String[] args) throws Exception {
 *         try (var prog = BPFProgram.load(MyScheduler.class)) {
 *             prog.runSchedulerLoop();
 *             System.out.println("enqueued=" + SchedulerStats.totalEnqueued(prog.enqueuedCounts));
 *         }
 *     }
 * }
 * }</pre>
 */
public final class SchedulerStats {

    private SchedulerStats() {}

    /**
     * Increments the per-CPU counter at index 0 of {@code counts} by 1.
     * Call from BPF context (e.g. inside {@code enqueue()}).
     */
    @BuiltinBPFFunction("""
            {
              long *__cnt = bpf_map_lookup_elem(&$arg1, &(u32){0});
              if (__cnt) (*__cnt)++;
            }
            """)
    @NotUsableInJava
    public static void incrementEnqueued(BPFPerCpuArray<Long> counts) {
        throw new UnsupportedOperationException("BPF-only");
    }

    /**
     * Increments the per-CPU counter at index 0 of {@code counts} by 1.
     * Call from BPF context (e.g. inside {@code dispatch()}).
     */
    @BuiltinBPFFunction("""
            {
              long *__cnt = bpf_map_lookup_elem(&$arg1, &(u32){0});
              if (__cnt) (*__cnt)++;
            }
            """)
    @NotUsableInJava
    public static void incrementDispatched(BPFPerCpuArray<Long> counts) {
        throw new UnsupportedOperationException("BPF-only");
    }

    /**
     * Returns the sum of the per-CPU enqueue counter across all CPUs.
     * Call from Java (user-space) context.
     */
    public static long totalEnqueued(BPFPerCpuArray<Long> counts) {
        return counts.getAll(0).stream().mapToLong(Long::longValue).sum();
    }

    /**
     * Returns the sum of the per-CPU dispatch counter across all CPUs.
     * Call from Java (user-space) context.
     */
    public static long totalDispatched(BPFPerCpuArray<Long> counts) {
        return counts.getAll(0).stream().mapToLong(Long::longValue).sum();
    }

    /**
     * Increments the per-CPU counter at {@code index} of {@code counts} by 1.
     * Use when one array holds multiple counters, e.g. one entry per priority queue.
     * Call from BPF context; read back from Java via {@link #totalEnqueuedAt}.
     */
    @BuiltinBPFFunction("""
            {
              u32 __idx = (u32)$arg2;
              long *__cnt = bpf_map_lookup_elem(&$arg1, &__idx);
              if (__cnt) (*__cnt)++;
            }
            """)
    @NotUsableInJava
    public static void incrementEnqueuedAt(BPFPerCpuArray<Long> counts, int index) {
        throw new UnsupportedOperationException("BPF-only");
    }

    /**
     * Increments the per-CPU counter at {@code index} of {@code counts} by 1.
     * Use when one array holds multiple dispatch counters, e.g. one entry per priority queue.
     * Call from BPF context; read back from Java via {@link #totalDispatchedAt}.
     */
    @BuiltinBPFFunction("""
            {
              u32 __idx = (u32)$arg2;
              long *__cnt = bpf_map_lookup_elem(&$arg1, &__idx);
              if (__cnt) (*__cnt)++;
            }
            """)
    @NotUsableInJava
    public static void incrementDispatchedAt(BPFPerCpuArray<Long> counts, int index) {
        throw new UnsupportedOperationException("BPF-only");
    }

    /**
     * Returns the sum of the per-CPU counter at {@code index} across all CPUs.
     * Companion to {@link #incrementEnqueuedAt}.
     * Call from Java (user-space) context.
     */
    public static long totalEnqueuedAt(BPFPerCpuArray<Long> counts, int index) {
        return counts.getAll(index).stream().mapToLong(Long::longValue).sum();
    }

    /**
     * Returns the sum of the per-CPU counter at {@code index} across all CPUs.
     * Companion to {@link #incrementDispatchedAt}.
     * Call from Java (user-space) context.
     */
    public static long totalDispatchedAt(BPFPerCpuArray<Long> counts, int index) {
        return counts.getAll(index).stream().mapToLong(Long::longValue).sum();
    }
}
