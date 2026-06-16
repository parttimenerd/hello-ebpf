// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Convenience base class for sched-ext schedulers.
 *
 * <p>Provides a pre-wired shared FIFO DSQ at {@link #SHARED_DSQ_ID}, a default
 * {@link #init()} that creates it, and a default {@link #dispatch(int, Ptr)} that
 * moves tasks from it to the local CPU queue.  Subclasses only need to implement
 * {@link Scheduler#enqueue(Ptr, long)}.
 *
 * <p>BPF-side helpers such as {@code dsqInsert}, {@code selectCpuDfl},
 * {@code selectCpuFifoIdleOrFallback}, {@code isSmaller}, {@code vtimeEnqueue},
 * and {@code vtimeCharge} are inherited from the {@link Scheduler} interface and
 * are available in BPF context to any class that implements {@link Scheduler}.
 *
 * <p>Usage:
 * <pre>{@code
 * @BPF(license = "GPL")
 * @Property(name = "sched_name", value = "my_sched")
 * public abstract class MyScheduler extends SchedulerBase {
 *
 *     @Override
 *     public void enqueue(Ptr<task_struct> p, long enq_flags) {
 *         dsqInsert(p, enq_flags);  // insert into the shared DSQ
 *     }
 * }
 * }</pre>
 */
public abstract class SchedulerBase extends BPFProgram implements Scheduler {

    /** DSQ ID used by the pre-wired shared queue. */
    public static final long SHARED_DSQ_ID = 0;

    /**
     * Creates the shared DSQ on the local NUMA node.
     * Override to create additional DSQs or pin to a specific node.
     */
    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    /**
     * Moves all pending tasks from {@link #SHARED_DSQ_ID} to the current CPU's
     * local dispatch queue.
     */
    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    }
}
