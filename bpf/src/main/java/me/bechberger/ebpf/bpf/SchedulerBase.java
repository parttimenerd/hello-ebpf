// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Convenience base class for sched-ext schedulers.
 *
 * <p>Provides a pre-wired shared FIFO DSQ at {@link #SHARED_DSQ_ID}, a default
 * {@link #init()} that creates it, and a default {@link #dispatch(int, Ptr)} that
 * moves tasks from it to the local CPU queue.  Subclasses only need to
 * implement {@link Scheduler#enqueue(Ptr, long)}.
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

    /**
     * Inserts {@code p} into {@link #SHARED_DSQ_ID} with the default slice,
     * scaled inversely by the current queue depth to avoid starvation.
     *
     * <p>Equivalent to the pattern used in {@code MinimalScheduler} and
     * {@code FCFSScheduler}.
     */
    @BPFFunction
    public void dsqInsert(Ptr<task_struct> p, long enq_flags) {
        @Unsigned int queued = scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        long slice = queued > 0 ? SCX_SLICE_DFL.value() / queued : SCX_SLICE_DFL.value();
        scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, enq_flags);
    }

    /**
     * Selects a CPU for the waking task using the kernel default, optionally
     * pre-dispatching directly to the local queue when an idle CPU is found.
     *
     * <p>Calls {@code scx_bpf_select_cpu_dfl} and, when an idle CPU is chosen,
     * inserts the task directly into {@code SCX_DSQ_LOCAL} to avoid a round-trip
     * through {@code enqueue}/{@code dispatch}.  Override {@link #selectCPU} to
     * customise fully.
     *
     * @return target CPU for the waking task
     */
    @BPFFunction
    public int selectCpuDefault(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL.value(), SCX_SLICE_DFL.value(), 0);
        }
        return cpu;
    }

    /**
     * Unsigned-safe {@code a < b} comparison for virtual time values.
     */
    @BPFFunction
    @AlwaysInline
    public boolean isSmaller(@Unsigned long a, @Unsigned long b) {
        return (long) (a - b) < 0;
    }

    /**
     * Inserts {@code p} into {@link #SHARED_DSQ_ID} using vtime-ordered priority.
     *
     * <p>Clamps the task's accumulated vtime so that idle tasks cannot build up
     * more than one {@code SCX_SLICE_DFL} of budget ahead of the global vtime.
     *
     * @param vtimeNow current global virtual time
     */
    @BPFFunction
    public void vtimeEnqueue(Ptr<task_struct> p, long enq_flags, @Unsigned long vtimeNow) {
        @Unsigned long vtime = p.val().scx.dsq_vtime;
        if (isSmaller(vtime, vtimeNow - SCX_SLICE_DFL.value())) {
            vtime = vtimeNow - SCX_SLICE_DFL.value();
        }
        scx_bpf_dsq_insert_vtime(p, SHARED_DSQ_ID, SCX_SLICE_DFL.value(), vtime, enq_flags);
    }

    /**
     * Charges execution time to {@code p}'s virtual time, scaled by the inverse
     * of the task's weight (so heavier tasks advance their vtime more slowly).
     *
     * <p>Call from {@link Scheduler#stopping(Ptr, boolean)}.
     */
    @BPFFunction
    public void vtimeCharge(Ptr<task_struct> p) {
        p.val().scx.dsq_vtime +=
                (SCX_SLICE_DFL.value() - p.val().scx.slice) * 100 / p.val().scx.weight;
    }

    /**
     * Selects a CPU for a waking task, optionally pre-dispatching to {@code dsqId}
     * when an idle CPU is found (avoids a full enqueue/dispatch round-trip).
     *
     * <p>Unlike {@link #selectCpuDefault(Ptr, int, long)}, this variant accepts a
     * caller-supplied {@code dsqId} so that multi-DSQ schedulers can use it too.
     *
     * @param dsqId DSQ to pre-dispatch into when an idle CPU is chosen
     */
    @BPFFunction
    public int selectCpuIdleOrFallback(Ptr<task_struct> p, int prev_cpu, long wake_flags,
                                       @Unsigned long dsqId) {
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            scx_bpf_dsq_insert(p, dsqId, SCX_SLICE_DFL.value(), 0);
        }
        return cpu;
    }
}


