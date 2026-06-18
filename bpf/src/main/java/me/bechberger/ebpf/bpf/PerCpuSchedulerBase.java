// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.BoundedBy;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Convenience base class for sched-ext schedulers that use one DSQ per CPU plus a
 * shared global fallback.
 *
 * <p>Layout:
 * <ul>
 *   <li>DSQ {@code PER_CPU_DSQ_BASE + cpu} — pinned local queue for each logical CPU.</li>
 *   <li>DSQ {@link #SHARED_DSQ_ID} ({@code 0}) — global FIFO fallback for tasks that
 *       may migrate freely.</li>
 * </ul>
 *
 * <p>{@link #dispatch(int, Ptr)} drains the local per-CPU DSQ first, then falls back to
 * the shared DSQ.  {@link #dsqInsertLocal(Ptr, long)} enqueues into the caller-CPU's
 * pinned DSQ; {@link #dsqInsert(Ptr, long)} (inherited from {@link Scheduler}) enqueues
 * into the shared FIFO.
 *
 * <p>Subclasses only need to implement {@link Scheduler#enqueue(Ptr, long)}.  A typical
 * implementation routes non-migratable tasks to the per-CPU DSQ and everything else to
 * the shared DSQ:
 *
 * <pre>{@code
 * @BPF(license = "GPL")
 * @Property(name = "sched_name", value = "my_per_cpu_sched")
 * public abstract class MyScheduler extends PerCpuSchedulerBase {
 *
 *     @Override
 *     public void enqueue(Ptr<task_struct> p, long enq_flags) {
 *         if (isMigrationDisabled(p)) {
 *             dsqInsertLocal(p, enq_flags);
 *         } else {
 *             dsqInsert(p, enq_flags);
 *         }
 *     }
 * }
 * }</pre>
 */
public abstract class PerCpuSchedulerBase extends SchedulerBase {

    /** DSQ IDs for per-CPU queues start at this offset. CPU {@code n} uses {@code PER_CPU_DSQ_BASE + n}. */
    public static final long PER_CPU_DSQ_BASE = 1L;

    /** Maximum number of CPUs supported. Must be at least as large as the host CPU count. */
    public static final int MAX_CPUS = 512;

    /**
     * Creates the shared DSQ and one per-CPU DSQ for each logical CPU.
     */
    @Override
    @BPFFunction(headerTemplate = "s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init)", addDefinition = false)
    public int init() {
        int ret = scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        if (ret < 0) return ret;
        long nrCpus = scx_bpf_nr_cpu_ids();
        for (@BoundedBy(MAX_CPUS) int cpu = 0; (@Unsigned long) cpu < (@Unsigned long) nrCpus; cpu++) {
            ret = scx_bpf_create_dsq(PER_CPU_DSQ_BASE + cpu, -1);
            if (ret < 0) return ret;
        }
        return 0;
    }

    /**
     * Drains the per-CPU DSQ for {@code cpu} first; if that DSQ is empty,
     * falls back to the shared {@link #SHARED_DSQ_ID} DSQ.  Safe to return
     * without dispatching anything — the kernel will call again.
     */
    @Override
    @BPFFunction(headerTemplate = "void BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev)", addDefinition = false)
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        if (!DispatchQueue.attach(PER_CPU_DSQ_BASE + cpu).moveToLocal()) {
            DispatchQueue.attach(SHARED_DSQ_ID).moveToLocal();
        }
    }

    /**
     * Inserts {@code p} into the per-CPU DSQ of the CPU that {@code p} is currently
     * bound to (via {@code scx_bpf_task_cpu}).  Safe to call for non-migratable tasks.
     *
     * @param p         task to enqueue
     * @param enq_flags {@code SCX_ENQ_*} flags from the kernel
     */
    // The literal 1 below mirrors PER_CPU_DSQ_BASE; @BuiltinBPFFunction templates
    // only accept $-placeholders, so the constant cannot be referenced symbolically.
    @BuiltinBPFFunction("scx_bpf_dsq_insert($arg1, 1 + scx_bpf_task_cpu($arg1), SCX_SLICE_DFL, $arg2)")
    public void dsqInsertLocal(Ptr<task_struct> p, long enq_flags) {
        int cpu = scx_bpf_task_cpu(p);
        DispatchQueue.attach(PER_CPU_DSQ_BASE + cpu).insert(p, scx_public_consts.SCX_SLICE_DFL.value(),
                EnqFlags.passThrough(enq_flags));
    }
}
