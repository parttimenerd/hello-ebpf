// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.SchedulerStats;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dsq_move_to_local;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A direct Java reimplementation of the Linux kernel's {@code scx_simple} scheduler.
 *
 * <p>Supports two modes, switchable at runtime via {@link #setFifoMode(boolean)}:
 * <ul>
 *   <li><b>FIFO mode</b> (default) — tasks are inserted in arrival order with
 *       auto-scaled time slices, equivalent to {@link MinimalScheduler}.</li>
 *   <li><b>vtime mode</b> — weighted fair-queuing using virtual time, equivalent
 *       to {@link VTimeScheduler}.  Idle tasks are given at most one slice budget.</li>
 * </ul>
 *
 * <p>Based on
 * <a href="https://github.com/torvalds/linux/blob/master/tools/sched_ext/scx_simple.bpf.c">
 * {@code tools/sched_ext/scx_simple.bpf.c}</a> from the Linux kernel.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "simple_scheduler")
public abstract class SimpleScheduler extends SchedulerBase implements Scheduler {

    /** Current global virtual time; only meaningful in vtime mode. */
    final GlobalVariable<@Unsigned Long> vtimeNow = new GlobalVariable<>(0L);

    /** When {@code true}, use FIFO ordering; when {@code false}, use vtime fair-queuing. */
    final GlobalVariable<Boolean> fifoMode = new GlobalVariable<>(true);

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> enqueuedCounts;

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> dispatchedCounts;

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        return selectCpuFifoIdleOrFallback(p, prev_cpu, wake_flags, SHARED_DSQ_ID);
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        if (fifoMode.get()) {
            dsqInsert(p, enq_flags);
        } else {
            vtimeEnqueue(p, enq_flags, vtimeNow.get());
        }
        SchedulerStats.incrementEnqueued(enqueuedCounts);
    }

    @Override
    public void running(Ptr<task_struct> p) {
        if (!fifoMode.get()) {
            // Advance global vtime to at least this task's vtime so tasks that just
            // woke up don't see a stale vtime_now and accumulate too much budget.
            @Unsigned long vtime = p.val().scx.dsq_vtime;
            if (isSmaller(vtimeNow.get(), vtime)) {
                vtimeNow.set(vtime);
            }
        }
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        if (!fifoMode.get()) {
            vtimeCharge(p);
        }
    }

    @Override
    public void enable(Ptr<task_struct> p) {
        // Give new tasks the current global vtime so they don't start with an
        // unfair advantage from an empty (zero) vtime.
        p.val().scx.dsq_vtime = vtimeNow.get();
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
        SchedulerStats.incrementDispatched(dispatchedCounts);
    }

    // --- Java-side API ---

    /** Switches the scheduler between FIFO and vtime-fair modes. */
    public void setFifoMode(boolean fifo) {
        fifoMode.set(fifo);
    }

    /** Returns {@code true} when currently running in FIFO mode. */
    public boolean isFifoMode() {
        return fifoMode.get();
    }

    /** Returns total tasks enqueued since the scheduler started. */
    public long getTotalEnqueued() {
        return SchedulerStats.totalEnqueued(enqueuedCounts);
    }

    /** Returns total dispatch cycles since the scheduler started. */
    public long getTotalDispatched() {
        return SchedulerStats.totalDispatched(dispatchedCounts);
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(SimpleScheduler.class)) {
            prog.runSchedulerLoop();
            System.out.println("total enqueued:  " + prog.getTotalEnqueued());
            System.out.println("total dispatched: " + prog.getTotalDispatched());
        }
    }
}
