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
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A weighted virtual-time fair scheduler.
 *
 * <p>Tasks are dispatched from a vtime-ordered DSQ; the task with the smallest
 * virtual time runs first.  After a task finishes a scheduling slice its vtime
 * is advanced by {@code elapsed_ns * 100 / weight}, so heavier (higher-priority)
 * tasks accumulate vtime more slowly and are therefore preferred.
 *
 * <p>Sleeping tasks can accumulate at most one slice of budget so that a task
 * returning from a long sleep cannot monopolise the CPU.
 *
 * <p>Based on
 * <a href="https://github.com/torvalds/linux/blob/6712c4fefca0422851b71d1a58a32ea03f69310f/tools/sched_ext/scx_simple.bpf.c">
 * {@code scx_simple.bpf.c}</a> (vtime mode) from the Linux kernel.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh VTimeScheduler
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "vtime_scheduler")
@Property(name = "timeout_ms", value = "10000")
public abstract class VTimeScheduler extends SchedulerBase implements Scheduler {

    // current vtime
    final GlobalVariable<@Unsigned Long> vtime_now =
            new GlobalVariable<>(0L);

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> enqueuedCounts;

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> dispatchedCounts;

    /*
     * SchedulerBase.init() already creates SHARED_DSQ_ID — attach without a
     * second scx_bpf_create_dsq call.
     */
    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu,
                         long wake_flags) {
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu,
                wake_flags, Ptr.of(is_idle));
        DispatchQueue.insertToLocalIfIdle(p, is_idle, SCX_SLICE_DFL.value());
        return cpu;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertVtimeClamped(p, vtime_now.get(), EnqFlags.passThrough(enq_flags));
        SchedulerStats.incrementEnqueued(enqueuedCounts);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();
        SchedulerStats.incrementDispatched(dispatchedCounts);
    }

    @Override
    public void running(Ptr<task_struct> p) {
        /*
         * Global vtime always progresses forward as tasks
         * start executing. The test and update can be
         * performed concurrently from multiple CPUs and
         * thus racy. Any error should be contained and
         * temporary. Let's just live with it.
         */
        @Unsigned long vtime = p.val().scx.dsq_vtime;
        if (isSmaller(vtime_now.get(), vtime)) {
            vtime_now.set(vtime);
        }
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        /*
         * Scale the execution time by the inverse of the weight
         * and charge.
         *
         * Note that the default yield implementation yields by
         * setting @p->scx.slice to zero and the following would
         * treat the yielding task
         * as if it has consumed all its slice. If this penalizes
         * yielding tasks too much, determine the execution time
         * by taking explicit timestamps instead of depending on
         * @p->scx.slice.
         */
        p.val().scx.dsq_vtime +=
                (SCX_SLICE_DFL.value() - p.val().scx.slice) * 100
                        / p.val().scx.weight;
    }

    @Override
    public void enable(Ptr<task_struct> p) {
        /*
         * Set the virtual time to the current vtime, when the task
         * is about to be scheduled for the first time
         */
        p.val().scx.dsq_vtime = vtime_now.get();
    }

    public long getTotalEnqueued() {
        return SchedulerStats.totalEnqueued(enqueuedCounts);
    }

    public long getTotalDispatched() {
        return SchedulerStats.totalDispatched(dispatchedCounts);
    }

    public static void main(String[] args) {
        try (var program =
                     BPFProgram.load(VTimeScheduler.class)) {
            program.runSchedulerLoop();
        }
    }

}
