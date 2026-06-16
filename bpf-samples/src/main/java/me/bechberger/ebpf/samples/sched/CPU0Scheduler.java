// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerStats;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A Java reimplementation of the concept behind {@code scx_cpu0}.
 *
 * <p>All tasks are concentrated on CPU 0 in FIFO order.  This is a deliberate
 * single-core bottleneck scheduler useful for correctness testing and
 * reproducing serial execution behaviour.
 *
 * <p>Tasks already on CPU 0 are inserted into the shared DSQ, which is drained
 * by CPU 0's {@code dispatch()} hook.  Tasks on other CPUs are dispatched
 * immediately to their own local queues (so they can keep running without
 * creating a deadlock) and will eventually migrate to CPU 0.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh CPU0Scheduler
 * </pre>
 *
 * <p>Based on
 * <a href="https://github.com/torvalds/linux/blob/master/tools/sched_ext/scx_cpu0.bpf.c">
 * {@code tools/sched_ext/scx_cpu0.bpf.c}</a> from the Linux kernel.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "cpu0_scheduler")
public abstract class CPU0Scheduler extends BPFProgram implements Scheduler {

    static final long CPU0_DSQ_ID = 0;

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> dispatchedCounts;

    @Override
    public int init() {
        return scx_bpf_create_dsq(CPU0_DSQ_ID, -1);
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        return 0;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        if (scx_bpf_task_cpu(p) != 0) {
            // Task is on a non-CPU-0 core: let it run locally to avoid deadlock.
            // It will eventually migrate to CPU 0 via selectCPU.
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL.value(), SCX_SLICE_DFL.value(), 0);
        } else {
            scx_bpf_dsq_insert(p, CPU0_DSQ_ID, SCX_SLICE_DFL.value(), enq_flags);
        }
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        if (cpu == 0) {
            scx_bpf_dsq_move_to_local(CPU0_DSQ_ID);
            SchedulerStats.incrementDispatched(dispatchedCounts);
        }
    }

    public long getTotalDispatched() {
        return SchedulerStats.totalDispatched(dispatchedCounts);
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(CPU0Scheduler.class)) {
            prog.runSchedulerLoop();
        }
    }
}
