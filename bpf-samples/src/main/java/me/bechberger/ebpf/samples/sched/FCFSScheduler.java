// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * First-Come-First-Served scheduler — tasks are dispatched in arrival order
 * with no preemption ({@code slice = -1}).
 *
 * <p>All tasks share a single DSQ and are dispatched strictly in FIFO order.
 * No CPU-selection heuristic is applied; the kernel picks any available CPU.
 *
 * <p>Conceptually equivalent to the FIFO mode of
 * <a href="https://github.com/torvalds/linux/blob/master/tools/sched_ext/scx_simple.bpf.c">
 * {@code scx_simple.bpf.c}</a> from the Linux kernel.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh FCFSScheduler
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "fcfs_scheduler")
@Property(name = "timeout_ms", value = "10000")
public abstract class FCFSScheduler extends BPFProgram implements Scheduler {

    private static final int SHARED_DSQ_ID = 0;

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        scx_bpf_dsq_insert(p, SHARED_DSQ_ID,  -1, enq_flags);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(FCFSScheduler.class)) {
            program.runSchedulerLoop();
        }
    }
}
