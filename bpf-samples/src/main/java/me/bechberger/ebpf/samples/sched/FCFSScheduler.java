// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * First-Come-First-Served scheduler — tasks are dispatched in arrival order
 * with no preemption ({@code slice = -1}).
 *
 * <p>All tasks share a single DSQ ({@link SchedulerBase#SHARED_DSQ_ID}) and are
 * dispatched strictly in FIFO order. No CPU-selection heuristic is applied; the
 * kernel picks any available CPU.
 *
 * <p>Conceptually equivalent to the FIFO mode of
 * <a href="https://github.com/torvalds/linux/blob/6712c4fefca0422851b71d1a58a32ea03f69310f/tools/sched_ext/scx_simple.bpf.c">
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
public abstract class FCFSScheduler extends SchedulerBase implements Scheduler {

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insert(p, -1L, EnqFlags.passThrough(enq_flags));
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(FCFSScheduler.class)) {
            program.runSchedulerLoop();
        }
    }
}
