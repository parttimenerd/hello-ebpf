// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dsq_move_to_local;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A minimal FIFO scheduler using {@link SchedulerBase}.
 *
 * <p>Only {@link #enqueue} needs to be implemented — {@link SchedulerBase}
 * provides {@link #init()}, {@link #dispatch}, and {@link #dsqInsert}.
 *
 * <p>Conceptually equivalent to the FIFO mode of
 * <a href="https://github.com/torvalds/linux/blob/6712c4fefca0422851b71d1a58a32ea03f69310f/tools/sched_ext/scx_simple.bpf.c">
 * {@code scx_simple.bpf.c}</a> from the Linux kernel, stripped to the minimum
 * required to demonstrate the {@link SchedulerBase} convenience API.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh MinimalScheduler
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "minimal_scheduler")
@Property(name = "timeout_ms", value = "10000")
public abstract class MinimalScheduler extends SchedulerBase implements Scheduler {

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        dsqInsert(p, enq_flags);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(MinimalScheduler.class)) {
            program.runSchedulerLoop();
        }
    }
}
