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
 * A minimal FIFO scheduler using {@link SchedulerBase}.
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

    // SchedulerBase.init() already calls scx_bpf_create_dsq(SHARED_DSQ_ID, -1)
    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(MinimalScheduler.class)) {
            program.runSchedulerLoop();
        }
    }
}
