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
 * A simple scheduler that doesn't preempt tasks.
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
            program.attachScheduler();
            program.waitWhileSchedulerIsAttachedProperly();
        }
    }
}
