// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

@BPF(license = "GPL")
@Property(name = "sched_name", value = "minimal_scheduler")
public abstract class MinimalScheduler extends BPFProgram implements Scheduler {

    private static final int SHARED_DSQ_ID = 0;

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        scx_bpf_dispatch(p, SHARED_DSQ_ID,  5_000_000 /
                scx_bpf_dsq_nr_queued(SHARED_DSQ_ID), enq_flags);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_consume(SHARED_DSQ_ID);
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(MinimalScheduler.class)) {
            program.attachScheduler();
            System.in.read();
        }
    }
}
