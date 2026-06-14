// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A minimal FIFO scheduler using {@link SchedulerBase}.
 *
 * <p>Only {@link #enqueue} needs to be implemented — {@link SchedulerBase}
 * provides {@link #init()}, {@link #dispatch}, and {@link #dsqInsert}.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "minimal_scheduler")
@Property(name = "timeout_ms", value = "10000")
public abstract class MinimalScheduler extends SchedulerBase {

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        dsqInsert(p, enq_flags);
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(MinimalScheduler.class)) {
            program.attachScheduler();
            System.in.read();
        }
    }
}
