// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;

/**
 * Minimal scheduler that exercises {@code p.directVal().cpus_ptr} in a
 * non-sleepable {@code struct_ops} handler ({@code enqueue}). The kernel
 * verifier accepts the load only because {@code directVal()} suppresses
 * CO-RE lifting on {@code cpus_ptr}, preserving the trusted-pointer
 * annotation that {@code bpf_cpumask_test_cpu} requires.
 *
 * <p>If {@code directVal()} regresses to {@code BPF_CORE_READ(p, cpus_ptr)},
 * the verifier rejects the load with a trusted-pointer error and the test
 * fails.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "directval_taskcpu_test")
@Property(name = "timeout_ms", value = "10000")
public abstract class DirectValTaskCpuAllowedScheduler extends SchedulerBase implements Scheduler {

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        if (bpf_cpumask_test_cpu(0, p.directVal().cpus_ptr)) {
            shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
        } else {
            shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
        }
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();
    }
}
