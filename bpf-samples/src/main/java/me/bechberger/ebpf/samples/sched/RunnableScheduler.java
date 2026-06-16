// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Exercises Items 1 (configurable {@code sched_ops.flags} via {@code @Property("extra_flags")})
 * and 2 (the {@code runnable()} sched_ops callback) of the recent framework feature campaign.
 *
 * <p>FIFO scheduler that increments a {@link GlobalVariable} every time the kernel calls
 * {@link #runnable(Ptr, long)}. The scheduler also opts into
 * {@code SCX_OPS_ENQ_MIGRATION_DISABLED} via the {@code extra_flags} property to verify the
 * macro substitution path.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh RunnableScheduler
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "runnable_scheduler")
@Property(name = "extra_flags", value = "SCX_OPS_ENQ_MIGRATION_DISABLED")
public abstract class RunnableScheduler extends SchedulerBase implements Scheduler {

    final GlobalVariable<@Unsigned Long> runnableCalls = new GlobalVariable<>(0L);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        dsqInsert(p, enq_flags);
    }

    @Override
    public void runnable(Ptr<task_struct> p, @Unsigned long enq_flags) {
        runnableCalls.set(runnableCalls.get() + 1);
    }

    public long getRunnableCalls() {
        return runnableCalls.get();
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(RunnableScheduler.class)) {
            prog.runSchedulerLoop();
        }
    }
}
