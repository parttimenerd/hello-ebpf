// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * FIFO scheduler demonstrating two framework features: configurable {@code sched_ext_ops.flags}
 * via {@code @Property("extra_flags")}, and the {@link #runnable(Ptr, long)} callback for
 * per-task wakeup tracking.
 *
 * <p>Opts into {@code SCX_OPS_ENQ_MIGRATION_DISABLED} via {@code extra_flags}.
 * Increments a {@link GlobalVariable} counter on every {@link #runnable} call;
 * readable from Java via {@link #getRunnableCalls()}.
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

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
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
