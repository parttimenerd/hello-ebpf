// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.PerCpuSchedulerBase;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Minimal demonstration of {@link PerCpuSchedulerBase}.
 *
 * <p>Non-migratable tasks (pinned to a single CPU via affinity or
 * {@code migration_disabled}) are inserted directly into the per-CPU DSQ
 * via {@link #dsqInsertLocal}.  All other tasks go into the shared FIFO DSQ
 * and can be dispatched to any CPU.
 *
 * <p>{@link PerCpuSchedulerBase} creates one DSQ per logical CPU
 * (IDs {@code PER_CPU_DSQ_BASE + cpu}) plus the shared fallback DSQ at
 * {@code SHARED_DSQ_ID = 0}.  {@link #dispatch} drains the per-CPU DSQ
 * first, then falls back to the shared DSQ.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh PerCpuSchedulerSample
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "per_cpu_scheduler_sample")
@Property(name = "timeout_ms", value = "10000")
public abstract class PerCpuSchedulerSample extends PerCpuSchedulerBase implements Scheduler {

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        if (isMigrationDisabled(p)) {
            dsqInsertLocal(p, enq_flags);
        } else {
            dsqInsert(p, enq_flags);
        }
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(PerCpuSchedulerSample.class)) {
            program.runSchedulerLoop();
        }
    }
}
