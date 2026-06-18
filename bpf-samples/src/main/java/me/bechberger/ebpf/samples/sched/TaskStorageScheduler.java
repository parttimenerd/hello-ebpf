// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Kptr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.map.BPFTaskStorage;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * FIFO scheduler that maintains a per-task wakeup counter using
 * {@link BPFTaskStorage}.  Demonstrates the new task-storage map class.
 *
 * <p>Each time a task becomes runnable, the {@code runnable()} callback
 * gets-or-creates its task-storage entry (zero-initialized) and increments
 * a 64-bit counter.  The kernel automatically frees the entry when the
 * task exits — no PID-keyed bookkeeping required.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh TaskStorageScheduler
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "task_storage_scheduler")
@Property(name = "timeout_ms", value = "10000")
public abstract class TaskStorageScheduler extends SchedulerBase implements Scheduler {

    @Type
    static class TaskStats {
        @Unsigned long wakeups;
        @Kptr Ptr<bpf_cpumask> mask;
    }

    @BPFMapDefinition(maxEntries = 1)
    BPFTaskStorage<TaskStats> taskStats;

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    @Override
    public void runnable(Ptr<task_struct> p, @Unsigned long enq_flags) {
        Ptr<TaskStats> stats = taskStats.bpf_getOrCreate(p);
        if (stats != null) {
            stats.val().wakeups++;
        }
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(TaskStorageScheduler.class)) {
            program.runSchedulerLoop();
        }
    }
}
