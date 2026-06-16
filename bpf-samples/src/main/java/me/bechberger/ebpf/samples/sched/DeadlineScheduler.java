// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * An Earliest-Deadline-First (EDF) scheduler implemented in Java using sched_ext.
 *
 * <p>At enqueue time each task is assigned a virtual deadline:
 * <pre>
 *   deadline = now + (period_ns / weight)
 * </pre>
 * where {@code period_ns} is a configurable per-task period (default: 10 ms) and
 * {@code weight} is the task's scheduling weight (nice-0 == 100).  Heavier
 * (higher-priority) tasks get shorter deadlines and thus run sooner.
 *
 * <p>Tasks are inserted into a vtime-ordered DSQ using their deadline as the
 * vtime key, so the BPF DSQ dequeues the task with the earliest (smallest)
 * deadline first — exactly EDF ordering.
 *
 * <p>A global clock ({@code scx_bpf_now()}) is used so that sleeping tasks
 * do not accumulate deadline debt.  Their deadline is clamped to
 * {@code now + period_ns} on wakeup to prevent them from monopolising the
 * CPU upon return.
 *
 * <p>This is an original Java/sched_ext EDF implementation.  The EDF concept
 * is described in
 * <a href="https://en.wikipedia.org/wiki/Earliest_deadline_first_scheduling">
 * Earliest deadline first scheduling</a>.  The vtime-ordered DSQ approach is
 * inspired by
 * <a href="https://github.com/torvalds/linux/blob/6712c4fefca0422851b71d1a58a32ea03f69310f/tools/sched_ext/scx_simple.bpf.c">
 * {@code scx_simple.bpf.c}</a> (vtime mode).
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh DeadlineScheduler
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "deadline_scheduler")
public abstract class DeadlineScheduler extends BPFProgram implements Scheduler {

    static final long SHARED_DSQ_ID = 0;

    /** Default task period in nanoseconds (10 ms). */
    static final long DEFAULT_PERIOD_NS = 10_000_000L;

    /**
     * Configurable period used for all tasks (nanoseconds).
     * Can be changed from Java before attaching.
     */
    final GlobalVariable<@Unsigned Long> periodNs = new GlobalVariable<>(DEFAULT_PERIOD_NS);

    /**
     * Per-task deadline (absolute nanosecond timestamp from scx_bpf_now()).
     * Key: task pid, Value: deadline in ns.
     */
    @BPFMapDefinition(maxEntries = 65536)
    BPFHashMap<Integer, @Unsigned Long> deadlines;

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        // All task insertions happen in enqueue() via scx_bpf_dsq_insert_vtime to ensure
        // the vtime-ordered DSQ is not mixed with FIFO insertions.
        boolean is_idle = false;
        return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        @Unsigned long now = scx_bpf_now();
        @Unsigned long period = periodNs.get();
        @Unsigned int weight = p.val().scx.weight;

        // Compute deadline: now + period / weight  (heavier tasks get shorter deadlines)
        @Unsigned long deadline = now + period / weight;

        // Clamp: if stored deadline is in the future but not too far, reuse it
        // (avoids deadline inflation for waking tasks)
        int pid = p.val().pid;
        Ptr<@Unsigned Long> stored = deadlines.bpf_get(pid);
        if (stored != null) {
            @Unsigned long prev_deadline = stored.val();
            // If previous deadline hasn't expired yet and isn't stale (> 1 period old)
            if (isSmaller(now, prev_deadline) && isSmaller(prev_deadline - now, period)) {
                deadline = prev_deadline;
            }
        }
        deadlines.put(pid, deadline);

        scx_bpf_dsq_insert_vtime(p, SHARED_DSQ_ID, SCX_SLICE_DFL.value(), deadline, enq_flags);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    }

    @Override
    public void disable(Ptr<task_struct> p) {
        // Clean up per-task state when task leaves sched_ext
        deadlines.bpf_delete(p.val().pid);
    }

    // Java-side API

    /** Sets the task period used for deadline computation (nanoseconds). */
    public void setPeriodNs(long ns) {
        periodNs.set(ns);
    }

    /** Returns the current task period in nanoseconds. */
    public long getPeriodNs() {
        return periodNs.get();
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(DeadlineScheduler.class)) {
            prog.runSchedulerLoop();
        }
    }
}
