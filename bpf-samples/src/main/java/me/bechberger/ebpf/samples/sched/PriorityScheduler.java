// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A Java reimplementation of the core concept from {@code scx_qmap}.
 *
 * <p>Tasks are mapped to one of five dispatch queues (DSQ IDs 0–4) based on
 * their scheduling weight.  Higher-weight tasks land in higher-numbered queues.
 * Dispatch is greedy: the highest-priority non-empty queue is drained first,
 * ensuring that high-priority tasks are never starved by lower-priority ones.
 *
 * <p>Weight-to-queue mapping (mirrors {@code scx_qmap}):
 * <pre>
 *   weight ≤ 25  → queue 0 (lowest)
 *   weight ≤ 50  → queue 1
 *   weight ≤ 75  → queue 2
 *   weight ≤ 100 → queue 3  (normal nice-0 weight)
 *   weight  > 100 → queue 4 (highest)
 * </pre>
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh PriorityScheduler
 * </pre>
 *
 * <p>Based on
 * <a href="https://github.com/torvalds/linux/blob/master/tools/sched_ext/scx_qmap.bpf.c">
 * {@code tools/sched_ext/scx_qmap.bpf.c}</a> from the Linux kernel.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "priority_scheduler")
public abstract class PriorityScheduler extends BPFProgram implements Scheduler {

    static final int NUM_QUEUES = 5;

    /** Maps a task's {@code scx.weight} to a queue index in [0, NUM_QUEUES). */
    @BPFFunction
    int weightToQueue(@Unsigned int weight) {
        if (weight <= 25) return 0;
        if (weight <= 50) return 1;
        if (weight <= 75) return 2;
        if (weight <= 100) return 3;
        return 4;
    }

    @Override
    public int init() {
        for (int i = 0; i < NUM_QUEUES; i++) {
            int ret = scx_bpf_create_dsq(i, -1);
            if (ret < 0) {
                return ret;
            }
        }
        return 0;
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            int q = weightToQueue(p.val().scx.weight);
            scx_bpf_dsq_insert(p, q, SCX_SLICE_DFL.value(), 0);
        }
        return cpu;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        int q = weightToQueue(p.val().scx.weight);
        scx_bpf_dsq_insert(p, q, SCX_SLICE_DFL.value(), enq_flags);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        // Greedy: drain the highest-priority non-empty queue first.
        for (int q = NUM_QUEUES - 1; q >= 0; q--) {
            if (scx_bpf_dsq_nr_queued(q) > 0) {
                scx_bpf_dsq_move_to_local(q);
                return;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(PriorityScheduler.class)) {
            prog.runSchedulerLoop();
        }
    }
}
