// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.runtime.runtime.cpumask;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A Java reimplementation of the concept behind {@code scx_prev}.
 *
 * <p>Maximises CPU cache warmth by preferring to reuse a task's previous CPU.
 * The scheduler tries three fallback levels in order:
 * <ol>
 *   <li>If the previous CPU is idle, dispatch there directly (cache-warm path).</li>
 *   <li>Otherwise, search the idle cpumask for any idle CPU and dispatch there.</li>
 *   <li>If no idle CPU exists, insert into the global DSQ for whoever picks up work.</li>
 * </ol>
 *
 * <p>This mirrors the heuristic in {@code scx_prev.bpf.c}:
 * try prev → try any idle → fall to SCX_DSQ_GLOBAL.
 * No {@code dispatch()} override is needed because tasks inserted into
 * {@code SCX_DSQ_GLOBAL} are automatically moved to local queues by the kernel.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh PrevCpuScheduler
 * </pre>
 *
 * <p>Based on
 * <a href="https://github.com/sched-ext/scx/blob/d1810e6216c49f6c7bb52aaead1877d3176fa943/scheds/c/scx_prev.bpf.c">
 * {@code scx_prev.bpf.c}</a> from the scx-c-examples repository.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "prev_cpu_scheduler")
public abstract class PrevCpuScheduler extends BPFProgram implements Scheduler {

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        // Fast path: previous CPU is still idle — dispatch directly there.
        if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
            DispatchQueue.localOn(prev_cpu).insert(p, SCX_SLICE_DFL.value(), EnqFlags.empty());
            return prev_cpu;
        }

        // Second chance: pick any idle CPU from the possible-CPU mask.
        // Use the raw pointer directly so the single acquire is passed to both
        // scx_bpf_pick_idle_cpu and scx_bpf_put_cpumask — avoiding a double-acquire
        // that would trip the BPF verifier's reference-leak check.
        Ptr<cpumask> possible = scx_bpf_get_possible_cpumask();
        int cpu = scx_bpf_pick_idle_cpu(possible, 0);
        scx_bpf_put_cpumask(possible);
        if (cpu >= 0) {
            DispatchQueue.localOn(cpu).insert(p, SCX_SLICE_DFL.value(), EnqFlags.empty());
            return cpu;
        }

        // No idle CPU: fall through to enqueue() which inserts into SCX_DSQ_GLOBAL.
        return prev_cpu;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        // Tasks that reached here did not get a direct local-queue dispatch in
        // selectCPU; insert them into the global DSQ for any free CPU to pick up.
        DispatchQueue.global().insert(p, SCX_SLICE_DFL.value(), EnqFlags.passThrough(enq_flags));
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(PrevCpuScheduler.class)) {
            prog.runSchedulerLoop();
        }
    }
}
