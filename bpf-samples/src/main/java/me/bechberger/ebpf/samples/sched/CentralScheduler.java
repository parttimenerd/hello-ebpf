// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A Java reimplementation of the core concept from {@code scx_central}.
 *
 * <p>One designated CPU (CPU 0 by default) acts as the <em>central</em> dispatcher.
 * All user-space task wakeups are funnelled to it via {@code selectCPU()}.  The
 * central CPU drains a shared DSQ on every dispatch cycle; non-central CPUs signal
 * the central CPU via {@code scx_bpf_kick_cpu()} when they need work.
 *
 * <p>Periodic preemption is handled by the {@code tick()} hook (fires every 1/HZ
 * seconds) rather than a {@code bpf_timer}, keeping the Java implementation free of
 * raw-C workarounds.  Kernel threads are fast-pathed directly to the local queue so
 * they are never starved.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh CentralScheduler
 * </pre>
 *
 * <p>Based on
 * <a href="https://github.com/torvalds/linux/blob/d6edb15ad92cb61386c46662a5ae245c7feac5f0/tools/sched_ext/scx_central.bpf.c">
 * {@code tools/sched_ext/scx_central.bpf.c}</a> from the Linux kernel.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "central_scheduler")
public abstract class CentralScheduler extends BPFProgram implements Scheduler {

    static final long CENTRAL_DSQ_ID = 0;

    /**
     * The CPU that makes all scheduling decisions.  Defaults to 0.
     * Can be changed before attaching by setting this field from Java.
     */
    final GlobalVariable<Integer> centralCpu = new GlobalVariable<>(0);

    @Override
    public int init() {
        return scx_bpf_create_dsq(CENTRAL_DSQ_ID, -1);
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        // Funnel all wakeup hints to the central CPU so it can observe all
        // runnable tasks.  The actual enqueue decision is made in enqueue().
        return centralCpu.get();
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        if ((p.val().flags & PerProcessFlags.PF_KTHREAD) != 0) {
            // Kernel threads get dispatched directly to the local queue so
            // they are never delayed by the central dispatch round-trip.
            scx_bpf_dsq_insert(p, scx_dsq_id_flags.SCX_DSQ_LOCAL.value(),
                    SCX_SLICE_DFL.value(), enq_flags);
        } else {
            scx_bpf_dsq_insert(p, CENTRAL_DSQ_ID, SCX_SLICE_DFL.value(), enq_flags);
        }
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        if (cpu == centralCpu.get()) {
            // Central CPU: drain the shared queue into the local queue.
            scx_bpf_dsq_move_to_local(CENTRAL_DSQ_ID);
        } else {
            // Non-central CPU: wake the central CPU so it dispatches a task for us.
            scx_bpf_kick_cpu(centralCpu.get(), 0);
        }
    }

    @Override
    public void tick(Ptr<task_struct> p) {
        // Preempt tasks that have consumed their time slice by setting slice to 0.
        // The kernel triggers an immediate dispatch cycle when slice reaches 0.
        if (p.val().scx.slice == 0) {
            p.val().scx.slice = SCX_SLICE_DFL.value();
        }
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(CentralScheduler.class)) {
            prog.runSchedulerLoop();
        }
    }
}
