// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.BoundedBy;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.bpf.sched.KickFlags;
import me.bechberger.ebpf.runtime.runtime.cpumask;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A cache-topology-aware "nest" scheduler.
 *
 * <h2>Concept</h2>
 * Cache affinity matters: a task that repeatedly runs on the same physical core
 * (or at least the same LLC domain) finds its working set warm in L1/L2.  A
 * <em>nest scheduler</em> designates a subset of CPUs as the <em>primary nest</em>
 * and tries to keep all runnable tasks within those cores.  Tasks only spill to
 * <em>secondary</em> CPUs when every nest core is busy, and are pulled back as
 * soon as a nest core becomes idle.
 *
 * <h2>Algorithm</h2>
 * <ol>
 *   <li>CPUs {@code 0 .. nestSize-1} form the primary nest; the remainder are
 *       secondary.  The nest size is configurable from Java before attaching
 *       (default: {@code nrCpus / 2}).</li>
 *   <li>{@code selectCPU}: scan the idle cpumask for any CPU numbered below
 *       {@code nestSize}.  If one is found, dispatch directly to its local queue
 *       ({@code SCX_DSQ_LOCAL_ON | nestCpu}) for a zero-overhead fast path.
 *       Otherwise fall back to {@code scx_bpf_select_cpu_dfl}.</li>
 *   <li>{@code enqueue}: insert into the shared global DSQ (FIFO).</li>
 *   <li>{@code dispatch}: drain the shared DSQ to the local queue.  When a
 *       <em>secondary</em> CPU is dispatching and a nest CPU is idle, kick that
 *       nest CPU ({@code SCX_KICK_IDLE}) so it wakes up and can pull work.</li>
 *   <li>{@code tick}: if the current CPU is secondary and any nest CPU is idle,
 *       set the task's remaining slice to 0 — forcing an immediate re-dispatch
 *       so {@code selectCPU} gets another chance to land the task in the nest.</li>
 * </ol>
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh NestScheduler
 * </pre>
 *
 * <p>This scheduler is an original Java/sched_ext design inspired by the
 * cache-affinity concepts described in
 * <a href="https://www.usenix.org/conference/osdi18/presentation/ousterhout">
 * Shenango (OSDI '18)</a> and the nest-aware scheduling approach in
 * <a href="https://github.com/sched-ext/scx/blob/d1810e6216c49f6c7bb52aaead1877d3176fa943/scheds/c/scx_nest.bpf.c">
 * {@code scx_nest.bpf.c}</a> from the sched-ext scheduler collection.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "nest_scheduler")
public abstract class NestScheduler extends BPFProgram implements Scheduler {

    static final long SHARED_DSQ_ID = 0;

    /** Maximum number of CPUs supported. */
    static final int MAX_CPUS = 512;

    // scx_bpf_create_dsq(SHARED_DSQ_ID, -1) is lifted into init() by the compiler plugin.
    final DispatchQueue shared = new DispatchQueue(SHARED_DSQ_ID);

    /**
     * Number of CPUs in the primary nest (CPUs 0..nestSize-1).
     * Set from Java before attaching.
     */
    final GlobalVariable<Integer> nestSize = new GlobalVariable<>(1);

    /** Total logical CPUs; set from Java before attaching. */
    final GlobalVariable<Integer> nrCpus = new GlobalVariable<>(2);

    /**
     * Per-CPU nest membership flag: {@code inNest[cpu]} is 1 for nest CPUs, 0 for secondary.
     * Populated from Java before attaching via {@link #configure}.
     */
    @BPFMapDefinition(maxEntries = MAX_CPUS)
    BPFArray<Integer> inNest;

    @Override
    public int init() {
        // scx_bpf_create_dsq(SHARED_DSQ_ID, -1) is injected before this line
        // by the compiler plugin (from the DispatchQueue field initializer above).
        return 0;
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        // Fast path: find an idle nest CPU and dispatch directly to its local queue.
        Ptr<cpumask> idle = scx_bpf_get_idle_cpumask();
        int nestCpu = findIdleNestCpu(idle);
        scx_bpf_put_idle_cpumask(idle);

        if (nestCpu >= 0) {
            DispatchQueue.localOn(nestCpu).insert(p, SCX_SLICE_DFL.value(), EnqFlags.empty());
            return nestCpu;
        }

        // No idle nest CPU — fall back to kernel default (may land on secondary).
        boolean is_idle = false;
        return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insert(p, SCX_SLICE_DFL.value(), EnqFlags.passThrough(enq_flags));
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();

        // Secondary CPUs: wake an idle nest CPU so it can steal the work we just dispatched.
        Ptr<Integer> nestFlag = inNest.bpf_get(cpu);
        if (nestFlag != null && nestFlag.val() == 0) {
            Ptr<cpumask> idle = scx_bpf_get_idle_cpumask();
            int nestCpu = findIdleNestCpu(idle);
            scx_bpf_put_idle_cpumask(idle);
            if (nestCpu >= 0) {
                DispatchQueue.kickCpu(nestCpu, KickFlags.idle());
            }
        }
    }

    @Override
    public void tick(Ptr<task_struct> p) {
        // Secondary CPU: if any nest CPU is idle, force a reschedule so the task
        // gets another chance to migrate into the nest via selectCPU.
        int cpu = scx_bpf_task_cpu(p);
        Ptr<Integer> nestFlag = inNest.bpf_get(cpu);
        if (nestFlag != null && nestFlag.val() == 0) {
            Ptr<cpumask> idle = scx_bpf_get_idle_cpumask();
            int nestCpu = findIdleNestCpu(idle);
            scx_bpf_put_idle_cpumask(idle);
            if (nestCpu >= 0) {
                DispatchQueue.yieldNow(p);
            }
        }
    }

    /**
     * Scans the idle cpumask for the first CPU whose index is within the nest
     * (i.e. {@code < nestSize}).  Returns -1 if no idle nest CPU is found.
     *
     * <p>{@code @BoundedBy(64)} declares a verifier-friendly compile-time upper bound;
     * the natural {@code cpu < ns} condition is preserved as the early-exit check.
     */
    @BPFFunction
    int findIdleNestCpu(Ptr<cpumask> idle) {
        @Unsigned int ns = nestSize.get();
        for (@BoundedBy(64) @Unsigned int cpu = 0; cpu < ns; cpu++) {
            if (bpf_cpumask_test_cpu(cpu, idle)) {
                return cpu;
            }
        }
        return -1;
    }

    // -----------------------------------------------------------------------
    // Java-side API
    // -----------------------------------------------------------------------

    /**
     * Configures the nest before attaching.
     *
     * @param totalCpus    total logical CPUs on the system
     * @param primaryCount number of CPUs to place in the primary nest (CPUs 0..primaryCount-1)
     */
    public void configure(int totalCpus, int primaryCount) {
        nrCpus.set(totalCpus);
        nestSize.set(primaryCount);
        for (int cpu = 0; cpu < totalCpus; cpu++) {
            inNest.put(cpu, cpu < primaryCount ? 1 : 0);
        }
    }

    /** Returns the configured nest size. */
    public int getNestSize() {
        return nestSize.get();
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(NestScheduler.class)) {
            int ncpus = Runtime.getRuntime().availableProcessors();
            prog.configure(ncpus, Math.max(1, ncpus / 2));
            prog.runSchedulerLoop();
        }
    }
}
