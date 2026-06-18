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
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_select_cpu_dfl;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_task_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A simplified Java reimplementation of the SMT-pair scheduling concept behind
 * {@code scx_pair}.
 *
 * <h2>Security motivation</h2>
 * Simultaneous Multi-Threading (SMT / Hyper-Threading) exposes a side-channel:
 * two hardware threads sharing a physical core also share execution units,
 * caches, and branch-predictor state.  An adversarial thread on one HT sibling
 * can observe microarchitectural state left behind by the other
 * (Spectre-v1/v2, MDS, L1TF, …).
 *
 * <p>A <em>pair scheduler</em> closes this channel by ensuring that both HT
 * siblings of the same physical core always run threads belonging to the
 * <strong>same process</strong>.  Two threads from different, mutually
 * untrusting processes are never co-scheduled on the same core.
 *
 * <h2>Algorithm (TGID-affinity model)</h2>
 * The original {@code scx_pair.bpf.c} pairs threads by Linux <em>cgroup</em>
 * and uses {@code bpf_spin_lock} inside map values — features not yet exposed
 * in the Java framework.  This implementation achieves the same security
 * property using TGID (thread-group / process ID) affinity:
 *
 * <ol>
 *   <li>Each logical CPU is paired with one sibling: {@code sibling[cpu] =
 *       (cpu + stride) % nr_cpus}.  The default stride is {@code nr_cpus / 2},
 *       which on a typical system matches the HT siblings reported by the
 *       kernel.</li>
 *   <li>A {@code BPFArray<Integer>} of size {@code MAX_CPUS} tracks which TGID
 *       is currently running on each CPU (0 = idle).</li>
 *   <li>In {@code selectCPU}: if the sibling of {@code prev_cpu} is idle
 *       (owner == 0) <em>or</em> already running a thread of the same process
 *       (owner == p.tgid), prefer that CPU neighbourhood.  Otherwise fall back
 *       to kernel-default selection.</li>
 *   <li>{@code running()} / {@code stopping()} maintain the owner table.</li>
 * </ol>
 *
 * <p>This is a <em>best-effort</em> implementation: it steers tasks toward
 * compatible pairs but does not block dispatch when no compatible CPU is
 * available.  A strict version would require per-pair synchronisation
 * (spinlock or atomic) which is not yet supported in the Java BPF framework.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh SMTPairScheduler
 * </pre>
 *
 * <p>Inspired by
 * <a href="https://github.com/torvalds/linux/blob/f0262b102c7ce43f3744bdb0278ddf0d15bb1a71/tools/sched_ext/scx_pair.bpf.c">
 * {@code tools/sched_ext/scx_pair.bpf.c}</a> from the Linux kernel.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "smt_pair_scheduler")
public abstract class SMTPairScheduler extends BPFProgram implements Scheduler {

    static final long SHARED_DSQ_ID = 0;

    /** Maximum number of CPUs this scheduler handles. */
    static final int MAX_CPUS = 512;

    /** Static loop bound for CPU scan — must be a compile-time constant for the BPF verifier. */
    static final int MAX_SCAN_CPUS = 64;

    /**
     * Pairing stride: CPU {@code c} is paired with CPU {@code (c + stride) % nr_cpus}.
     * Default is {@code nr_cpus / 2}, matching typical HT-sibling layout.
     * Set from Java before attaching.
     */
    final GlobalVariable<Integer> stride = new GlobalVariable<>(1);

    /** Total number of logical CPUs; set from Java before attaching. */
    final GlobalVariable<Integer> nrCpus = new GlobalVariable<>(2);

    /**
     * Per-CPU owner table: {@code cpuOwner[cpu]} holds the TGID of the task
     * currently running on that CPU, or 0 if idle.
     */
    @BPFMapDefinition(maxEntries = MAX_CPUS)
    BPFArray<Integer> cpuOwner;

    // scx_bpf_create_dsq(SHARED_DSQ_ID, -1) is lifted into init() by the compiler plugin.
    final DispatchQueue shared = new DispatchQueue(SHARED_DSQ_ID);

    @Override
    public int init() {
        // scx_bpf_create_dsq(SHARED_DSQ_ID, -1) is injected before this line
        // by the compiler plugin (from the DispatchQueue field initializer above).
        return 0;
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        int tgid  = p.val().tgid;
        @Unsigned int ncpus = nrCpus.get();
        @Unsigned int str   = stride.get();

        // Guard: ncpus must be ≥ 1 for modulo to be safe (BPF verifier requires provable non-zero divisor)
        if (ncpus == 0) {
            boolean is_idle = false;
            return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        }

        // Compute the sibling of prev_cpu
        @Unsigned int sibling = (prev_cpu + str) % ncpus;

        // Check what TGID the sibling is currently running
        Ptr<Integer> sibOwnerPtr = cpuOwner.bpf_get(sibling);
        int sibOwner = 0;
        if (sibOwnerPtr != null) {
            sibOwner = sibOwnerPtr.val();
        }

        if (sibOwner == 0 || sibOwner == tgid) {
            // Sibling is idle or already running our process — safe to co-schedule.
            boolean is_idle = false;
            int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
            if (is_idle) {
                shared.insert(p, SCX_SLICE_DFL.value(), EnqFlags.empty());
            }
            return cpu;
        }

        // Sibling is running a different process.  Search for a CPU whose sibling
        // is idle or running the same TGID.
        // @BoundedBy(MAX_SCAN_CPUS) gives the verifier a compile-time iteration bound
        // while we keep the natural `cpu < ncpus` condition for early exit.
        int best = prev_cpu;
        for (@BoundedBy(MAX_SCAN_CPUS) @Unsigned int cpu = 0; cpu < ncpus; cpu++) {
            @Unsigned int sib = (cpu + str) % ncpus;
            Ptr<Integer> ownerPtr = cpuOwner.bpf_get(sib);
            int owner = 0;
            if (ownerPtr != null) {
                owner = ownerPtr.val();
            }
            if (owner == 0 || owner == tgid) {
                best = cpu;
                break;
            }
        }

        // best-effort: steer toward a compatible CPU
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, best, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            shared.insert(p, SCX_SLICE_DFL.value(), EnqFlags.empty());
        }
        return cpu;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insert(p, SCX_SLICE_DFL.value(), EnqFlags.passThrough(enq_flags));
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();
    }

    @Override
    public void running(Ptr<task_struct> p) {
        int cpu = scx_bpf_task_cpu(p);
        cpuOwner.bpf_put(cpu, p.val().tgid);
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        int cpu = scx_bpf_task_cpu(p);
        cpuOwner.bpf_put(cpu, 0);

        // Kick the sibling so it can re-evaluate its pair compatibility.
        @Unsigned int str2 = stride.get();
        @Unsigned int ncpus2 = nrCpus.get();
        if (ncpus2 > 0) {
            @Unsigned int sibling = (cpu + str2) % ncpus2;
            DispatchQueue.kickCpu(sibling, KickFlags.preempt());
        }
    }

    // -----------------------------------------------------------------------
    // Java-side API
    // -----------------------------------------------------------------------

    /**
     * Configures the pairing stride and total CPU count before attaching.
     *
     * @param totalCpus total logical CPUs on the system
     * @param pairStride distance between paired CPUs (default {@code totalCpus / 2})
     */
    public void configure(int totalCpus, int pairStride) {
        nrCpus.set(totalCpus);
        stride.set(pairStride);
    }

    /** Returns the TGID currently running on {@code cpu}, or 0 if idle. */
    public int getCpuOwner(int cpu) {
        return cpuOwner.get(cpu);
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(SMTPairScheduler.class)) {
            int ncpus = Runtime.getRuntime().availableProcessors();
            prog.configure(ncpus, ncpus / 2);
            prog.runSchedulerLoop();
        }
    }
}
