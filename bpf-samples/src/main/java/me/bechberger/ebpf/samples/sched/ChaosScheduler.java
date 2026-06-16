// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.map.BPFTaskStorage;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A concurrency-fuzzing chaos scheduler that stress-tests concurrent Java programs
 * by introducing controlled scheduling perturbations.
 *
 * <p>Merges ideas from
 * <a href="https://github.com/parttimenerd/concurrency-fuzz-scheduler">concurrency-fuzz-scheduler</a>
 * and
 * <a href="https://github.com/sched-ext/scx/blob/29ae42129a78f76a2bdda1827f7d246f773a5c4f/scheds/rust/scx_chaos/src/bpf/main.bpf.c">
 * {@code scx_chaos/main.bpf.c}</a> from the sched-ext scheduler collection.
 *
 * <h2>Chaos traits</h2>
 * <ol>
 *   <li><b>Random vtime delays</b> — targeted tasks are placed in a vtime-ordered DSQ with a
 *       random delay up to {@code maxDelayNs}. A higher random vtime means the task waits longer
 *       before being dispatched, simulating non-deterministic scheduling.
 *   <li><b>CPU frequency throttling</b> — all CPUs are randomly throttled to a fraction of
 *       their maximum performance on each tick, varying the execution speed of every task.
 *   <li><b>Slice degradation</b> — targeted tasks receive a smaller time slice (down to
 *       {@code minSliceFraction} of the default), forcing more frequent context switches.
 *   <li><b>Per-task SLEEP/RUN state machine</b> — each targeted task carries a tiny state
 *       struct (via {@link BPFTaskStorage}) that records how many times it has been woken up.
 *       Tasks that have been woken up only once get a much smaller slice (cold-start penalty),
 *       encouraging interleaving with newly woken threads.
 * </ol>
 *
 * <h2>Targeting</h2>
 * By default the scheduler applies chaos to all non-kthread tasks.  When
 * {@code targetTgid} is set (non-zero), only tasks belonging to that process
 * tree are perturbed; all other tasks fall through to a fair FIFO queue.
 *
 * <h2>Usage</h2>
 * <pre>
 *   sudo ./run.sh ChaosScheduler [targetPid]
 * </pre>
 *
 * <p>Pass an optional PID to restrict chaos to that process's subtree.
 * Omit it to chaos all user tasks on the system.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "chaos_scheduler")
public abstract class ChaosScheduler extends SchedulerBase implements Scheduler {

    // -------------------------------------------------------------------------
    // Tuning knobs (written from Java before attach, read-only in BPF)
    // -------------------------------------------------------------------------

    /** Target process TGID. 0 = apply chaos to all non-kthread tasks. */
    final GlobalVariable<Integer> targetTgid = new GlobalVariable<>(0);

    /**
     * Maximum random vtime delay added to targeted tasks (nanoseconds).
     * Default: 5 ms. Set to 0 to disable vtime delay chaos.
     */
    final GlobalVariable<@Unsigned Long> maxDelayNs = new GlobalVariable<>(5_000_000L);

    /**
     * CPU performance throttle level [0..1024] applied to CPUs on each tick.
     * 1024 = full speed, 0 = minimum speed. Default: 512 (50%).
     * Set to 1024 to disable throttling.
     */
    final GlobalVariable<@Unsigned Integer> cpuPerfTarget = new GlobalVariable<>(512);

    /**
     * Denominator for slice degradation: targeted tasks get
     * {@code SCX_SLICE_DFL / sliceDivisor} ns. Default: 4 (25% of default slice).
     */
    final GlobalVariable<Integer> sliceDivisor = new GlobalVariable<>(4);

    // -------------------------------------------------------------------------
    // Per-task storage
    // -------------------------------------------------------------------------

    @Type
    static class TaskState {
        /** Number of times this task has been made runnable since last sleep. */
        @Unsigned long wakeups;
    }

    @BPFMapDefinition(maxEntries = 1)
    BPFTaskStorage<TaskState> taskState;

    // -------------------------------------------------------------------------
    // BPF-side helpers
    // -------------------------------------------------------------------------

    /** Returns {@code true} if chaos should be applied to task {@code p}. */
    @BPFFunction
    boolean isChaosTarget(Ptr<task_struct> p) {
        // Skip kernel threads and constrained tasks
        if (hasSchedulingConstraints(p)) {
            return false;
        }
        int tgid = targetTgid.get();
        if (tgid == 0) {
            return true;
        }
        return isDescendantOf(p, tgid);
    }

    // -------------------------------------------------------------------------
    // SCX callbacks
    // -------------------------------------------------------------------------

    @Override
    public int init() {
        int ret = scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        if (ret != 0) return ret;
        // Create a separate vtime DSQ for delayed tasks (ID 1)
        return scx_bpf_create_dsq(1L, -1);
    }

    @Override
    public void runnable(Ptr<task_struct> p, @Unsigned long enq_flags) {
        Ptr<TaskState> state = taskState.bpf_getOrCreate(p);
        if (state != null) {
            state.val().wakeups++;
        }
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        if (!isChaosTarget(p)) {
            scx_bpf_dsq_insert(p, SHARED_DSQ_ID, SCX_SLICE_DFL.value(), enq_flags);
            return;
        }

        // --- Trait 3: slice degradation ---
        int divisor = sliceDivisor.get();
        if (divisor <= 0) divisor = 1;
        long slice = SCX_SLICE_DFL.value() / divisor;
        if (slice < 100_000L) slice = 100_000L;  // floor: 100 µs

        // --- Per-task state: cold-start penalty ---
        Ptr<TaskState> state = taskState.bpf_getOrCreate(p);
        if (state != null && state.val().wakeups == 1) {
            // First wakeup after being created/woken: shrink slice further
            slice = slice / 4;
            if (slice < 100_000L) slice = 100_000L;
        }

        // --- Trait 1: random vtime delay ---
        @Unsigned long delay = maxDelayNs.get();
        if (delay > 0) {
            @Unsigned long randomDelay = BPFJ.bpfRandBounded(delay);
            @Unsigned long vtime = p.val().scx.dsq_vtime + randomDelay;
            scx_bpf_dsq_insert_vtime(p, 1L, slice, vtime, enq_flags);
        } else {
            scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, enq_flags);
        }
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        // Drain the vtime chaos DSQ first (delayed tasks), then FIFO fallback
        if (!scx_bpf_dsq_move_to_local(1L)) {
            scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
        }
    }

    @Override
    public void running(Ptr<task_struct> p) {
        // Advance the shared vtime reference so that the vtime-delay window
        // is always relative to the current point in time (mirrors VTimeScheduler).
        @Unsigned long vtime = p.val().scx.dsq_vtime;
        // No CAS needed: small drift is acceptable for chaos fuzzing
        p.val().scx.dsq_vtime = vtime;
    }

    @Override
    public void enable(Ptr<task_struct> p) {
        // Intentionally start at vtime=0, not vtimeNow: chaos tasks begin at the
        // front of the vtime window so the random delay in enqueue() is the only
        // thing that separates them — no inherited lag from global vtime drift.
        p.val().scx.dsq_vtime = 0;
    }

    /** Trait 2: randomise CPU performance on each scheduling tick. */
    @Override
    public void tick(Ptr<task_struct> p) {
        @Unsigned int perfTarget = cpuPerfTarget.get();
        if (perfTarget < 1024) {
            // Add ±25% jitter around the target to vary frequency continuously
            @Unsigned int jitter = BPFJ.bpfRandBounded(perfTarget / 2L + 1L);
            @Unsigned int perf = perfTarget - perfTarget / 4 + jitter;
            if (perf > 1024) perf = 1024;
            scx_bpf_cpuperf_set(scx_bpf_task_cpu(p), perf);
        }
    }

    // -------------------------------------------------------------------------
    // Java-side orchestration
    // -------------------------------------------------------------------------

    /**
     * Run the chaos scheduler, optionally targeting a specific process.
     *
     * <pre>
     *   sudo ./run.sh ChaosScheduler              # chaos all user tasks
     *   sudo ./run.sh ChaosScheduler 12345        # chaos PID 12345 and descendants
     *   sudo ./run.sh ChaosScheduler 12345 512    # also set cpuPerfTarget (0..1024)
     * </pre>
     */
    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(ChaosScheduler.class)) {
            if (args.length >= 1) {
                int pid = Integer.parseInt(args[0]);
                prog.targetTgid.set(pid);
                System.out.println("Targeting PID subtree: " + pid);
            } else {
                System.out.println("Targeting all user tasks (no PID filter)");
            }

            if (args.length >= 2) {
                int perf = Integer.parseInt(args[1]);
                prog.cpuPerfTarget.set(perf);
                System.out.println("CPU perf target: " + perf + " / 1024");
            }

            System.out.println("Attaching chaos scheduler — press Enter to stop.");
            prog.runSchedulerLoop();
        }
    }
}
