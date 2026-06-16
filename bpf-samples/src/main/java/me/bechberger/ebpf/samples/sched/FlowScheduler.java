// SPDX-License-Identifier: GPL-2.0
/*
 * Java port of scx_flow — a budget-driven, starvation-free tier scheduler.
 *
 * Original C implementation:
 * https://github.com/sched-ext/scx/tree/main/scheds/experimental/scx_flow
 * (no single commit pinned — experimental scheduler, actively developed)
 *
 * Design overview
 * ---------------
 * Each task accumulates a "budget" in nanoseconds, earned by sleeping.
 * On wakeup the budget is refilled: refill = (sleep_ns / 100) * weight,
 * with a floor for interactive tasks that slept >= 750 µs.
 *
 * At enqueue time, tasks are classified into one of four FIFO tier DSQs
 * based on their current budget:
 *
 *   PRIORITY  budget >= 1500 µs  — long-sleeping interactive tasks
 *   NORMAL    budget >= 1000 µs  — typical tasks
 *   LOW       budget >=  500 µs  — modest-budget tasks
 *   DEFICIT   budget <   500 µs  — budget-exhausted bulk workers
 *
 * Non-migratable tasks (nr_cpus_allowed == 1 or migration disabled) bypass
 * the tier system and go directly to a per-CPU pinned DSQ.
 *
 * Dispatch rotates which tier is checked first on every call, so no tier
 * waits more than 3 dispatch cycles before being serviced.
 *
 * On task stop, the runtime is deducted from the budget. When a task yields,
 * its slice is cut to SLICE_MIN_NS but the yield is not honoured (the task
 * stays eligible for re-dispatch immediately).  When a CPU is preempted by
 * RT/deadline, all locally queued tasks are re-enqueued.
 */
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.BoundedBy;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.bpf.map.BPFTaskStorage;
import me.bechberger.ebpf.runtime.ScxDefinitions;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL_ON;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_enq_flags.*;
// SCX_CPUPERF_ONE = 1024 (full CPU performance)
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A budget-driven, starvation-free tier scheduler.
 *
 * <p>Tasks earn CPU budget by sleeping.  At enqueue time, budget determines
 * which of four FIFO priority tiers a task enters.  A rotating dispatch
 * order guarantees that even the lowest-priority tier is served every 4
 * dispatch calls.  Non-migratable tasks bypass the tiers entirely through
 * per-CPU pinned DSQs for lowest latency.
 *
 * <p>Run with:
 * <pre>
 *   sudo ./run.sh FlowScheduler
 * </pre>
 *
 * <p>Based on
 * <a href="https://github.com/sched-ext/scx/tree/main/scheds/experimental/scx_flow">
 * {@code scx_flow}</a> from the sched-ext scheduler collection.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "flow_scheduler")
@Property(name = "timeout_ms", value = "5000")
public abstract class FlowScheduler extends BPFProgram implements Scheduler {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /** Maximum supported CPU count — gives the BPF verifier a compile-time loop bound. */
    static final int MAX_CPUS = 512;

    static final long NSEC_PER_USEC = 1_000L;
    static final long NSEC_PER_MSEC = 1_000_000L;

    /** Minimum time slice: 50 µs */
    static final long SLICE_MIN_NS = 50L * NSEC_PER_USEC;
    /** Default max slice (tunable): 250 µs */
    static final long SLICE_RESERVED_MAX_NS = 250L * NSEC_PER_USEC;
    /** Upper bound for tuneReservedMaxNs: 350 µs */
    static final long SLICE_RESERVED_TUNE_MAX_NS = 350L * NSEC_PER_USEC;

    /** Max budget a task can accumulate: 2 ms */
    static final long BUDGET_MAX_NS = 2L * NSEC_PER_MSEC;
    /** Min budget (negative floor): −500 µs */
    static final long BUDGET_MIN_NS = 500L * NSEC_PER_USEC;
    /** Cap on sleep time counted for budget refill: 250 ms */
    static final long SLEEP_MAX_NS = 250L * NSEC_PER_MSEC;

    /** Sleep threshold for interactive floor guarantee: 750 µs */
    static final long INTERACTIVE_SLEEP_MIN_NS = 750L * NSEC_PER_USEC;
    /** Default interactive refill floor: 100 µs */
    static final long INTERACTIVE_FLOOR_NS = 100L * NSEC_PER_USEC;
    static final long INTERACTIVE_FLOOR_MIN_NS = 80L * NSEC_PER_USEC;
    static final long INTERACTIVE_FLOOR_MAX_NS = 200L * NSEC_PER_USEC;

    /** Divisor for budget refill: refill_base = sleep_ns / 100 */
    static final long REFILL_DIV = 100L;

    /** Per-CPU pinned DSQ base: each CPU gets PINNED_DSQ_BASE + cpu */
    static final long PINNED_DSQ_BASE = 2048L;

    /** Tier DSQ IDs */
    static final long TIER_PRIORITY_DSQ = 3000L;
    static final long TIER_NORMAL_DSQ   = 3001L;
    static final long TIER_LOW_DSQ      = 3002L;
    static final long TIER_DEFICIT_DSQ  = 3003L;

    /** Budget thresholds for tier classification */
    static final long BUDGET_TIER_PRIORITY_NS = 1_500_000L;  // 1500 µs
    static final long BUDGET_TIER_NORMAL_NS   = 1_000_000L;  // 1000 µs
    static final long BUDGET_TIER_LOW_NS      =   500_000L;  //  500 µs

    // -------------------------------------------------------------------------
    // Per-task context (stored in BPFTaskStorage)
    // -------------------------------------------------------------------------

    @Type
    static class TaskCtx {
        long budgetNs;          // signed: negative = deficit
        long lastRefillNs;
        long lastRunAt;
        long lastSleepNs;
        long sleepStartedAt;
        int  lastCpu;
        int  wakeCpu;
        boolean wakeCpuIdle;
        boolean wakeCpuValid;
        boolean firstRun;
    }

    @BPFMapDefinition(maxEntries = 1)
    BPFTaskStorage<TaskCtx> taskCtxStor;

    // -------------------------------------------------------------------------
    // Per-CPU state (aggregated counters)
    // -------------------------------------------------------------------------

    @Type
    static class FlowCpuState {
        @Unsigned long budgetExhaustions;
        @Unsigned long runnableWakeups;
        @Unsigned long cpuMigrations;
    }

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<FlowCpuState> cpuState;

    // -------------------------------------------------------------------------
    // Global counters (visible from Java for monitoring)
    // -------------------------------------------------------------------------

    final GlobalVariable<@Unsigned Long> onCpu             = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> totalRuntime      = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> pinnedDispatches  = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> prioDispatches    = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> tierPriorityDispatches = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> tierNormalDispatches   = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> tierLowDispatches      = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> tierDeficitDispatches  = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> budgetRefillEvents     = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> budgetExhaustions      = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> runnableWakeups        = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> cpuReleaseReenqueues   = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> initTaskEvents         = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> enableEvents           = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> exitTaskEvents         = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> cpuMigrations          = new GlobalVariable<>(0L);

    /** Dispatch phase selector: (dispatchGen & 3) rotates the tier start. */
    final GlobalVariable<@Unsigned Long> dispatchGen = new GlobalVariable<>(0L);

    /** Tunable: max slice per dispatch (default 250 µs, range 50–350 µs). */
    final GlobalVariable<@Unsigned Long> tuneReservedMaxNs = new GlobalVariable<>(SLICE_RESERVED_MAX_NS);

    /** Tunable: min refill for interactive tasks (default 100 µs, range 80–200 µs). */
    final GlobalVariable<@Unsigned Long> tuneInteractiveFloorNs = new GlobalVariable<>(INTERACTIVE_FLOOR_NS);

    // -------------------------------------------------------------------------
    // BPF-side helpers
    // -------------------------------------------------------------------------

    @BPFFunction
    @AlwaysInline
    long clampBudget(long budgetNs) {
        if (budgetNs > BUDGET_MAX_NS) return BUDGET_MAX_NS;
        if (budgetNs < -BUDGET_MIN_NS) return -BUDGET_MIN_NS;
        return budgetNs;
    }

    @BPFFunction
    @AlwaysInline
    long taskSliceNs(Ptr<TaskCtx> tctx) {
        if (tctx != null && tctx.val().budgetNs > 0) {
            long budget = tctx.val().budgetNs;
            long reservedMax = tuneReservedMaxNs.get();
            if (reservedMax < SLICE_MIN_NS) reservedMax = SLICE_MIN_NS;
            else if (reservedMax > SLICE_RESERVED_TUNE_MAX_NS) reservedMax = SLICE_RESERVED_TUNE_MAX_NS;
            if (budget < SLICE_MIN_NS) return SLICE_MIN_NS;
            if (budget > reservedMax) return reservedMax;
            return budget;
        }
        return SLICE_MIN_NS;
    }

    @BPFFunction
    @AlwaysInline
    boolean validSchedCpu(int cpu, long nrCpuIds) {
        return cpu >= 0 && (@Unsigned long) cpu < (@Unsigned long) nrCpuIds;
    }

    @BPFFunction
    @AlwaysInline
    void clearWakeTarget(Ptr<TaskCtx> tctx) {
        if (tctx == null) return;
        tctx.val().wakeCpu = -1;
        tctx.val().wakeCpuIdle = false;
        tctx.val().wakeCpuValid = false;
    }

    @BPFFunction
    @AlwaysInline
    void resetTaskCtx(Ptr<TaskCtx> tctx, long now, boolean sleeping) {
        if (tctx == null) return;
        tctx.val().budgetNs = SLICE_MIN_NS;
        tctx.val().lastRefillNs = 0;
        tctx.val().lastRunAt = 0;
        tctx.val().lastSleepNs = 0;
        tctx.val().sleepStartedAt = sleeping ? now : 0;
        tctx.val().lastCpu = -1;
        tctx.val().firstRun = true;
        clearWakeTarget(tctx);
    }

    @BPFFunction
    long calcBudgetRefill(Ptr<task_struct> p, long sleepNs) {
        if (sleepNs <= 0) return 0;
        if (sleepNs > SLEEP_MAX_NS) sleepNs = SLEEP_MAX_NS;
        long refillBase = sleepNs / REFILL_DIV;
        if (refillBase <= 0) return 0;
        long refillNs = scaleByTaskWeight(p, refillBase);
        if (sleepNs >= INTERACTIVE_SLEEP_MIN_NS) {
            long floor = tuneInteractiveFloorNs.get();
            if (floor < INTERACTIVE_FLOOR_MIN_NS) floor = INTERACTIVE_FLOOR_MIN_NS;
            else if (floor > INTERACTIVE_FLOOR_MAX_NS) floor = INTERACTIVE_FLOOR_MAX_NS;
            if (refillNs < floor) refillNs = floor;
        }
        return refillNs;
    }

    @BPFFunction
    void updateBudgetOnWakeup(Ptr<task_struct> p, Ptr<TaskCtx> tctx, long now) {
        if (tctx == null) return;
        tctx.val().lastRefillNs = 0;
        if (tctx.val().sleepStartedAt == 0 || now <= tctx.val().sleepStartedAt) {
            tctx.val().lastSleepNs = 0;
            return;
        }
        long sleepNs = now - tctx.val().sleepStartedAt;
        long refillNs = calcBudgetRefill(p, sleepNs);
        tctx.val().budgetNs = clampBudget(tctx.val().budgetNs + refillNs);
        tctx.val().lastRefillNs = refillNs;
        tctx.val().lastSleepNs = sleepNs;
        tctx.val().sleepStartedAt = 0;
        if (refillNs > 0) {
            budgetRefillEvents.addAndGet(1L);
        }
    }

    // -------------------------------------------------------------------------
    // SCX ops
    // -------------------------------------------------------------------------

    @Override
    public int init() {
        long nrCpuIds = scx_bpf_nr_cpu_ids();
        for (@BoundedBy(MAX_CPUS) int cpu = 0; (@Unsigned long) cpu < (@Unsigned long) nrCpuIds; cpu++) {
            int ret = scx_bpf_create_dsq(PINNED_DSQ_BASE + cpu, -1);
            if (ret < 0) return ret;
        }
        int ret = scx_bpf_create_dsq(TIER_PRIORITY_DSQ, -1);
        if (ret < 0) return ret;
        ret = scx_bpf_create_dsq(TIER_NORMAL_DSQ, -1);
        if (ret < 0) return ret;
        ret = scx_bpf_create_dsq(TIER_LOW_DSQ, -1);
        if (ret < 0) return ret;
        return scx_bpf_create_dsq(TIER_DEFICIT_DSQ, -1);
    }

    @Override
    public int initTask(Ptr<task_struct> p, Ptr<ScxDefinitions.scx_init_task_args> args) {
        Ptr<TaskCtx> tctx = taskCtxStor.bpf_getOrCreate(p);
        if (tctx == null) return -12; // ENOMEM
        resetTaskCtx(tctx, BPFJ.currentNs(), true);
        initTaskEvents.addAndGet(1L);
        return 0;
    }

    @Override
    public void enable(Ptr<task_struct> p) {
        Ptr<TaskCtx> tctx = taskCtxStor.bpf_getOrCreate(p);
        if (tctx == null) return;
        boolean sleeping = !scx_bpf_task_running(p);
        resetTaskCtx(tctx, BPFJ.currentNs(), sleeping);
        enableEvents.addAndGet(1L);
    }

    @Override
    public void exitTask(Ptr<task_struct> p, Ptr<ScxDefinitions.scx_exit_task_args> args) {
        Ptr<TaskCtx> tctx = taskCtxStor.bpf_get(p);
        if (tctx == null) return;
        resetTaskCtx(tctx, 0, false);
        exitTaskEvents.addAndGet(1L);
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        Ptr<TaskCtx> tctx = taskCtxStor.bpf_get(p);
        boolean nonMigratable = isMigrationDisabled(p);

        if (tctx != null) {
            if (tctx.val().sleepStartedAt != 0) {
                updateBudgetOnWakeup(p, tctx, BPFJ.currentNs());
            }
            clearWakeTarget(tctx);
        }

        // Prefer last-run CPU for cache locality (skip for first run or non-migratable)
        int preferredCpu = prev_cpu;
        if (!nonMigratable && tctx != null && tctx.val().lastCpu >= 0) {
            preferredCpu = tctx.val().lastCpu;
        }

        boolean isIdle = false;
        int cpu;

        if (nonMigratable) {
            // Non-migratable: stay on current CPU; don't bother searching
            cpu = preferredCpu;
            isIdle = scx_bpf_test_and_clear_cpu_idle(preferredCpu);
        } else {
            boolean isIdleBox = false;
            cpu = scx_bpf_select_cpu_dfl(p, preferredCpu, wake_flags, Ptr.of(isIdleBox));
            isIdle = isIdleBox;
        }

        if (tctx != null) {
            int finalCpu = cpu >= 0 ? cpu : preferredCpu;
            tctx.val().wakeCpu = finalCpu;
            tctx.val().wakeCpuIdle = isIdle;
            tctx.val().wakeCpuValid = cpu >= 0;
        }

        return cpu >= 0 ? cpu : preferredCpu;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        long nrCpuIds = scx_bpf_nr_cpu_ids();
        Ptr<TaskCtx> tctx = taskCtxStor.bpf_get(p);
        long sliceNs = taskSliceNs(tctx);
        boolean isWakeup = (enq_flags & SCX_ENQ_WAKEUP.value()) != 0;

        int targetCpu = -1;
        boolean hasWakeTarget = false;
        if (tctx != null && tctx.val().wakeCpuValid) {
            targetCpu = tctx.val().wakeCpu;
            hasWakeTarget = true;
        }

        int taskCpu = scx_bpf_task_cpu(p);
        if (isMigrationDisabled(p) && taskCpu >= 0) {
            if (!hasWakeTarget || targetCpu != taskCpu) {
                targetCpu = taskCpu;
                hasWakeTarget = true;
                if (tctx != null) {
                    tctx.val().wakeCpu = taskCpu;
                    tctx.val().wakeCpuIdle = false;
                    tctx.val().wakeCpuValid = true;
                }
            }
        }

        // Pinned kernel threads go straight to the local DSQ
        if ((p.val().flags & PerProcessFlags.PF_KTHREAD) != 0 && p.val().nr_cpus_allowed == 1) {
            clearWakeTarget(tctx);
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL.value(), SLICE_MIN_NS, enq_flags);
            return;
        }

        // Non-migratable non-wakeup → per-CPU pinned DSQ
        if (!isWakeup && tctx != null && isMigrationDisabled(p)) {
            if (taskCpu >= 0 && validSchedCpu(taskCpu, nrCpuIds)) {
                clearWakeTarget(tctx);
                scx_bpf_dsq_insert(p, PINNED_DSQ_BASE + taskCpu, taskSliceNs(tctx), enq_flags);
                pinnedDispatches.addAndGet(1L);
                return;
            }
        }

        // Wakeup with a known idle target → dispatch directly to that CPU
        if (isWakeup && hasWakeTarget && validSchedCpu(targetCpu, nrCpuIds)) {
            long wakeEnqFlags = enq_flags | SCX_ENQ_HEAD.value();
            if (tctx != null && (tctx.val().firstRun
                    || tctx.val().budgetNs >= SLICE_MIN_NS)) {
                wakeEnqFlags |= SCX_ENQ_PREEMPT.value();
            }
            scx_bpf_cpuperf_set(targetCpu, 1024); // SCX_CPUPERF_ONE
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON.value() | targetCpu, SLICE_MIN_NS, wakeEnqFlags);
            prioDispatches.addAndGet(1L);
            clearWakeTarget(tctx);
            return;
        }

        // Tier classification by budget
        long budget = tctx != null ? tctx.val().budgetNs : 0L;
        if (budget >= BUDGET_TIER_PRIORITY_NS) {
            scx_bpf_dsq_insert(p, TIER_PRIORITY_DSQ, sliceNs, enq_flags);
        } else if (budget >= BUDGET_TIER_NORMAL_NS) {
            scx_bpf_dsq_insert(p, TIER_NORMAL_DSQ, sliceNs, enq_flags);
        } else if (budget >= BUDGET_TIER_LOW_NS) {
            scx_bpf_dsq_insert(p, TIER_LOW_DSQ, sliceNs, enq_flags);
        } else {
            scx_bpf_dsq_insert(p, TIER_DEFICIT_DSQ, sliceNs, enq_flags);
        }
        clearWakeTarget(tctx);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        // addAndGet returns new value; subtract 1 to get the old gen for phase selection
        long gen = dispatchGen.addAndGet(1L) - 1L;

        // Pinned DSQ always first (non-migratable tasks, latency-sensitive)
        long pinnedDsq = PINNED_DSQ_BASE + cpu;
        if (scx_bpf_dsq_nr_queued(pinnedDsq) > 0 && scx_bpf_dsq_move_to_local(pinnedDsq)) {
            pinnedDispatches.addAndGet(1L);
            return;
        }

        // Rotating tier dispatch: each phase starts from a different tier
        int phase = (int)(gen & 3L);
        if (phase == 0) {
            if (dispatchTierPriority()) return;
            if (dispatchTierNormal())   return;
            if (dispatchTierLow())      return;
            if (dispatchTierDeficit())  return;
        } else if (phase == 1) {
            if (dispatchTierNormal())   return;
            if (dispatchTierLow())      return;
            if (dispatchTierDeficit())  return;
            if (dispatchTierPriority()) return;
        } else if (phase == 2) {
            if (dispatchTierLow())      return;
            if (dispatchTierDeficit())  return;
            if (dispatchTierPriority()) return;
            if (dispatchTierNormal())   return;
        } else {
            if (dispatchTierDeficit())  return;
            if (dispatchTierPriority()) return;
            if (dispatchTierNormal())   return;
            if (dispatchTierLow())      return;
        }

        // No tasks anywhere — let prev keep its slice if still queued
        if (prev != null && (prev.val().scx.flags & 1) != 0) { // SCX_TASK_QUEUED = 1
            Ptr<TaskCtx> tctx = taskCtxStor.bpf_get(prev);
            prev.val().scx.slice = taskSliceNs(tctx);
        }
    }

    @BPFFunction
    @AlwaysInline
    boolean dispatchTierPriority() {
        if (scx_bpf_dsq_nr_queued(TIER_PRIORITY_DSQ) > 0 && scx_bpf_dsq_move_to_local(TIER_PRIORITY_DSQ)) {
            tierPriorityDispatches.addAndGet(1L);
            return true;
        }
        return false;
    }

    @BPFFunction
    @AlwaysInline
    boolean dispatchTierNormal() {
        if (scx_bpf_dsq_nr_queued(TIER_NORMAL_DSQ) > 0 && scx_bpf_dsq_move_to_local(TIER_NORMAL_DSQ)) {
            tierNormalDispatches.addAndGet(1L);
            return true;
        }
        return false;
    }

    @BPFFunction
    @AlwaysInline
    boolean dispatchTierLow() {
        if (scx_bpf_dsq_nr_queued(TIER_LOW_DSQ) > 0 && scx_bpf_dsq_move_to_local(TIER_LOW_DSQ)) {
            tierLowDispatches.addAndGet(1L);
            return true;
        }
        return false;
    }

    @BPFFunction
    @AlwaysInline
    boolean dispatchTierDeficit() {
        if (scx_bpf_dsq_nr_queued(TIER_DEFICIT_DSQ) > 0 && scx_bpf_dsq_move_to_local(TIER_DEFICIT_DSQ)) {
            tierDeficitDispatches.addAndGet(1L);
            return true;
        }
        return false;
    }

    @Override
    public void runnable(Ptr<task_struct> p, @Unsigned long enq_flags) {
        Ptr<TaskCtx> tctx = taskCtxStor.bpf_get(p);
        if (tctx == null) return;
        long now = BPFJ.currentNs();
        if (tctx.val().sleepStartedAt != 0 && now > tctx.val().sleepStartedAt) {
            Ptr<FlowCpuState> cs = cpuState.bpf_get(0);
            if (cs != null) cs.val().runnableWakeups++;
            else runnableWakeups.addAndGet(1L);
        }
        updateBudgetOnWakeup(p, tctx, now);
    }

    @Override
    public void running(Ptr<task_struct> p) {
        Ptr<TaskCtx> tctx = taskCtxStor.bpf_get(p);
        if (tctx != null) {
            int currentCpu = BPFJ.currentCpuId();
            long now = BPFJ.currentNs();
            if (tctx.val().lastCpu >= 0 && tctx.val().lastCpu != currentCpu) {
                Ptr<FlowCpuState> cs = cpuState.bpf_get(0);
                if (cs != null) cs.val().cpuMigrations++;
                else cpuMigrations.addAndGet(1L);
            }
            tctx.val().lastCpu = currentCpu;
            tctx.val().lastRunAt = now;
            tctx.val().firstRun = false;
        }
        onCpu.addAndGet(1L);
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        Ptr<TaskCtx> tctx = taskCtxStor.bpf_get(p);
        long runtimeNs = 0;
        if (tctx != null) {
            long now = BPFJ.currentNs();
            if (tctx.val().lastRunAt != 0 && now > tctx.val().lastRunAt) {
                runtimeNs = now - tctx.val().lastRunAt;
            }
            if (tctx.val().budgetNs > 0 && tctx.val().budgetNs - runtimeNs <= 0) {
                Ptr<FlowCpuState> cs = cpuState.bpf_get(0);
                if (cs != null) cs.val().budgetExhaustions++;
                else budgetExhaustions.addAndGet(1L);
            }
            tctx.val().budgetNs = clampBudget(tctx.val().budgetNs - runtimeNs);
            tctx.val().lastRunAt = 0;
            if (runnable) {
                tctx.val().sleepStartedAt = 0;
            } else {
                tctx.val().sleepStartedAt = BPFJ.currentNs();
                clearWakeTarget(tctx);
            }
        }
        totalRuntime.addAndGet(runtimeNs);
        onCpu.addAndGet(-1L);
    }

    @Override
    public boolean yield(Ptr<task_struct> from, Ptr<task_struct> to) {
        // Shorten slice to minimum but keep task eligible for immediate re-dispatch
        from.val().scx.slice = SLICE_MIN_NS;
        return false;
    }

    @Override
    public void cpuRelease(int cpu, Ptr<ScxDefinitions.scx_cpu_release_args> args) {
        scx_bpf_reenqueue_local();
        cpuReleaseReenqueues.addAndGet(1L);
    }

    // -------------------------------------------------------------------------
    // Java-side API
    // -------------------------------------------------------------------------

    /** Returns the total number of tasks currently on-CPU (global volatile). */
    public long getOnCpu() { return onCpu.get(); }

    /** Returns cumulative nanoseconds of runtime across all tasks. */
    public long getTotalRuntime() { return totalRuntime.get(); }

    /** Returns total dispatches from pinned per-CPU DSQs. */
    public long getPinnedDispatches() { return pinnedDispatches.get(); }

    /** Returns priority-wakeup dispatches (direct LOCAL_ON insertion). */
    public long getPrioDispatches() { return prioDispatches.get(); }

    /** Returns dispatches from the PRIORITY tier DSQ. */
    public long getTierPriorityDispatches() { return tierPriorityDispatches.get(); }

    /** Returns dispatches from the NORMAL tier DSQ. */
    public long getTierNormalDispatches() { return tierNormalDispatches.get(); }

    /** Returns dispatches from the LOW tier DSQ. */
    public long getTierLowDispatches() { return tierLowDispatches.get(); }

    /** Returns dispatches from the DEFICIT tier DSQ. */
    public long getTierDeficitDispatches() { return tierDeficitDispatches.get(); }

    /** Returns tasks that ran their budget to zero or below. */
    public long getBudgetExhaustions() { return budgetExhaustions.get(); }

    /** Returns tasks woken from sleep. */
    public long getRunnableWakeups() { return runnableWakeups.get(); }

    /** Returns times a CPU was released to RT/DL and local tasks were re-enqueued. */
    public long getCpuReleaseReenqueues() { return cpuReleaseReenqueues.get(); }

    /** Returns total CPU migrations (task switched to a different CPU). */
    public long getCpuMigrations() { return cpuMigrations.get(); }

    /** Sets the maximum slice size (nanoseconds). Clamped to [50 µs, 350 µs]. */
    public void setReservedMaxNs(long ns) { tuneReservedMaxNs.set(ns); }

    /** Sets the interactive wakeup refill floor (nanoseconds). Clamped to [80 µs, 200 µs]. */
    public void setInteractiveFloorNs(long ns) { tuneInteractiveFloorNs.set(ns); }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(FlowScheduler.class)) {
            if (args.length >= 1) prog.setReservedMaxNs(Long.parseLong(args[0]));
            if (args.length >= 2) prog.setInteractiveFloorNs(Long.parseLong(args[1]));
            System.out.println("Flow scheduler attached — press Enter to stop.");
            prog.runSchedulerLoop();
        }
    }
}
