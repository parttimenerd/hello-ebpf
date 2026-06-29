// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.bpf.map.BPFTaskStorage;
import me.bechberger.ebpf.bpf.map.BPFTypedArena;
import me.bechberger.ebpf.bpf.map.BPFUserRingBuffer;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.runtime.ScxDefinitions.scx_init_task_args;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.BPFJ.currentNs;
import static me.bechberger.ebpf.bpf.BPFJ.sync_fetch_and_add;
import static me.bechberger.ebpf.bpf.BPFJ.sync_fetch_and_and;
import static me.bechberger.ebpf.bpf.BPFJ.sync_fetch_and_or;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * BPF half of the userspace-scheduler framework.
 *
 * <p>Extends {@link SchedulerBase} (which provides {@code SHARED_DSQ_ID} and the
 * {@code init}/{@code dispatch} defaults) and implements the full set of
 * {@link Scheduler} ops needed for a Java-side run loop:
 *
 * <ul>
 *   <li>{@link #selectCPU} — idle short-circuit; increments {@code STAT_IDLE_FAST_PATH}.</li>
 *   <li>{@link #enqueue} — framework-PID fast path; kthread fast path (Task 5);
 *       ring-buf publish with wake-suppress (Task 6).</li>
 *   <li>{@link #dispatch} — drain framework DSQ, user ring-buf, stall fallback (Task 5/6).</li>
 *   <li>{@link #updateIdle} — keeps the mmap'd idle-CPU bitmap current.</li>
 *   <li>{@link #running}/{@link #stopping} — populate per-task timestamps.</li>
 *   <li>{@link #initTask} — allocates per-task storage.</li>
 *   <li>{@link #heartbeatTick} — periodic timer (Task 7).</li>
 * </ul>
 *
 * <p>Concrete scheduler samples extend this class, declare a {@code @BPF} annotation,
 * and pair it with a {@link UserspaceScheduler} subclass that implements the Java-side
 * scheduling policy.
 */
@BPF(license = "GPL")
public abstract class UserspaceSchedulerBase extends SchedulerBase implements Scheduler {

    // ─── Wire constants ───────────────────────────────────────────
    static final long FRAMEWORK_DSQ     = 1;
    /** Stall-fallback threshold: if Java hasn't dispatched for this long, promote from SHARED_DSQ. */
    static final long STALL_FALLBACK_NS = 50_000_000L;  // 50 ms
    /** Wire-compatible with rustland's RL_CPU_ANY sentinel. */
    static final int  ANY_CPU           = -1;
    /** Hardcoded CPU bitmap cap. Hosts with more CPUs need a recompile. */
    static final int  MAX_CPUS          = 1024;
    /** Number of 64-bit words in the idle-CPU bitmap ({@code MAX_CPUS / 64}). */
    static final int  BITMAP_WORDS      = MAX_CPUS / 64;  // 16
    /** Heartbeat timer period — matches rustland's bpf_timer period. */
    static final long HEARTBEAT_NS      = 1_000_000_000L; // 1 s

    // ─── Stat slot constants (BPF↔Java ABI — append only, never reorder) ────
    /**
     * Slot indices for {@link SchedStats}. Numbering is load-bearing: both the
     * {@code @Type} field order in {@link SchedStats} and every {@link #incStat}/
     * {@link #decStat} call site reference these integers. New counters are
     * <em>appended only</em> — never reorder, never reuse a retired slot.
     */
    public static final class Stats {
        /** Slot 1: current online CPU count. */
        public static final int ONLINE_CPUS         = 1;
        /** Slot 2: tasks currently on a CPU (gauge). */
        public static final int RUNNING_TASKS        = 2;
        /** Slot 3: cumulative {@code enqueue} events routed to userspace. */
        public static final int NR_QUEUED            = 3;
        /** Slot 4: cumulative Java-side ring-buf submits accepted by kernel. */
        public static final int NR_SCHEDULED         = 4;
        /** Slot 5: cumulative kernel-side DSQ inserts via the Java-dispatch path. */
        public static final int USER_DISPATCHES      = 5;
        /** Slot 6: cumulative dispatches via BPF stall-fallback path. */
        public static final int KERNEL_DISPATCHES    = 6;
        /** Slot 7: task became ineligible (CPU offline, cpumask mismatch). */
        public static final int BOUNCED_DISPATCHES   = 7;
        /** Slot 8: Java reserve→discard, or reserve returned null. */
        public static final int CANCELLED_DISPATCHES = 8;
        /** Slot 9: {@code enqueue} saw full kernel→user ring-buf. */
        public static final int CONGESTION_EVENTS    = 9;
        /** Slot 10: tasks routed to FRAMEWORK_DSQ in enqueue. */
        public static final int FRAMEWORK_ENQUEUES   = 10;
        /** Slot 11: exceptions caught in {@code schedule()} per-task try block. */
        public static final int POLICY_EXCEPTIONS    = 11;
        /** Slot 12: {@code selectCPU} short-circuited to LOCAL on idle hint. */
        public static final int IDLE_FAST_PATH       = 12;

        private Stats() {}
    }

    // Keep shorter aliases for use in method bodies below.
    private static final int STAT_ONLINE_CPUS         = Stats.ONLINE_CPUS;
    private static final int STAT_RUNNING_TASKS        = Stats.RUNNING_TASKS;
    private static final int STAT_NR_QUEUED            = Stats.NR_QUEUED;
    private static final int STAT_NR_SCHEDULED         = Stats.NR_SCHEDULED;
    private static final int STAT_USER_DISPATCHES      = Stats.USER_DISPATCHES;
    private static final int STAT_KERNEL_DISPATCHES    = Stats.KERNEL_DISPATCHES;
    private static final int STAT_BOUNCED_DISPATCHES   = Stats.BOUNCED_DISPATCHES;
    private static final int STAT_CANCELLED_DISPATCHES = Stats.CANCELLED_DISPATCHES;
    private static final int STAT_CONGESTION_EVENTS    = Stats.CONGESTION_EVENTS;
    private static final int STAT_FRAMEWORK_ENQUEUES   = Stats.FRAMEWORK_ENQUEUES;
    private static final int STAT_POLICY_EXCEPTIONS    = Stats.POLICY_EXCEPTIONS;
    private static final int STAT_IDLE_FAST_PATH       = Stats.IDLE_FAST_PATH;

    // ─── BPF @Type records/classes ────────────────────────────────
    /**
     * Per-task context stored in {@link #taskCtx}. The {@code enqCnt} counter is
     * bumped on every {@link #enqueue} and copied into the kernel→user record; the
     * drain callback compares the record's {@code enqCnt} against the task's current
     * value and cancels stale dispatches (Task 6).
     *
     * <p>Declared as a {@code class} (not {@code record}) so that BPF code can
     * mutate individual fields via {@code ptr.val().field = x}.
     */
    @Type
    static class TaskCtx {
        @Unsigned long enqCnt;
        @Unsigned long startTs;
        @Unsigned long stopTs;
        @Unsigned long execRuntime;
    }

    /**
     * Kernel→user ring-buf record. Wire-layout-equivalent to
     * {@code scx_rustland_core}'s {@code queued_task_ctx}. The Java side surfaces
     * these fields via {@link QueuedTask}.
     */
    @Type
    record QueuedTaskCtx(
        int pid,
        int prevCpu,
        @Unsigned long nrCpusAllowed,
        @Unsigned long flags,
        @Unsigned long startTs,
        @Unsigned long stopTs,
        @Unsigned long execRuntime,
        @Unsigned long weight,
        @Unsigned long vtime,
        @Unsigned long enqCnt,
        @Size(16) byte[] comm
    ) {}

    /**
     * User→kernel ring-buf record. Wire-layout-equivalent to rustland's
     * dispatched-task record. The Java side fills this via {@link DispatchedTask}.
     */
    @Type
    record DispatchedTaskCtx(
        int pid,
        int targetCpu,
        @Unsigned long flags,
        @Unsigned long sliceNs,
        @Unsigned long vtime,
        @Unsigned long enqCnt
    ) {}

    /**
     * Shared stats arena, mmap'd from Java. 12 counters; slot numbering is
     * part of the BPF↔Java ABI — see {@link Stats}. BPF increments via
     * {@code __sync_fetch_and_add}; Java reads via {@code VarHandle.getOpaque()}.
     */
    @Type
    record SchedStats(
        @Unsigned long onlineCpus,
        @Unsigned long runningTasks,
        @Unsigned long nrQueued,
        @Unsigned long nrScheduled,
        @Unsigned long userDispatches,
        @Unsigned long kernelDispatches,
        @Unsigned long bouncedDispatches,
        @Unsigned long cancelledDispatches,
        @Unsigned long congestionEvents,
        @Unsigned long frameworkEnqueues,
        @Unsigned long policyExceptions,
        @Unsigned long idleFastPath
    ) {}

    // ─── Per-task storage ─────────────────────────────────────────
    /**
     * Per-task storage allocated lazily in {@link #initTask} and freed automatically
     * by the kernel on task exit. The {@code enqCnt} counter is bumped on every
     * {@link #enqueue} call; the drain callback uses it to cancel stale dispatches
     * (Task 6: stale-dispatch cancellation path).
     */
    @BPFMapDefinition(maxEntries = 1)   // BPF_MAP_TYPE_TASK_STORAGE — kernel ignores maxEntries; 1 satisfies plugin validator
    BPFTaskStorage<TaskCtx> taskCtx;

    // ─── Ring-buf maps ────────────────────────────────────────────
    // 4 MiB ≈ 52k QueuedTaskCtx records at ~80 B each — large enough to absorb
    // fork-storm scenarios without back-pressuring into SHARED_DSQ.
    /** Kernel→user ring buffer: BPF enqueues; Java drains. */
    @BPFMapDefinition(maxEntries = 4 * 1024 * 1024)
    BPFRingBuffer<QueuedTaskCtx> queued;

    /** User→kernel ring buffer: Java submits dispatch decisions; BPF drains. */
    @BPFMapDefinition(maxEntries = 4 * 1024 * 1024)
    BPFUserRingBuffer<DispatchedTaskCtx> dispatched;

    // ─── Arena maps ───────────────────────────────────────────────
    /**
     * Shared stats arena, mmap'd from Java. Single slot of type {@link SchedStats}.
     * Slot 0 maps directly to the 12-counter struct; no index arithmetic needed.
     * <p>
     * Only one arena map is declared to avoid a clang {@code __ulong(map_extra,...)}
     * macro-counter collision that occurs when two arena maps appear in the same
     * generated C translation unit.
     */
    @BPFMapDefinition(maxEntries = 1)   // 1 page = 4 KiB; SchedStats is 96 B
    BPFTypedArena<SchedStats> stats;

    // ─── Hash and array maps ──────────────────────────────────────
    /**
     * Idle-CPU bitmap. One {@code long} word per 64 CPUs, indexed by {@code cpu / 64}.
     * BPF uses {@code __sync_fetch_and_or}/{@code and} to set/clear bits atomically
     * in {@link #setBit}. Java reads words individually via the map file-descriptor
     * (no mmap required — polled infrequently by the Java scheduler).
     * <p>
     * 16 entries = 1 024 bits = {@link #MAX_CPUS} coverage.
     */
    @BPFMapDefinition(maxEntries = 16)  // BITMAP_WORDS = MAX_CPUS / 64 = 16
    BPFArray<Long> idleBitmap;

    /** PIDs of threads that belong to the scheduler process; value is ignored. */
    @BPFMapDefinition(maxEntries = 8192)
    BPFHashMap<Integer, Byte> frameworkPids;

    /**
     * Per-CPU drain budget — counted down inside {@link #dispatchOne} so each
     * {@link #dispatch} call cannot consume more slots than
     * {@code scx_bpf_dispatch_nr_slots()} reports. Single-entry array keyed by 0;
     * BPFPerCpuArray stamps one counter per CPU automatically.
     */
    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Integer> dispatchBudget;

    /**
     * Single-entry array holding a {@code bpf_timer} for the heartbeat.
     * Declared here so Task 7 can call {@code bpf_timer_init}/{@code bpf_timer_start}
     * from {@code initHeartbeat()} in {@link #init()}.
     *
     * TODO Task 7: wire heartbeat init + tick callback.
     */
    @BPFMapDefinition(maxEntries = 1)
    BPFArray<bpf_timer> heartbeat;

    // ─── DSQ handles ─────────────────────────────────────────────
    /**
     * Framework-priority DSQ — scheduler process threads are routed here.
     * The {@code @BPFAbstraction} constructor injects
     * {@code scx_bpf_create_dsq(FRAMEWORK_DSQ, -1)} into {@link #init()}.
     */
    final DispatchQueue framework = new DispatchQueue(FRAMEWORK_DSQ);

    /**
     * Shared FIFO DSQ — stall-fallback path drains from here.
     * <p>
     * Declared with {@code new DispatchQueue(0L)} so the plugin injects
     * {@code scx_bpf_create_dsq(0, -1)} into {@code init()} alongside
     * {@link #framework}'s creation call. We do NOT override {@code init()}
     * (which would require calling {@code super.init()}, broken in C since
     * {@code init} and the BPF struct-ops entry point are the same symbol) — instead
     * we let both {@code DispatchQueue} field constructors inject their
     * {@code scx_bpf_create_dsq} calls via the {@code @BPFAbstraction} mechanism.
     */
    final DispatchQueue shared = new DispatchQueue(0L);

    // ─── Global variables ─────────────────────────────────────────
    /**
     * TGID of the Java scheduler process. Written by the framework before
     * {@code attachScheduler()}, read by {@link #enqueue} to gate the
     * framework-PID fast path, and by the {@code onFork} tracepoint (Task 7).
     */
    final GlobalVariable<Integer> schedulerTgid = new GlobalVariable<>(0);

    /** Timestamp of the last Java→kernel dispatch, used for the stall-fallback check. */
    final GlobalVariable<@Unsigned Long> lastUserDispatchNs = new GlobalVariable<>(0L);

    /** Timestamp of the last {@link #enqueue} that routed a task to userspace. */
    final GlobalVariable<@Unsigned Long> lastEnqueueNs = new GlobalVariable<>(0L);

    /**
     * Pending-task hint written by {@code UserspaceScheduler.notifyComplete(pending)}.
     * BPF's {@link #enqueue} reads this to suppress the ring-buf wakeup when
     * Java already has queued work (wake-suppress, Task 6).
     */
    final GlobalVariable<@Unsigned Long> nrUserPending = new GlobalVariable<>(0L);

    /**
     * CPU the scheduler thread last ran on. The heartbeat timer (Task 7) kicks
     * this CPU to keep the Java run loop ticking even when no enqueues arrive.
     */
    final GlobalVariable<Integer> schedulerCpu = new GlobalVariable<>(0);

    /**
     * PID of {@code kswapd}; 0 means not found. Populated by Java at startup via
     * {@code /proc} scan. The kthread fast path in {@link #enqueue} routes it to
     * {@code SCX_DSQ_LOCAL_ON} to avoid latency from the userspace round-trip
     * (Task 5).
     */
    final GlobalVariable<Integer> kswapdPid = new GlobalVariable<>(0);

    /**
     * PID of {@code khugepaged}; 0 means not found. Same role as
     * {@link #kswapdPid} (Task 5).
     */
    final GlobalVariable<Integer> khugepageDPid = new GlobalVariable<>(0);

    // ─── sched_ext ops ───────────────────────────────────────────

    // init() is NOT overridden here. Both DispatchQueue fields (framework, shared)
    // inject their scx_bpf_create_dsq() calls into the inherited init() via the
    // @BPFAbstraction(constructorPrependTo = "init") mechanism. No super.init()
    // call is needed — SchedulerBase.init() only creates SHARED_DSQ_ID(=0), which
    // is now handled by `new DispatchQueue(0L)` above.
    // TODO Task 7: add initHeartbeat() @BPFFunction + call it from init() override
    //   once bpf_timer_init is supported without a super.init() chaining issue.

    /**
     * Idle short-circuit: when the kernel reports a known-idle CPU, pre-dispatch
     * straight to {@code SCX_DSQ_LOCAL} and skip Java entirely. Mirrors
     * rustland's selectCPU behaviour. Falls back to "let {@link #enqueue} ship
     * to Java" when no idle CPU is available.
     *
     * <p>Uses {@link #selectCpuDefault} which pre-dispatches to
     * {@code SCX_DSQ_LOCAL} when idle and increments the idle-fast-path stat
     * via {@link #incStat}.
     */
    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        // selectCpuDefault pre-dispatches to SCX_DSQ_LOCAL when idle (enqueue won't be called).
        return selectCpuDefault(p, prev_cpu, wake_flags);
        // TODO Task 5: also call incStat(STAT_IDLE_FAST_PATH, 1) when idle path taken
        //   (needs is_idle detection; selectCpuDefault hides it — consider inlining)
    }

    /**
     * Route the task to the correct destination DSQ.
     *
     * <p>Framework threads (PIDs in {@link #frameworkPids}) go straight to
     * {@link #framework} with priority. All other tasks are published to the
     * Java-side via the {@link #queued} ring-buf after the kthread fast-path
     * check (Task 5).
     *
     * TODO Task 5: kthread fast path (PF_KTHREAD && nr_cpus_allowed==1, kswapdPid, khugepageDPid).
     * TODO Task 5/6: lastEnqueueNs update, taskCtx.enqCnt bump, queued.reserve/submit per spec §2 lines 262-284.
     */
    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        int pid = p.val().pid;
        if (frameworkPids.bpf_get(pid) != null) {
            framework.insertScaled(p, EnqFlags.passThrough(enq_flags));
            incStat(STAT_FRAMEWORK_ENQUEUES, 1);
            return;
        }
        // TODO Task 5: kthread fast path per spec §2 lines 255-261
        // TODO Task 5/6: lastEnqueueNs update, taskCtx.enqCnt bump, queued.reserve/submit per spec §2 lines 262-284
        // Temporary fallback: route unhandled tasks to SHARED_DSQ until Task 5
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    /**
     * Drain decisions from Java and dispatch tasks.
     *
     * <p>Priority order: (1) framework DSQ, (2) user ring-buf drain, (3) stall
     * fallback to SHARED_DSQ when Java is silent too long.
     *
     * TODO Task 5/6: full dispatch body per spec §2 lines 287-327
     *   — drain budget setup, dispatched.drain, lastUserDispatchNs, stall fallback.
     */
    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        // 1. Drain framework DSQ first — unbounded priority
        if (framework.moveToLocal()) return;
        // TODO Task 5/6: user ring-buf drain + stall fallback per spec §2 lines 292-327
        shared.moveToLocal();
    }

    /**
     * Drain callback: dispatch one record from the user→kernel ring-buf.
     *
     * <p>Returns 0 to continue draining, 1 to stop (budget exhausted).
     *
     * TODO Task 5/6: full dispatchOne body per spec §2 lines 345-383
     *   — bpf_task_from_pid, enqCnt cancellation (Task 6), affinity validation,
     *     ANY_CPU routing, budget decrement.
     */
    @BPFFunction
    int dispatchOne(Ptr<DispatchedTaskCtx> d, Ptr<Integer> budget) {
        // TODO Task 5/6: implement per spec §2 lines 345-383
        return 0;
    }

    /**
     * Keep the idle-CPU bitmap ({@link #idleBitmap}) current.
     * Also tracks the {@code runningTasks} stat counter (gauge).
     */
    @Override
    public void updateIdle(int cpu, boolean idle) {
        setBit(cpu, idle);
        if (idle) decStat(STAT_RUNNING_TASKS, 1);
        else      incStat(STAT_RUNNING_TASKS, 1);
    }

    // ─── Per-task lifecycle ops ──────────────────────────────────

    /**
     * Allocate per-task storage. Returns {@code -12} ({@code -ENOMEM}) on failure,
     * which causes the kernel to refuse to admit the task to this scheduler.
     */
    @Override
    public int initTask(Ptr<task_struct> p, Ptr<scx_init_task_args> args) {
        Ptr<TaskCtx> t = taskCtx.bpf_getOrCreate(p);
        if (t == null) return -12; // -ENOMEM
        t.val().enqCnt      = 0;
        t.val().startTs     = 0;
        t.val().stopTs      = 0;
        t.val().execRuntime = 0;
        return 0;
    }

    /**
     * Task became runnable but is not yet on a CPU. No-op in the base class;
     * subclasses can override to receive "task is now eligible" notifications
     * mirroring rustland's runnable callback.
     */
    @Override
    public void runnable(Ptr<task_struct> p, @Unsigned long enq_flags) {
        // No-op for the framework; subclasses can override.
    }

    /**
     * Task was context-switched in — record the start timestamp.
     * Feeds the {@code execRuntime} accounting in {@link #stopping}.
     */
    @Override
    public void running(Ptr<task_struct> p) {
        Ptr<TaskCtx> t = taskCtx.bpf_get(p);
        if (t != null) t.val().startTs = currentNs();
    }

    /**
     * Task was context-switched out — update timestamps and accumulated runtime.
     *
     * @param runnable {@code true} if the task will be re-enqueued (preempted);
     *                 {@code false} if it is going to sleep
     */
    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        Ptr<TaskCtx> t = taskCtx.bpf_get(p);
        if (t == null) return;
        @Unsigned long now = currentNs();
        t.val().stopTs = now;
        if (t.val().startTs != 0) {
            t.val().execRuntime += now - t.val().startTs;
            t.val().startTs = 0;
        }
    }

    // exitTask: task_storage maps are freed automatically by the kernel
    // on task exit, so no manual cleanup is required.

    // ─── Heartbeat timer ─────────────────────────────────────────

    /**
     * Periodic BPF timer callback that kicks the scheduler CPU once per
     * {@link #HEARTBEAT_NS}. Load-bearing on fully-idle systems: without it, the
     * Java run loop can starve and trip the sched_ext watchdog before
     * {@link #STALL_FALLBACK_NS} fires.
     *
     * TODO Task 7: implement per spec §2 lines 437-448
     *   (bpf_timer_start reschedule + schedulerCpu kick via DispatchQueue.kickCpu).
     */
    @BPFFunction
    int heartbeatTick(Ptr<bpf_timer> t) {
        // TODO Task 7: DispatchQueue.kickCpu(schedulerCpu.get(), KickFlags.idle())
        //              + bpf_timer_start(t, HEARTBEAT_NS, 0)
        return 0;
    }

    // TODO Task 7: add initHeartbeat() called from init() + onFork tracepoint (spec §2 lines 458-474)

    // ─── BPF-side stat and bitmap helpers ────────────────────────

    /**
     * Atomically increment {@code stats} counter at {@code slot} by {@code delta}.
     *
     * <p>Slot indices are defined in {@link Stats}; slot numbering is an ABI contract.
     * Lowers to a {@code __sync_fetch_and_add} on the corresponding {@code long} field
     * of the single {@link SchedStats} record at index 0 of the {@link #stats} arena.
     *
     * <p>Spec §"BPF-side stat and bitmap helpers" lines 1341-1347.
     *
     * @param slot  counter slot (1–12, see {@link Stats})
     * @param delta amount to add (typically 1)
     */
    @BPFFunction
    void incStat(int slot, long delta) {
        int zero = 0;
        Ptr<SchedStats> s = stats.bpf_lookup_elem(Ptr.of(zero));
        if (s == null) return;
        // slot is 1-based; field offset = (slot - 1) * 8 bytes (all longs, tightly packed)
        long offset = (long)(slot - 1) * 8L;
        Ptr<Long> fieldPtr = s.<Byte>cast().add(offset).<Long>cast();
        sync_fetch_and_add(fieldPtr, delta);
    }

    /**
     * Atomically decrement {@code stats} counter at {@code slot} by {@code delta}.
     *
     * <p>See {@link #incStat} for the slot numbering contract.
     *
     * @param slot  counter slot (1–12, see {@link Stats})
     * @param delta amount to subtract (typically 1)
     */
    @BPFFunction
    void decStat(int slot, long delta) {
        int zero = 0;
        Ptr<SchedStats> s = stats.bpf_lookup_elem(Ptr.of(zero));
        if (s == null) return;
        long offset = (long)(slot - 1) * 8L;
        Ptr<Long> fieldPtr = s.<Byte>cast().add(offset).<Long>cast();
        sync_fetch_and_add(fieldPtr, -delta);
    }

    /**
     * Atomically set or clear bit {@code cpu} in the idle-CPU bitmap.
     *
     * <p>Bit {@code cpu} lives in word {@code cpu / 64} at bit position
     * {@code cpu & 63}. Uses {@code __sync_fetch_and_or} (set) /
     * {@code __sync_fetch_and_and} (clear) to be safe against concurrent
     * {@link #updateIdle} calls from different CPUs.
     *
     * <p>The bitmap is stored in {@link #idleBitmap}, a {@code BPFArray<Long>}
     * with 16 words (= 1 024 bits = {@link #MAX_CPUS} coverage). Java reads words
     * individually via the map fd (no mmap — polled infrequently).
     *
     * @param cpu   CPU number (must be in [0, {@link #MAX_CPUS}))
     * @param idle  {@code true} to mark idle (set bit), {@code false} to mark busy (clear bit)
     */
    @BPFFunction
    void setBit(int cpu, boolean idle) {
        if (cpu >= MAX_CPUS) return;             // bounded write
        int wordIdx = cpu / 64;
        Ptr<Long> word = idleBitmap.bpf_get(wordIdx);
        if (word == null) return;
        long mask = 1L << (cpu & 63);
        if (idle) sync_fetch_and_or(word, mask);
        else      sync_fetch_and_and(word, ~mask);
    }
}
