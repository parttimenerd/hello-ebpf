// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.InArena;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFTimer;
import me.bechberger.ebpf.annotations.bpf.Tracepoint;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.bpf.map.BPFArena;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFHistogram;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.bpf.map.BPFTaskStorage;
import me.bechberger.ebpf.bpf.map.BPFUserRingBuffer;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.bpf.sched.KickFlags;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.runtime.MmConstants;
import me.bechberger.ebpf.runtime.ScxDefinitions.scx_init_task_args;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Map;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_probe_read_kernel_str;
import static me.bechberger.ebpf.bpf.BPFJ.bpfArenaAllocPages;
import static me.bechberger.ebpf.bpf.BPFJ.currentNs;
import static me.bechberger.ebpf.bpf.BPFJ.sync_fetch_and_add;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_task_from_pid;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_init;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_start;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_task_release;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL_ON;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
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
    /** Default slice when the Java side submits sliceNs == 0. */
    static final long DEFAULT_SLICE_NS  =  5_000_000L;  // 5 ms
    /** Wire-compatible with rustland's RL_CPU_ANY sentinel. */
    static final int  ANY_CPU           = -1;
    /** Hardcoded CPU bitmap cap. Hosts with more CPUs need a recompile. */
    public static final int  MAX_CPUS          = 1024;
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
        /** Slot 13: heartbeat timer ticks (incremented in {@code heartbeatTick}). */
        public static final int HEARTBEAT_KICKS      = 13;

        private Stats() {}
    }

    // Keep shorter aliases for use in method bodies below.
    // Tasks 6/7/8+ will reference the remaining slots; suppress until then.
    @SuppressWarnings("unused") private static final int STAT_ONLINE_CPUS         = Stats.ONLINE_CPUS;
    @SuppressWarnings("unused") private static final int STAT_NR_SCHEDULED         = Stats.NR_SCHEDULED;
    private static final int STAT_KERNEL_DISPATCHES    = Stats.KERNEL_DISPATCHES;
    @SuppressWarnings("unused") private static final int STAT_CANCELLED_DISPATCHES = Stats.CANCELLED_DISPATCHES;
    @SuppressWarnings("unused") private static final int STAT_POLICY_EXCEPTIONS    = Stats.POLICY_EXCEPTIONS;
    @SuppressWarnings("unused") private static final int STAT_HEARTBEAT_KICKS      = Stats.HEARTBEAT_KICKS;
    // Active aliases — no suppression needed:
    private static final int STAT_RUNNING_TASKS        = Stats.RUNNING_TASKS;
    private static final int STAT_NR_QUEUED            = Stats.NR_QUEUED;
    private static final int STAT_USER_DISPATCHES      = Stats.USER_DISPATCHES;
    private static final int STAT_BOUNCED_DISPATCHES   = Stats.BOUNCED_DISPATCHES;
    private static final int STAT_CONGESTION_EVENTS    = Stats.CONGESTION_EVENTS;
    private static final int STAT_FRAMEWORK_ENQUEUES   = Stats.FRAMEWORK_ENQUEUES;
    private static final int STAT_IDLE_FAST_PATH        = Stats.IDLE_FAST_PATH;

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
     *
     * <p>Declared as a {@code class} (not {@code record}) so that BPF code can
     * mutate individual fields via {@code ptr.val().field = x}.
     *
     * @see QueuedTaskDispatchedTaskMarshallingTest for the bit-for-bit wire-format contract
     */
    @Type
    static class QueuedTaskCtx {
        int pid;
        int prevCpu;
        @Unsigned long nrCpusAllowed;
        @Unsigned long flags;
        @Unsigned long startTs;
        @Unsigned long stopTs;
        @Unsigned long execRuntime;
        @Unsigned long weight;
        @Unsigned long vtime;
        @Unsigned long enqCnt;
        @Size(16) byte[] comm;
    }

    /**
     * User→kernel ring-buf record. Wire-layout-equivalent to rustland's
     * dispatched-task record. The Java side fills this via {@link DispatchedTask}.
     *
     * <p>Declared as a {@code class} (not {@code record}) for symmetry with
     * {@link QueuedTaskCtx} and to allow Task 6+ to stamp fields back
     * (e.g., enqCnt cancellation feedback, wake-suppress flags).
     *
     * @see QueuedTaskDispatchedTaskMarshallingTest for the bit-for-bit wire-format contract
     */
    @Type
    static class DispatchedTaskCtx {
        public int pid;
        public int targetCpu;
        public @Unsigned long flags;
        public @Unsigned long sliceNs;
        public @Unsigned long vtime;
        public @Unsigned long enqCnt;
    }

    /**
     * Map-value wrapper for the heartbeat {@code bpf_timer}. The kernel requires
     * {@code bpf_timer} to be a <em>field</em> inside the map-value struct; it
     * cannot be the map value itself.
     */
    @Type
    public static class HeartbeatVal {
        public bpf_timer timer;
    }

    /**
     * Shared stats arena, mmap'd from Java. 13 counters; slot numbering is
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
        @Unsigned long idleFastPath,
        @Unsigned long heartbeatKicks
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
    public BPFRingBuffer<QueuedTaskCtx> queued;

    /** User→kernel ring buffer: Java submits dispatch decisions; BPF drains. */
    @BPFMapDefinition(maxEntries = 4 * 1024 * 1024)
    public BPFUserRingBuffer<DispatchedTaskCtx> dispatched;

    // ─── Arena maps ───────────────────────────────────────────────
    /**
     * Idle-CPU bitmap, mmap'd from Java. Each 8-byte word covers 64 CPUs;
     * word {@code i} covers CPUs {@code [64*i, 64*i+63]}. BPF uses atomic
     * or/and ops via {@link #setBit}. Java reads via the mmap'd view for
     * zero-syscall {@code pickIdleCpu} (Task 12, spec line 686).
     * <p>
     * This is the HOT path arena — must remain a {@code BPFArena} for zero-syscall
     * reads. One page = 4 KiB = 512 words = 32 768 bits; 16 words suffice for
     * {@link #MAX_CPUS} = 1 024 CPUs.
     */
    @BPFMapDefinition(maxEntries = 1)   // 1 page = 4 KiB; 16 words cover MAX_CPUS
    BPFArena idleMask;

    /**
     * Pre-allocated arena base pointer — obtained in {@link #init()} via
     * {@code bpf_arena_alloc_pages}, which gives the BPF verifier the
     * provenance required to accept atomic operations on the memory.
     *
     * <p>BPF code in {@link #setBit} uses this pointer for arithmetic rather
     * than the raw-VA cast previously used by {@code bpf_arena_word_at}. The
     * {@code @InArena} annotation causes the compiler plugin to emit the
     * {@code __arena} address-space qualifier so clang's type checker is
     * satisfied.
     */
    @InArena
    Ptr<Long> idleMaskBase;

    /**
     * Scheduler stats array. Single entry of type {@link SchedStats} at index 0.
     * BPF writes counters atomically via {@link #incStat}/{@link #decStat};
     * Java reads via {@code bpf_map_lookup_elem} syscall (acceptable: cold path).
     */
    @BPFMapDefinition(maxEntries = 1)   // single SchedStats slot
    BPFArray<SchedStats> stats;

    // ─── Hash and array maps ──────────────────────────────────────

    /** PIDs of threads that belong to the scheduler process; value is ignored. */
    @BPFMapDefinition(maxEntries = 8192)
    BPFHashMap<Integer, Byte> frameworkPids;

    /**
     * Single-entry array holding a {@link HeartbeatVal} (which wraps a
     * {@code bpf_timer} field). The kernel requires {@code bpf_timer} to be a
     * field inside the map-value struct, not the map value itself.
     */
    @BPFMapDefinition(maxEntries = 1)
    BPFArray<HeartbeatVal> heartbeat;

    // ─── Observability histograms (Task 14) ──────────────────────────────────
    // All five histograms use 64 buckets (BCC log2_hist layout: bucket i counts
    // values in [2^(i-1), 2^i)).  BPF-side recording via hist.record(value);
    // Java-side write via hist.increment(value); Java-side read via entrySet().

    /**
     * log2 histogram of batch sizes from {@code drainBatchOnce}.
     * Recorded on the Java side after each non-empty drain.
     */
    @BPFMapDefinition(maxEntries = 64)
    BPFHistogram batchSizeHist;

    /**
     * log2 histogram of kernel→user→kernel round-trip time in microseconds.
     * Recorded on the Java side at dispatch time, using {@code QueuedTask.stopTs}
     * (the BPF ktime when the task last stopped) as the start timestamp.
     *
     * <p>Note: {@code stopTs} is the task's last context-switch-out time, which
     * is a close but not exact proxy for the enqueue timestamp. A more precise
     * implementation would stamp the ring-buf record at {@code enqueue} time;
     * deferred to Task 21 obs-benchmark.
     */
    @BPFMapDefinition(maxEntries = 64)
    BPFHistogram roundTripUsHist;

    /**
     * log2 histogram of enqueue→dispatch latency in microseconds.
     * Intended for BPF-side recording at dispatch consume time.
     *
     * <p>TODO: Task 21 obs-benchmark — wire up BPF-side recording in
     * {@code dispatchOne} once a per-task enqueue timestamp is available.
     */
    @BPFMapDefinition(maxEntries = 64)
    BPFHistogram dispatchLatencyUsHist;

    /**
     * log2 histogram of ring-queue depth at enqueue time.
     * Intended for BPF-side recording inside {@code enqueue}.
     *
     * <p>TODO: Task 21 obs-benchmark — wire up BPF-side recording once a
     * depth estimator (e.g., a running NR_QUEUED - NR_CONSUMED counter) is
     * available in BPF context.
     */
    @BPFMapDefinition(maxEntries = 64)
    BPFHistogram queueDepthHist;

    /**
     * log2 histogram of time spent in one {@code consumeRaw} call in microseconds.
     * Recorded on the Java side, wrapping the {@code consumeRaw} call in
     * {@code drainBatchOnce}.
     */
    @BPFMapDefinition(maxEntries = 64)
    BPFHistogram ringConsumeUsHist;

    // ─── Histogram accessor seams (Task 14) ──────────────────────────────────
    //
    // These public methods are the ONLY way UserspaceScheduler should write to or
    // read from the five BPF histograms. Public (not protected) because
    // UserspaceScheduler is not a subclass of this class and requires cross-package
    // access. Following the same precedent as putFrameworkPid / frameworkPidsIterable.
    //
    // Tests may override UserspaceScheduler's recording seams (recordBatchSize etc.)
    // to capture calls without a live BPF fd; these base-class methods are exercised
    // only in production runs.

    /**
     * Test seam. Returns the {@link BPFHistogram} for batch sizes so that
     * {@link UserspaceScheduler#printHistograms} can read it without touching the
     * field directly across the package boundary.
     *
     * <p>Public to allow cross-package access from {@code UserspaceScheduler}
     * (which is not a subclass). Production code uses this for reading; histogram
     * writes go through {@link #recordBatchSizeHist}.
     */
    public BPFHistogram batchSizeHistView()       { return batchSizeHist; }

    /**
     * Test seam. Returns the {@link BPFHistogram} for round-trip latency.
     *
     * @see #batchSizeHistView()
     */
    public BPFHistogram roundTripHistView()       { return roundTripUsHist; }

    /**
     * Test seam. Returns the {@link BPFHistogram} for dispatch latency.
     *
     * @see #batchSizeHistView()
     */
    public BPFHistogram dispatchLatencyHistView() { return dispatchLatencyUsHist; }

    /**
     * Test seam. Returns the {@link BPFHistogram} for queue depth.
     *
     * @see #batchSizeHistView()
     */
    public BPFHistogram queueDepthHistView()      { return queueDepthHist; }

    /**
     * Test seam. Returns the {@link BPFHistogram} for ring-consume durations.
     *
     * @see #batchSizeHistView()
     */
    public BPFHistogram ringConsumeHistView()     { return ringConsumeUsHist; }

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
     * {@link SchedulerBase#init()} already creates {@code SHARED_DSQ_ID}; this just
     * attaches to it without emitting a second {@code scx_bpf_create_dsq} call.
     */
    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

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

    // ─── Java-side testability seams ─────────────────────────────
    //
    // These protected methods are the ONLY way UserspaceScheduler should touch
    // frameworkPids, kswapdPid, and khugepageDPid. Tests override them with
    // in-heap fakes so the real UserspaceScheduler logic runs without a live
    // BPF file descriptor.

    /**
     * Test seam. Production code routes BPF map writes through this method so
     * tests can override it with an in-heap fake. Not part of the user-facing API.
     *
     * <p>Public to allow cross-package access from
     * {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler}, which holds
     * a {@code UserspaceSchedulerBase} reference and is not a subclass.
     */
    public void putFrameworkPid(int pid) {
        frameworkPids.put(pid, (byte) 1);
    }

    /**
     * Test seam. Production code routes BPF map reads through this method so
     * tests can override it with an in-heap fake. Not part of the user-facing API.
     *
     * <p>Public to allow cross-package access from
     * {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler}, which holds
     * a {@code UserspaceSchedulerBase} reference and is not a subclass.
     */
    public Iterable<Map.Entry<Integer, Byte>> frameworkPidsIterable() {
        return frameworkPids;
    }

    /**
     * Test seam. Production code routes BPF global writes through this method so
     * tests can override it with an in-heap fake. Not part of the user-facing API.
     *
     * <p>Public to allow cross-package access from
     * {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler}, which holds
     * a {@code UserspaceSchedulerBase} reference and is not a subclass.
     */
    public void setKswapdPid(int pid) {
        kswapdPid.set(pid);
    }

    /**
     * Test seam. Production code routes BPF global writes through this method so
     * tests can override it with an in-heap fake. Not part of the user-facing API.
     *
     * <p>Public to allow cross-package access from
     * {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler}, which holds
     * a {@code UserspaceSchedulerBase} reference and is not a subclass.
     */
    public void setKhugepageDPid(int pid) {
        khugepageDPid.set(pid);
    }

    // ─── sched_ext ops ───────────────────────────────────────────

    /**
     * Creates the shared DSQ and arms the heartbeat timer.
     *
     * <p>Inlined SchedulerBase.init() body until super.init() lowering is fixed (see project memory: super.init() lowers to circular self-reference in struct_ops entry).
     * {@link #shared} uses {@link DispatchQueue#attach} so SHARED_DSQ_ID must be
     * created explicitly here.  {@link #framework} uses {@code new DispatchQueue(FRAMEWORK_DSQ)}
     * which causes the {@code @BPFAbstraction} processor to auto-inject
     * {@code scx_bpf_create_dsq(FRAMEWORK_DSQ, -1)} at the very top of the
     * generated {@code sched_init} body — so we must NOT call it again here.
     */
    @Override
    public int init() {
        // Create the shared DSQ.  The framework DSQ is already created by the
        // auto-injected @BPFAbstraction constructor code for `framework`.
        int rc = scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        if (rc != 0) return rc;
        // Pre-allocate the idle-mask arena page so the verifier tracks the
        // resulting pointer as a valid arena pointer (not a scalar cast).
        idleMaskBase = bpfArenaAllocPages(idleMask, null, 1, MmConstants.NUMA_NO_NODE, 0);
        if (idleMaskBase == null) {
            return -12;  // -ENOMEM — refuse to attach without idle bitmap
        }
        return initHeartbeat();
    }

    /**
     * Idle short-circuit: when the kernel reports a known-idle CPU, pre-dispatch
     * straight to {@code SCX_DSQ_LOCAL} and skip Java entirely. Mirrors
     * rustland's selectCPU behaviour. Falls back to "let {@link #enqueue} ship
     * to Java" when no idle CPU is available.
     *
     * <p>Increments {@code STAT_IDLE_FAST_PATH} when the idle path is taken,
     * per spec §2 lines 232-240.
     */
    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL.value(), SCX_SLICE_DFL.value(), 0);
            incStat(STAT_IDLE_FAST_PATH, 1);
        }
        return cpu;
    }

    /**
     * Route the task to the correct destination DSQ.
     *
     * <p>Framework threads (PIDs in {@link #frameworkPids}) go straight to
     * {@link #framework} with priority. Per-CPU kthreads and well-known mm
     * helpers (kswapd, khugepaged) bypass userspace via the kthread fast path.
     * All other tasks are published to Java via the {@link #queued} ring-buf.
     */
    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        int pid = p.val().pid;
        if (frameworkPids.bpf_get(pid) != null) {
            framework.insertScaled(p, EnqFlags.passThrough(enq_flags));
            incStat(STAT_FRAMEWORK_ENQUEUES, 1);
            return;
        }
        // Kthread fast path: per-CPU kernel threads and the well-known mm
        // helpers (kswapd, khugepaged) bypass userspace and go straight to
        // the task's last CPU to avoid latency from the userspace round-trip.
        boolean isPerCpuKthread = (p.val().flags & PerProcessFlags.PF_KTHREAD) != 0
                                  && p.val().nr_cpus_allowed == 1;
        if (isPerCpuKthread || pid == kswapdPid.get() || pid == khugepageDPid.get()) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON.value() | scx_bpf_task_cpu(p),
                               SCX_SLICE_DFL.value(), enq_flags);
            return;
        }
        lastEnqueueNs.set(currentNs());
        Ptr<TaskCtx> tctx = taskCtx.bpf_get(p);
        if (tctx != null) tctx.val().enqCnt += 1;
        Ptr<QueuedTaskCtx> evt = queued.reserve();
        if (evt == null) {
            incStat(STAT_CONGESTION_EVENTS, 1);
            shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
            return;
        }
        fillQueuedCtx(evt, p, enq_flags);     // copies enqCnt from tctx
        if (nrUserPending.get() > 0) queued.submitNoWakeup(evt);
        else                         queued.submit(evt);
        incStat(STAT_NR_QUEUED, 1);
    }

    /**
     * Populate a ring-buf record from the task and its per-task storage.
     *
     * <p>Copies timing counters from {@link TaskCtx} if available, then fills
     * weight, vtime and comm directly from {@code task_struct}. When {@code tctx}
     * is null (first observation of this task), the timing fields ({@code startTs},
     * {@code stopTs}, {@code execRuntime}, {@code enqCnt}) are left zero-initialised
     * by the BPF verifier.
     */
    @BPFFunction
    void fillQueuedCtx(Ptr<QueuedTaskCtx> evt, Ptr<task_struct> p, long enq_flags) {
        evt.val().pid           = p.val().pid;
        evt.val().prevCpu       = scx_bpf_task_cpu(p);
        evt.val().nrCpusAllowed = p.val().nr_cpus_allowed;
        evt.val().flags         = enq_flags;
        Ptr<TaskCtx> tctx = taskCtx.bpf_get(p);
        if (tctx != null) {
            evt.val().startTs     = tctx.val().startTs;
            evt.val().stopTs      = tctx.val().stopTs;
            evt.val().execRuntime = tctx.val().execRuntime;
            evt.val().enqCnt      = tctx.val().enqCnt;
        }
        evt.val().weight = p.val().scx.weight;
        evt.val().vtime  = p.val().scx.dsq_vtime;
        bpf_probe_read_kernel_str(evt.val().comm, p.val().comm);
    }

    /**
     * Drain decisions from Java and dispatch tasks.
     *
     * <p>Priority order: (1) framework DSQ, (2) user ring-buf drain, (3) stall
     * fallback to SHARED_DSQ when Java is silent too long (Task 6).
     */
    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        // 1. Framework DSQ first — unbounded priority
        if (framework.moveToLocal()) return;

        // 2. Drain Java decisions — pass null ctx; dispatchOne checks
        // scx_bpf_dispatch_nr_slots() internally per iteration (mirrors rustland).
        // Explicit lambda param types force Ctx=Integer so javac does not infer Object.
        int drained = dispatched.drain(
                (Ptr<DispatchedTaskCtx> d, Ptr<Integer> ctx) -> dispatchOne(d), null);
        if (drained > 0) {
            lastUserDispatchNs.set(currentNs());
            return;
        }
        long now = currentNs();
        if (lastEnqueueNs.get() > lastUserDispatchNs.get() &&
            now - lastUserDispatchNs.get() > STALL_FALLBACK_NS) {
            if (shared.moveToLocal()) {
                incStat(STAT_KERNEL_DISPATCHES, 1);
                return;
            }
        }
    }

    /**
     * Drain callback: dispatch one record from the user→kernel ring-buf.
     *
     * <p>Returns 0 to continue draining, 1 to stop (no dispatch slots left).
     * Stale dispatches (enqCnt mismatch) are cancelled early: the task ref is
     * released, STAT_BOUNCED_DISPATCHES is incremented, and the remaining-slots
     * check determines whether to stop.
     */
    @BPFFunction
    int dispatchOne(Ptr<DispatchedTaskCtx> d) {
        Ptr<task_struct> p = bpf_task_from_pid(d.val().pid);
        if (p == null) { incStat(STAT_BOUNCED_DISPATCHES, 1); return 0; }
        Ptr<TaskCtx> tctx = taskCtx.bpf_get(p);
        if (tctx != null && tctx.val().enqCnt != d.val().enqCnt) {
            bpf_task_release(p);
            incStat(STAT_BOUNCED_DISPATCHES, 1);
            return scx_bpf_dispatch_nr_slots() == 0 ? 1 : 0;
        }
        long slice = d.val().sliceNs == 0 ? DEFAULT_SLICE_NS : d.val().sliceNs;
        int targetCpu = d.val().targetCpu;
        if (targetCpu < 0) {                                // ANY_CPU sentinel
            scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, d.val().flags);
            DispatchQueue.kickCpu(scx_bpf_task_cpu(p), KickFlags.idle());
        } else {
            if (!bpf_cpumask_test_cpu(targetCpu, p.directVal().cpus_ptr)) {
                targetCpu = scx_bpf_task_cpu(p);
                incStat(STAT_BOUNCED_DISPATCHES, 1);
            }
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON.value() | targetCpu, slice, d.val().flags);
        }
        bpf_task_release(p);
        incStat(STAT_USER_DISPATCHES, 1);
        return scx_bpf_dispatch_nr_slots() == 0 ? 1 : 0;
    }

    /**
     * Keep the idle-CPU bitmap ({@link #idleMask}) current.
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
     * <p>BPF timer ABI requires three arguments: map, key, and value.
     */
    @BPFTimer
    @BPFFunction
    int heartbeatTick(Ptr<?> map, Ptr<Integer> key, Ptr<HeartbeatVal> val) {
        DispatchQueue.kickCpu(schedulerCpu.get(), KickFlags.idle());
        incStat(Stats.HEARTBEAT_KICKS, 1);
        bpf_timer_start(Ptr.of(val.val().timer), HEARTBEAT_NS, 0);
        return 0;
    }

    /**
     * Initialise and arm the heartbeat timer from slot 0 of {@link #heartbeat}.
     * Called from {@link #init()} after DSQ creation.
     *
     * <p>Uses {@code CLOCK_MONOTONIC} (clock id 1). {@code bpf_timer_init} needs a
     * pointer to the owning map ({@code &heartbeat}) so the kernel can hold a
     * reference; the {@code Ptr.of(heartbeat)} expression lowers to {@code &heartbeat}.
     *
     * @return 0 on success, negative errno on failure
     */
    @BPFFunction
    int initHeartbeat() {
        int zero = 0;
        Ptr<HeartbeatVal> v = heartbeat.bpf_get(zero);
        if (v == null) return -1;
        bpf_timer_init(Ptr.of(v.val().timer), Ptr.of(heartbeat), 1 /* CLOCK_MONOTONIC */);
        BPFJ.bpf_timer_set_callback(Ptr.of(v.val().timer), this::heartbeatTick);
        bpf_timer_start(Ptr.of(v.val().timer), HEARTBEAT_NS, 0);
        return 0;
    }

    // ─── Fork tracepoint ─────────────────────────────────────────

    /**
     * Context type for the {@code sched/sched_process_fork} tracepoint.
     *
     * <p>Field names and layout are taken verbatim from the running kernel:
     * {@code /sys/kernel/debug/tracing/events/sched/sched_process_fork/format}.
     *
     * <p>Note: {@code parent_comm} and {@code child_comm} are {@code __data_loc char[]}
     * fields in the kernel, encoded as a 32-bit offset/length value — represented here
     * as {@code int} so the struct layout matches.
     */
    @Type
    record TracepointSchedProcessFork(
            @Unsigned short common_type,
            byte common_flags,
            byte common_preempt_count,
            int common_pid,
            int parent_comm,   // __data_loc char[] — encoded as 32-bit data_loc value
            int parent_pid,
            int child_comm,    // __data_loc char[] — encoded as 32-bit data_loc value
            int child_pid
    ) {}

    /**
     * Tracepoint fired on every {@code fork(2)} / {@code clone(2)}.
     *
     * <p>When the forking task belongs to the scheduler process (its TGID equals
     * {@link #schedulerTgid}), the new child PID is inserted into {@link #frameworkPids}
     * so the BPF {@link #enqueue} path routes it to {@link #framework} instead of
     * serialising it through the userspace ring buffer.
     *
     * <p>On this kernel, {@code sched_process_fork} only exports {@code parent_pid} and
     * {@code child_pid}; there are no separate tgid fields. Because the tracepoint is
     * emitted at the parent thread level, {@code parent_pid} equals the parent's tgid
     * (i.e., the scheduler process TGID) for the relevant fork events.
     */
    @Tracepoint(category = "sched", name = "sched_process_fork")
    int onFork(Ptr<TracepointSchedProcessFork> ctx) {
        if (ctx.val().parent_pid == schedulerTgid.get()) {
            byte one = 1;
            frameworkPids.bpf_put(ctx.val().child_pid, one);
        }
        return 0;
    }

    // ─── BPF-side stat and bitmap helpers ────────────────────────

    /**
     * Atomically increment {@code stats} counter at {@code slot} by {@code delta}.
     *
     * <p>Slot indices are defined in {@link Stats}; slot numbering is an ABI contract.
     * Lowers to a {@code __sync_fetch_and_add} on the corresponding {@code long} field
     * of the single {@link SchedStats} record at index 0 of the {@link #stats} array.
     *
     * <p>Spec §"BPF-side stat and bitmap helpers" lines 1341-1347.
     *
     * @param slot  counter slot (1–12, see {@link Stats})
     * @param delta amount to add (typically 1)
     */
    @BPFFunction
    void incStat(int slot, long delta) {
        Ptr<SchedStats> s = stats.bpf_get(0);
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
        Ptr<SchedStats> s = stats.bpf_get(0);
        if (s == null) return;
        long offset = (long)(slot - 1) * 8L;
        Ptr<Long> fieldPtr = s.<Byte>cast().add(offset).<Long>cast();
        sync_fetch_and_add(fieldPtr, -delta);
    }

    /**
     * Atomically set or clear bit {@code cpu} in the idle-CPU bitmap.
     *
     * <p>Bit {@code cpu} lives in word {@code cpu / 64} at bit position
     * {@code cpu & 63}. Uses non-atomic compound assignment (|= / &=) because BPF
     * does not allow {@code BPF_ATOMIC} instructions on arena (address-space 1)
     * pointers. Correctness holds because each CPU only modifies its own bit, so
     * there is no intra-BPF write-write race to the same word.
     *
     * <p>The bitmap is stored in {@link #idleMask}, a {@code BPFArena} mmap'd
     * from Java (zero-syscall reads via {@link me.bechberger.ebpf.bpf.map.BPFArena#userView()}).
     * The {@link #idleMaskBase} pointer is pre-allocated in {@link #init()} via
     * {@code bpf_arena_alloc_pages} so the BPF verifier tracks it as a valid
     * arena pointer (not a scalar).
     *
     * @param cpu   CPU number (must be in [0, {@link #MAX_CPUS}))
     * @param idle  {@code true} to mark idle (set bit), {@code false} to mark busy (clear bit)
     */
    @BPFFunction
    void setBit(int cpu, boolean idle) {
        if (cpu >= MAX_CPUS) return;             // bounded write
        if (idleMaskBase == null) return;        // init() not yet completed
        long wordIdx = cpu / 64;
        long mask = 1L << (cpu & 63);
        // Non-atomic compound assignment: BPF does not allow BPF_ATOMIC on arena
        // (address-space 1) pointers. Each CPU only writes its own bit, so there is
        // no intra-BPF write-write race and non-atomic ops are safe.
        @InArena Ptr<Long> word = idleMaskBase.add(wordIdx);
        if (idle) word.set(word.val() | mask);
        else      word.set(word.val() & ~mask);
    }

    // ─── Wire offsets for DispatchedTaskCtx (Java→BPF) ────────────
    // Layout: int pid(0), int targetCpu(4), long flags(8), long sliceNs(16),
    //         long vtime(24), long enqCnt(32) — total 40 bytes.
    private static final long DTC_PID        = 0;
    private static final long DTC_TARGET_CPU = 4;
    private static final long DTC_FLAGS      = 8;
    private static final long DTC_SLICE_NS   = 16;
    private static final long DTC_VTIME      = 24;
    private static final long DTC_ENQ_CNT    = 32;

    // ─── Java-callable BPF helpers ───────────────────────────────

    /**
     * Ask the kernel for a recommended CPU for {@code pid} given hint {@code prevCpu}.
     *
     * <p>Looks up the task by PID via {@code bpf_task_from_pid}, calls
     * {@code scx_bpf_select_cpu_dfl} with the provided wake flags, then releases the
     * task reference before returning. The {@code found} pointer is a local bool so
     * the verifier tracks it as a valid non-null pointer.
     *
     * <p>Returns {@code prevCpu} if the task with {@code pid} has already exited, or
     * if the kernel has no idle CPU recommendation ({@code scx_bpf_select_cpu_dfl}
     * sets {@code found = false}).
     *
     * @param pid       target task PID
     * @param prevCpu   previous / hint CPU
     * @param wakeFlags {@code SCX_WAKE_*} flags as provided by the kernel
     * @return the kernel-recommended CPU if an idle CPU was found, or {@code prevCpu}
     *         if the task is gone or the kernel has no idle CPU recommendation
     */
    @BPFFunction
    public int selectCpuFor(int pid, int prevCpu, long wakeFlags) {
        Ptr<task_struct> task = bpf_task_from_pid(pid);
        if (task == null) return prevCpu;
        boolean found = false;
        int cpu = scx_bpf_select_cpu_dfl(task, prevCpu, wakeFlags, Ptr.of(found));
        bpf_task_release(task);
        return found ? cpu : prevCpu;
    }

    /**
     * Reserve a slot in the {@link #dispatched} user→kernel ring buffer, write a
     * {@link DispatchedTaskCtx} record, and submit it.
     *
     * <p>Called from the Java run loop after {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#policy}
     * returns a decision. The BPF {@link #dispatchOne} drain callback reads this record.
     *
     * @param targetCpu target CPU, or {@link #ANY_CPU} ({@code -1}) for SHARED_DSQ
     * @param pid       task PID
     * @param enqCnt    enqueue-counter copied from the task; enables stale-dispatch detection
     * @param sliceNs   time-slice in nanoseconds; 0 means "use framework default"
     * @param vtime     virtual time; 0 means "monotonic order"
     * @return 0 on success, {@code -1} if the ring buffer is full (reserve returned null)
     */
    public int submitDispatchDecision(int targetCpu, int pid, long enqCnt, long sliceNs, long vtime) {
        MemorySegment slot = dispatched.reserve();
        if (slot == null) return -1;
        slot.set(ValueLayout.JAVA_INT,  DTC_PID,        pid);
        slot.set(ValueLayout.JAVA_INT,  DTC_TARGET_CPU, targetCpu);
        slot.set(ValueLayout.JAVA_LONG, DTC_FLAGS,      0L);
        slot.set(ValueLayout.JAVA_LONG, DTC_SLICE_NS,   sliceNs);
        slot.set(ValueLayout.JAVA_LONG, DTC_VTIME,      vtime);
        slot.set(ValueLayout.JAVA_LONG, DTC_ENQ_CNT,    enqCnt);
        dispatched.submit(slot);
        return 0;
    }

    // ─── Java-side stat readers ───────────────────────────────────

    /**
     * Read a single {@link SchedStats} counter by 1-based slot index.
     * Performs a {@code bpf_map_lookup_elem} syscall — acceptable on the cold path only.
     *
     * @param statSlot 1-based slot index (see {@link Stats})
     * @return counter value, or 0 if the stats array is unavailable
     */
    public long readStat(int statSlot) {
        SchedStats s = stats.get(0);
        if (s == null) return 0L;
        return switch (statSlot) {
            case Stats.ONLINE_CPUS          -> s.onlineCpus();
            case Stats.RUNNING_TASKS        -> s.runningTasks();
            case Stats.NR_QUEUED            -> s.nrQueued();
            case Stats.NR_SCHEDULED         -> s.nrScheduled();
            case Stats.USER_DISPATCHES      -> s.userDispatches();
            case Stats.KERNEL_DISPATCHES    -> s.kernelDispatches();
            case Stats.BOUNCED_DISPATCHES   -> s.bouncedDispatches();
            case Stats.CANCELLED_DISPATCHES -> s.cancelledDispatches();
            case Stats.CONGESTION_EVENTS    -> s.congestionEvents();
            case Stats.FRAMEWORK_ENQUEUES   -> s.frameworkEnqueues();
            case Stats.POLICY_EXCEPTIONS    -> s.policyExceptions();
            case Stats.IDLE_FAST_PATH       -> s.idleFastPath();
            case Stats.HEARTBEAT_KICKS      -> s.heartbeatKicks();
            default -> 0L;
        };
    }

    /** Cumulative tasks enqueued by BPF into the kernel→user ring buffer. */
    public long readRingEnqueued()   { return readStat(Stats.NR_QUEUED); }
    /** Cumulative times BPF saw the ring buffer full and fell back to SHARED_DSQ. */
    public long readRingDropped()    { return readStat(Stats.CONGESTION_EVENTS); }
    /** Cumulative dispatch records discarded due to stale {@code enqCnt}. */
    public long readRingCanceled()   { return readStat(Stats.CANCELLED_DISPATCHES); }
    /** Cumulative tasks rescued by the 50 ms stall-fallback path. */
    public long readStallFallbacks() { return readStat(Stats.KERNEL_DISPATCHES); }
    /** Cumulative heartbeat timer ticks that issued a CPU kick. */
    public long readHeartbeatKicks() { return readStat(Stats.HEARTBEAT_KICKS); }

    /**
     * Return a read-only view of the idle-CPU bitmap mmap'd from the {@link #idleMask} arena.
     * Word {@code i} covers CPUs {@code [64*i .. 64*i+63]}; bit {@code cpu & 63} is set when
     * the CPU is idle. This is a zero-syscall read path after the first {@code userView()} call.
     */
    public MemorySegment idleMaskView() {
        return idleMask.userView();
    }
}
