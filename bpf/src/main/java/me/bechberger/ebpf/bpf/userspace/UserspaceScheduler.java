// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import me.bechberger.ebpf.bpf.map.BPFHistogram;
import me.bechberger.ebpf.bpf.map.SegmentCallback;
import me.bechberger.ebpf.bpf.userspace.jfr.BatchEvent;
import me.bechberger.ebpf.bpf.userspace.jfr.DispatchEvent;
import me.bechberger.ebpf.bpf.userspace.jfr.TickEvent;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Base class for user-defined sched_ext schedulers whose policy lives in Java.
 *
 * <p>Subclass and override {@link #policy} (per-task) or {@link #tick} (per-heartbeat).
 * Call {@link #runUntilExit(Opts)} from your {@code main}.
 *
 * <p>The BPF transport ({@link UserspaceSchedulerBase}) is loaded automatically; you
 * never touch it directly. All scheduling decisions flow through this class.
 *
 * <h2>Threading</h2>
 * <p>{@code runUntilExit} blocks the calling thread. {@code policy} and {@code tick}
 * are all called on that thread — they must not block on external I/O.
 *
 * <h2>Cancellation</h2>
 * <p>{@link #requestExit} from any thread; the loop returns at the next batch boundary.
 */
public abstract class UserspaceScheduler {

    /** Sentinel returned by {@link #policy} to mean "let BPF pick any idle CPU". */
    public static final int ANY_CPU = -1;

    private static final long BYTES_PER_MIB = 1024L * 1024L;
    private static final long TICK_PERIOD_NS = 1_000_000_000L;

    private final AtomicBoolean exitRequested = new AtomicBoolean(false);
    private final AtomicBoolean hasExited     = new AtomicBoolean(false);
    /** Set by {@link #runLoop} just before it returns so {@link #runUntilExit} can log why. */
    private volatile ExitCause exitCause = ExitCause.NOT_EXITED;
    private Opts opts = Opts.defaults();

    /** Why {@link #runLoop} returned. Used by the exit diagnostic in {@link #runUntilExit}. */
    public enum ExitCause {
        NOT_EXITED,
        /** {@link #requestExit} was called from another thread. */
        REQUESTED,
        /** {@link #isAttached} returned false — kernel detached the scheduler (watchdog, error, etc.). */
        DETACHED
    }

    private long sRingDrained;     // tasks successfully consumed from kernel→user ringbuf
    private long sDispatched;
    private long sDispatchFailed;

    // Cached BPF-side counters, populated by cleanupBpf() before close so that
    // stats() returns meaningful values after runUntilExit() has returned.
    private long cachedRingEnqueued;
    private long cachedRingDropped;
    private long cachedRingCanceled;
    private long cachedStallFallbacks;
    private long cachedHeartbeatKicks;

    /** Task pool — package-private so test subclasses can seed fake tasks via {@link #drainRaw()}. */
    QueuedTask[] taskPool;

    /** Batch context — package-private so test overrides of {@link #drainRaw()} can set the count. */
    final BatchCtx batchCtx = new BatchCtx();

    static final class BatchCtx {
        int count;
    }

    private final AtomicInteger cpuCursor = new AtomicInteger(0);
    /** CPU count cached once at construction; avoids per-call syscall in {@link #pickIdleCpu}. */
    private final int nrCpus = Runtime.getRuntime().availableProcessors();

    /** Timestamp of the last /proc/self/task rescan (nanoseconds, from System.nanoTime()). */
    private long lastRescanNs;

    // ── hoisted drain callback (avoids lambda allocation on hot path) ─────────
    private final SegmentCallback drainCallback = (seg, size, ctx) -> {
        BatchCtx bc = (BatchCtx) ctx;
        if (bc.count >= opts.batchSize) return 1; // stop — budget exhausted
        QueuedTask.fillFromSegment(seg, taskPool[bc.count++]);
        sRingDrained++;
        return 0;
    };

    // ── user overrides ───────────────────────────────────────────────────────

    /**
     * Per-task scheduling decision.
     *
     * <p>Return a CPU number to pin the task to that CPU, or {@link #ANY_CPU} to
     * let BPF pick any idle CPU. Default: {@link #ANY_CPU}.
     *
     * <p>Must not block. Called on the run-loop thread.
     */
    protected int policy(QueuedTask t) { return ANY_CPU; }

    /**
     * Called once per heartbeat (approximately every second).
     * Default: no-op. Override for periodic housekeeping.
     */
    protected void tick() {}

    /**
     * Called when {@link #policy} throws. Default: print to stderr and continue.
     * Override to apply custom error handling or rethrow to abort.
     */
    protected void onPolicyException(QueuedTask t, Throwable ex) {
        System.err.println("[sched] policy() threw for pid=" + t.pid + ": " + ex);
    }

    // ── public API ───────────────────────────────────────────────────────────

    /**
     * Load the BPF program, attach as struct_ops, and run the dispatch loop until
     * {@link #requestExit()} or the kernel detaches us.
     *
     * @param opts tunables — pass {@link Opts#defaults()} if you have no overrides
     * @throws UserspaceSchedulerStartupException if BPF load or scheduler attach fails
     */
    public final void runUntilExit(Opts opts) {
        this.opts = opts;
        loadAndAttachBpf();
        // loadAndAttachBpf has already seeded kernel-thread PIDs and done the
        // initial /proc/self/task rescan; the next periodic rescan happens on
        // schedule (opts.frameworkPidRescan after the one done in load).
        // Allocate the task pool after BPF load so the handle is available.
        taskPool = new QueuedTask[opts.batchSize];
        for (int i = 0; i < taskPool.length; i++) taskPool[i] = new QueuedTask();
        try {
            runLoop();
        } finally {
            logExitDiagnostic();
            hasExited.set(true);
            cleanupBpf();
        }
    }

    /**
     * Why {@link #runLoop} returned, or {@link ExitCause#NOT_EXITED} if it hasn't.
     * Visible to tests that need to assert on the exit cause.
     */
    public final ExitCause exitCause() {
        return exitCause;
    }

    /**
     * Print a single-line diagnostic explaining why the run loop returned. Called from
     * {@link #runUntilExit}'s {@code finally} so callers don't get a silent exit when
     * the kernel detaches us. Reads the SCX exit code from BPF before {@link #cleanupBpf}
     * nulls the handle.
     */
    private void logExitDiagnostic() {
        long scxExitCode = 0L;
        String schedName = "?";
        String opsContent = "?";
        if (bpfHandle != null) {
            try { scxExitCode = bpfHandle.getExitCode(); } catch (Exception ignored) {}
            try { schedName = bpfHandle.getSchedulerName(); } catch (Exception ignored) {}
        }
        try {
            opsContent = java.nio.file.Files.readString(
                    java.nio.file.Path.of("/sys/kernel/sched_ext/root/ops")).trim();
        } catch (Exception e) {
            opsContent = "<read-failed: " + e.getClass().getSimpleName() + ">";
        }
        System.err.printf("[sched] runLoop exited: cause=%s scxExitCode=0x%x schedName=%s opsFile=%s %s%n",
                exitCause, scxExitCode, schedName, opsContent, formatStats());
    }

    /** Ask the run loop to exit at the next batch boundary. Safe from any thread. */
    public final void requestExit() {
        exitRequested.set(true);
    }

    /** True once {@link #runUntilExit} has returned. */
    public final boolean exited() {
        return hasExited.get();
    }

    /**
     * Snapshot of counters accumulated since {@link #runUntilExit} was called.
     * Java-side counters ({@code ringDrained}, {@code dispatched}, {@code dispatchFailed})
     * are always populated. BPF-side counters are zero when {@code bpfHandle} is
     * {@code null} (e.g. before {@code runUntilExit} is called, in tests that inject
     * only the dispatch seam, or after the run loop returns).
     */
    public SchedStatsSnapshot stats() {
        long ringEnqueued    = bpfHandle != null ? bpfHandle.readRingEnqueued()    : cachedRingEnqueued;
        long ringDropped     = bpfHandle != null ? bpfHandle.readRingDropped()     : cachedRingDropped;
        long ringCanceled    = bpfHandle != null ? bpfHandle.readRingCanceled()    : cachedRingCanceled;
        long stallFallbacks  = bpfHandle != null ? bpfHandle.readStallFallbacks()  : cachedStallFallbacks;
        long heartbeatKicks  = bpfHandle != null ? bpfHandle.readHeartbeatKicks()  : cachedHeartbeatKicks;
        return new SchedStatsSnapshot(
            ringEnqueued, ringDropped, sRingDrained, ringCanceled,
            sDispatched, sDispatchFailed, stallFallbacks, heartbeatKicks);
    }

    // ── hooks (overridable for testing) ──────────────────────────────────────

    /**
     * Load the BPF program and attach it as a struct_ops scheduler.
     *
     * <p>The default implementation calls {@link BPFProgram#load} on
     * {@link UserspaceSchedulerBase} then {@code attachScheduler()}.
     * Tests override this to inject a fake/no-op transport without needing
     * a sched_ext kernel.
     *
     * @throws UserspaceSchedulerStartupException on failure
     */
    protected void loadAndAttachBpf() {
        UserspaceSchedulerBase bpf;
        try {
            bpf = BPFProgram.load(UserspaceSchedulerBase.class);
        } catch (Exception e) {
            throw new UserspaceSchedulerStartupException("BPF load failed", e);
        }
        this.bpfHandle = bpf;
        // Seed framework PIDs BEFORE attaching the scheduler. Once attached, every
        // JVM thread that blocks/wakes (GC, JIT, the run-loop thread itself) is
        // routed by BPF enqueue: framework PIDs bypass userspace; everything else
        // sits in the user ring waiting for the run-loop thread to drain it.
        // If the run-loop thread is not yet in frameworkPids and happens to block
        // on a syscall here (e.g., /proc reads, mmap), the scheduler can dead-lock
        // on itself — the drainer is the very task that needs dispatching.
        seedKernelThreadPids();
        maybeRescanFrameworkPids();
        try {
            bpf.attachScheduler();
        } catch (Exception e) {
            this.bpfHandle = null;
            bpf.close();
            throw new UserspaceSchedulerStartupException("attachScheduler failed", e);
        }
    }

    /**
     * Close / release the BPF program after the run loop exits.
     * Tests may override to skip closing a fake handle.
     */
    protected void cleanupBpf() {
        if (bpfHandle != null) {
            try {
                cachedRingEnqueued   = bpfHandle.readRingEnqueued();
                cachedRingDropped    = bpfHandle.readRingDropped();
                cachedRingCanceled   = bpfHandle.readRingCanceled();
                cachedStallFallbacks = bpfHandle.readStallFallbacks();
                cachedHeartbeatKicks = bpfHandle.readHeartbeatKicks();
            } catch (Exception ignored) {}
            try { bpfHandle.close(); } catch (Exception ignored) {}
            bpfHandle = null;
        }
    }

    /**
     * Return {@code true} while the scheduler is attached to the kernel.
     *
     * <p>Default: delegates to {@link UserspaceSchedulerBase#isSchedulerAttachedProperly()}.
     * Tests override to return a controllable value.
     */
    protected boolean isAttached() {
        return bpfHandle != null && bpfHandle.isSchedulerAttachedProperly();
    }

    /**
     * Insert {@code pid} into the framework-PID set.
     *
     * <p>Default: delegates to {@link UserspaceSchedulerBase#putFrameworkPid}.
     * Tests override to capture into an in-heap {@code Map<Integer,Byte>} so
     * the real {@link #maybeRescanFrameworkPids} logic can run without a live
     * BPF file descriptor.
     */
    protected void putFrameworkPid(int pid) {
        bpfHandle.putFrameworkPid(pid);
    }

    /**
     * Return an iterable view of the framework-PID set entries.
     *
     * <p>Default: delegates to {@link UserspaceSchedulerBase#frameworkPidsIterable}, or
     * returns an empty iterable if the BPF handle is not yet loaded.
     * Tests override to return an in-heap collection so
     * the real {@link #frameworkPidCount} logic can run without a live
     * BPF file descriptor.
     */
    protected Iterable<Map.Entry<Integer, Byte>> frameworkPidsIterable() {
        if (bpfHandle == null) return java.util.Collections.emptyList();
        return bpfHandle.frameworkPidsIterable();
    }

    /**
     * Ask the kernel for a recommended CPU for {@code pid} given hint {@code prevCpu}.
     *
     * <p>Default: delegates to {@link UserspaceSchedulerBase#selectCpuFor}.
     * Tests override to return a controllable stub result so
     * the real {@link #selectCpu} delegation logic can be verified without a live
     * BPF file descriptor.
     *
     * @param pid     target task PID
     * @param prevCpu previous / hint CPU
     * @return kernel-recommended CPU if an idle CPU was found, or {@code prevCpu}
     *         if the task is gone or the kernel has no idle CPU recommendation
     */
    protected int selectCpuFor(int pid, int prevCpu) {
        return bpfHandle.selectCpuFor(pid, prevCpu, 0L);
    }

    /**
     * BPF transport handle, exposed so tests (notably {@code UserspaceSchedulerObsBenchTest})
     * can read raw histogram maps without the public {@code printHistograms} side
     * effect. May be {@code null} before {@link #runUntilExit} is called or after
     * the run loop has returned.
     */
    public final UserspaceSchedulerBase bpf() {
        return bpfHandle;
    }

    // ── internal ─────────────────────────────────────────────────────────────

    /** BPF transport — set by {@link #loadAndAttachBpf}, cleared by {@link #cleanupBpf}. */
    UserspaceSchedulerBase bpfHandle;

    /**
     * Emit a {@link TickEvent} for the current heartbeat tick.
     *
     * <p>Called by {@link #runLoop} just before {@link #tick()}. Protected so tests
     * can call it directly without spinning up the full run loop.
     */
    protected void emitTickEvent() {
        var ev = new TickEvent();
        ev.begin();
        try {
            // no-op: timing runs over the full tick-event emission window
        } finally {
            ev.end();
            if (ev.shouldCommit()) {
                ev.heapUsedMb    = (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / BYTES_PER_MIB;
                ev.frameworkPids = (int) frameworkPidCount();
                ev.commit();
            }
        }
    }

    /**
     * Human-readable single-line stats summary, suitable for periodic stderr printing
     * from sample schedulers. Format is intentionally compact and may change.
     */
    public String formatStats() {
        var s = stats();
        return String.format(
            "drained=%d dropped=%d disp=%d/-%d cancel=%d stall=%d kicks=%d",
            s.ringDrained(), s.ringDropped(),
            s.dispatched(), s.dispatchFailed(),
            s.ringCanceled(), s.stallFallbacks(), s.heartbeatKicks());
    }

    private void runLoop() {
        long lastTickNs   = System.nanoTime();
        while (true) {
            if (exitRequested.get()) { exitCause = ExitCause.REQUESTED; break; }
            if (!isAttached())       { exitCause = ExitCause.DETACHED;  break; }
            maybeRescanFrameworkPids();
            drainBatchOnce();
            long now = System.nanoTime();
            if (now - lastTickNs >= TICK_PERIOD_NS) {
                emitTickEvent();
                try {
                    tick();
                } catch (Throwable t) {
                    System.err.println("[sched] tick() threw: " + t);
                }
                lastTickNs = now;
            }
        }
    }

    /**
     * Drain one batch of tasks from the kernel→user ring buffer ({@code queued}),
     * call {@link #policy} for each, and submit dispatch decisions back to the
     * kernel via the user→kernel ring buffer ({@code dispatched}).
     *
     * <p>If the ring buffer is empty, returns without blocking (zero-copy fast path).
     * The method is protected to allow unit tests to call it directly on a
     * fake/mocked handle without spinning up the full run loop.
     */
    protected void drainBatchOnce() {
        int drained = drainRaw();
        if (drained <= 0) return;

        recordBatchSize(batchCtx.count);

        long dispBefore = sDispatched;
        long nowNs = System.nanoTime();
        var ev = new BatchEvent();
        ev.begin();
        try {
            for (int i = 0; i < batchCtx.count; i++) {
                QueuedTask t = taskPool[i];
                int cpu;
                try {
                    cpu = policy(t);
                } catch (Throwable th) {
                    onPolicyException(t, th);
                    continue;          // skip — do NOT fall through to dispatchInternal
                }
                // Record round-trip: stopTs is the BPF ktime when the task was last
                // context-switched out, which is a close proxy for the enqueue ktime.
                // System.nanoTime() is not directly comparable with BPF ktime (which uses
                // CLOCK_MONOTONIC), but both are ns-resolution monotonic clocks and are
                // equal on most kernels. Recorded here for observability; exact semantics
                // are documented in UserspaceSchedulerBase.roundTripUsHist.
                // nowNs is hoisted out of the loop so all tasks in one batch share the
                // same "end of batch" snapshot — cheaper and more meaningful semantically.
                // The guard rejects negative deltas that can occur on clock skew or when
                // stopTs is stale (zero is already excluded by the outer check).
                if (t.stopTs > 0) {
                    long deltaUs = (nowNs - t.stopTs) / 1_000L;
                    if (deltaUs >= 0) recordRoundTrip(deltaUs);
                }
                dispatchInternal(t, cpu);
            }
        } finally {
            ev.end();
            if (ev.shouldCommit()) {
                ev.size = batchCtx.count;
                ev.dispatched = (int) (sDispatched - dispBefore);
                ev.commit();
            }
        }
    }

    /**
     * Drain raw tasks from the kernel ring buffer into {@link #taskPool}, setting
     * {@link BatchCtx#count} to the number of tasks filled.
     *
     * <p>Returns the number of tasks drained (as reported by {@code consumeRaw}),
     * or {@code <= 0} if the ring is empty. When {@code bpfHandle} is {@code null},
     * sleeps briefly to avoid busy-spinning in lifecycle tests and returns 0.
     *
     * <p>Protected for test injection: a test subclass may override this to fill
     * {@link #taskPool} with controllable {@link QueuedTask}s and return their count,
     * bypassing the real BPF ring buffer. The overriding method must also set
     * {@link BatchCtx#count} to match the number of tasks placed into the pool.
     */
    protected int drainRaw() {
        if (bpfHandle == null) {
            // No BPF handle — sleep briefly to avoid a busy spin in the lifecycle test.
            try { Thread.sleep(10); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            return 0;
        }
        batchCtx.count = 0;
        long nsBeforeConsume = System.nanoTime();
        int result = bpfHandle.queued.consumeRaw(drainCallback, batchCtx);
        long nsAfterConsume = System.nanoTime();
        recordRingConsume((nsAfterConsume - nsBeforeConsume) / 1_000L);
        return result;
    }

    /**
     * Ensure {@link #taskPool} is allocated with at least {@code minSize} entries.
     *
     * <p>Package-private for test subclasses that override {@link #drainRaw()} and
     * need to seed fake tasks before calling {@link #drainBatchOnce()} without
     * going through {@link #runUntilExit(Opts)}.
     */
    void ensureTaskPool(int minSize) {
        if (taskPool == null || taskPool.length < minSize) {
            int newSize = Math.max(minSize, opts.batchSize);
            taskPool = new QueuedTask[newSize];
            for (int i = 0; i < taskPool.length; i++) taskPool[i] = new QueuedTask();
        }
    }

    // ── Histogram recording seams (Task 14) ──────────────────────────────────
    //
    // These protected methods are the ONLY way drainBatchOnce/drainRaw should
    // write to the BPF histograms. Tests override them with in-memory counters
    // so the production recording logic runs without a live BPF file descriptor.

    /**
     * Record one batch-size sample. Called once per non-empty drain with the
     * number of tasks in the batch.
     *
     * <p>Default: delegates to {@link UserspaceSchedulerBase#batchSizeHistView()}.
     * Tests override to capture the call without a BPF fd.
     */
    protected void recordBatchSize(long value) {
        if (bpfHandle != null) bpfHandle.batchSizeHistView().increment(value);
    }

    /**
     * Record one round-trip sample in microseconds. Called once per task whose
     * {@code stopTs} is non-zero and whose delta is non-negative.
     *
     * <p>Default: delegates to {@link UserspaceSchedulerBase#roundTripHistView()}.
     * Tests override to capture the call without a BPF fd.
     */
    protected void recordRoundTrip(long usValue) {
        if (bpfHandle != null) bpfHandle.roundTripHistView().increment(usValue);
    }

    /**
     * Record one ring-consume duration sample in microseconds. Called once per
     * non-null-handle {@code drainRaw} call.
     *
     * <p>Default: delegates to {@link UserspaceSchedulerBase#ringConsumeHistView()}.
     * Tests override to capture the call without a BPF fd.
     */
    protected void recordRingConsume(long usValue) {
        if (bpfHandle != null) bpfHandle.ringConsumeHistView().increment(usValue);
    }

    // ── Histogram printing ────────────────────────────────────────────────────

    /**
     * Print all five histograms to {@code out}. Each bucket [i] represents
     * values in the half-open range [2^(i-1) .. 2^i). Zero buckets are skipped.
     *
     * <p>Public for use from sample schedulers' periodic stderr dumps; safe
     * to call from any thread. Reads via BPF map syscall — not a zero-copy path.
     */
    public void printHistograms(PrintStream out) {
        if (bpfHandle == null) return;
        out.println("== batchSize ==");
        printOne(out, bpfHandle.batchSizeHistView());
        out.println("== roundTrip us ==");
        printOne(out, bpfHandle.roundTripHistView());
        out.println("== dispatchLat us ==");
        printOne(out, bpfHandle.dispatchLatencyHistView());
        out.println("== queueDepth ==");
        printOne(out, bpfHandle.queueDepthHistView());
        out.println("== ringConsume us ==");
        printOne(out, bpfHandle.ringConsumeHistView());
    }

    private static void printOne(PrintStream out, BPFHistogram h) {
        var entries = new java.util.ArrayList<>(h.entrySet());
        entries.sort(java.util.Map.Entry.comparingByKey());
        for (var e : entries) {
            int slot = e.getKey();
            long v = e.getValue();
            if (slot >= 0 && slot < BPFHistogram.BUCKET_COUNT && v > 0) {
                out.printf("  [2^%2d ..) %d%n", slot, v);
            }
        }
    }

    /**
     * Print a histogram snapshot (a {@code Map<Integer,Long>} of bucket→count) to
     * {@code out}. Extracted so tests can call it with a controlled in-heap map
     * without needing a BPF file descriptor.
     *
     * <p>Package-private; intended for use by {@link HistogramsTest}.
     */
    static void printHistogram(PrintStream out, java.util.Map<Integer, Long> snapshot) {
        var entries = new java.util.ArrayList<>(snapshot.entrySet());
        entries.sort(java.util.Map.Entry.comparingByKey());
        for (var e : entries) {
            int slot = e.getKey();
            long v = e.getValue();
            if (slot >= 0 && slot < BPFHistogram.BUCKET_COUNT && v > 0) {
                out.printf("  [2^%2d ..) %d%n", slot, v);
            }
        }
    }

    /**
     * Route one dispatch decision to the kernel.
     *
     * <p>If {@code cpu == ANY_CPU}, scans the idle-CPU bitmap via
     * {@link #pickIdleCpu()} for a locality hint before delegating to SHARED_DSQ.
     *
     * @param t   task to dispatch
     * @param cpu policy-provided CPU, or {@link #ANY_CPU}
     */
    void dispatchInternal(QueuedTask t, int cpu) {
        var ev = new DispatchEvent();
        ev.pid = t.pid;
        ev.begin();
        int target = (cpu == ANY_CPU) ? pickIdleCpu() : cpu;
        int rc = -1;
        try {
            rc = submitDispatch(target, t.pid, t.enqCnt, 0L, t.vtime);
        } finally {
            ev.end();
            if (ev.shouldCommit()) {
                ev.cpu = target;
                ev.rc  = rc;
                ev.commit();
            }
        }
        if (rc == 0) sDispatched++;
        else         sDispatchFailed++;
    }

    /**
     * Submit one dispatch decision to the BPF transport.
     *
     * <p>Delegates to {@link UserspaceSchedulerBase#submitDispatchDecision}.
     * Overridable for tests that want to intercept submits without a real BPF handle.
     *
     * @return 0 on success, non-zero on error
     */
    protected int submitDispatch(int targetCpu, int pid, long enqCnt, long sliceNs, long vtime) {
        return bpfHandle.submitDispatchDecision(targetCpu, pid, enqCnt, sliceNs, vtime);
    }

    /**
     * Round-robin scan of the idle-CPU bitmap.
     *
     * <p>Advances an {@link AtomicInteger} cursor so successive calls spread
     * dispatches evenly across idle CPUs rather than always picking the lowest-
     * numbered idle CPU. The cursor wraps at {@code nrCpus} so no CPU is
     * permanently preferred.
     *
     * <p>The bitmap is mmap'd via {@link UserspaceSchedulerBase#idleMask} —
     * zero-syscall after the first {@code userView()} call. Each 64-bit word
     * covers 64 CPUs.
     *
     * @return an idle CPU number, or {@link #ANY_CPU} if none is currently idle
     */
    protected final int pickIdleCpu() {
        MemorySegment view = idleMaskView();
        if (view == null) return ANY_CPU;
        int start = cpuCursor.getAndIncrement() & 0x7FFFFFFF;
        for (int i = 0; i < nrCpus; i++) {
            int cpu = (start + i) % nrCpus;
            long word = view.get(ValueLayout.JAVA_LONG, (long)(cpu / 64) * 8L);
            if ((word & (1L << (cpu & 63))) != 0) return cpu;
        }
        return ANY_CPU;
    }

    /**
     * Returns the mmap'd idle-CPU bitmap segment, or {@code null} if unavailable.
     *
     * <p>Overridable for tests: a test subclass can return a heap-allocated
     * {@link MemorySegment} to exercise {@link #pickIdleCpu()} without a BPF
     * file descriptor.
     */
    protected MemorySegment idleMaskView() {
        if (bpfHandle == null) return null;
        return bpfHandle.idleMaskView();
    }

    // ── kernel-assisted CPU selection ────────────────────────────────────────

    /**
     * Ask the kernel for a recommended CPU for {@code pid} given hint {@code prevCpu}.
     *
     * <p>Delegates to {@link #selectCpuFor} which by default calls
     * {@link UserspaceSchedulerBase#selectCpuFor} on the kernel side.
     * Cheap; safe to call from {@link #policy}.
     * Returns {@code prevCpu} if the kernel has no idle CPU recommendation
     * ({@code scx_bpf_select_cpu_dfl} sets {@code found = false}) OR the task is gone.
     *
     * @param pid     target task PID
     * @param prevCpu previous / hint CPU
     * @return kernel-recommended CPU if an idle CPU was found, or {@code prevCpu}
     *         if the task is gone or the kernel has no idle CPU recommendation
     */
    public final int selectCpu(int pid, int prevCpu) {
        return selectCpuFor(pid, prevCpu);
    }

    // ── framework-PID rescan ─────────────────────────────────────────────────

    /**
     * Re-scan {@code /proc/self/task} and insert every TID into the
     * {@code frameworkPids} BPF hash map so the BPF enqueue path routes them to
     * the framework DSQ without a userspace round-trip.
     *
     * <p>Only runs if {@code opts.frameworkPidRescan} has elapsed since the last
     * scan. On the first call ({@code lastRescanNs == 0}) the scan always runs.
     *
     * <p>Errors are logged to stderr and ignored so a transient {@code /proc} race
     * never aborts the scheduler.
     */
    void maybeRescanFrameworkPids() {
        long now = System.nanoTime();
        if (now - lastRescanNs < opts.frameworkPidRescan.toNanos()) return;
        lastRescanNs = now;
        try (var stream = Files.list(Path.of("/proc/self/task"))) {
            stream.forEach(p -> {
                try {
                    int tid = Integer.parseInt(p.getFileName().toString());
                    putFrameworkPid(tid);
                } catch (NumberFormatException ignored) {}
            });
        } catch (Exception e) {
            System.err.println("[sched] /proc/self/task rescan failed: " + e);
        }
    }

    /**
     * Return the number of entries currently in the {@code frameworkPids} BPF map.
     *
     * <p>Public for tests. Returns 0 if the BPF handle is not yet loaded
     * (the default {@link #frameworkPidsIterable} returns an empty iterable when
     * {@code bpfHandle} is {@code null}).
     */
    public long frameworkPidCount() {
        long c = 0;
        for (var ignored : frameworkPidsIterable()) c++;
        return c;
    }

    // ── kernel-thread PID seeding ────────────────────────────────────────────

    /**
     * Scan {@code /proc} for kernel threads {@code kswapd*} and {@code khugepaged},
     * then write their PIDs into the BPF globals {@link UserspaceSchedulerBase#kswapdPid}
     * and {@link UserspaceSchedulerBase#khugepageDPid}.
     *
     * <p>Called once after {@link #loadAndAttachBpf()} so the kthread fast path in
     * BPF {@code enqueue} is populated before the first task arrives.
     *
     * <p>{@code /proc} races (process exits between listing and reading {@code comm})
     * are silently ignored.
     */
    private void seedKernelThreadPids() {
        if (bpfHandle == null) return;
        try (var stream = Files.list(Path.of("/proc"))) {
            stream.forEach(p -> {
                String name = p.getFileName().toString();
                int pid;
                try { pid = Integer.parseInt(name); } catch (NumberFormatException e) { return; }
                try {
                    String comm = Files.readString(p.resolve("comm")).trim();
                    if (comm.startsWith("kswapd")) {
                        bpfHandle.setKswapdPid(pid);
                    } else if (comm.equals("khugepaged")) {
                        bpfHandle.setKhugepageDPid(pid);
                    }
                } catch (java.io.IOException ignored) {
                    // /proc race: pid exited between listing and read — fine
                }
            });
        } catch (Exception e) {
            System.err.println("[sched] kernel-thread PID seeding failed: " + e);
        }
    }
}
