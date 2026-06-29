// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import me.bechberger.ebpf.bpf.map.SegmentCallback;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
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

    private final AtomicBoolean exitRequested = new AtomicBoolean(false);
    private final AtomicBoolean hasExited     = new AtomicBoolean(false);
    private Opts opts;

    private long sRingDrained;     // tasks successfully consumed from kernel→user ringbuf
    private long sDispatched;
    private long sDispatchFailed;

    private QueuedTask[] taskPool;

    private final BatchCtx batchCtx = new BatchCtx();

    private static final class BatchCtx {
        int count;
    }

    private final AtomicInteger cpuCursor = new AtomicInteger(0);
    /** CPU count cached once at construction; avoids per-call syscall in {@link #pickIdleCpu}. */
    private final int nrCpus = Runtime.getRuntime().availableProcessors();

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
        // Allocate the task pool after BPF load so the handle is available.
        taskPool = new QueuedTask[opts.batchSize];
        for (int i = 0; i < taskPool.length; i++) taskPool[i] = new QueuedTask();
        try {
            runLoop();
        } finally {
            hasExited.set(true);
            cleanupBpf();
        }
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
        long ringEnqueued    = bpfHandle != null ? bpfHandle.readRingEnqueued()    : 0;
        long ringDropped     = bpfHandle != null ? bpfHandle.readRingDropped()     : 0;
        long ringCanceled    = bpfHandle != null ? bpfHandle.readRingCanceled()    : 0;
        long stallFallbacks  = bpfHandle != null ? bpfHandle.readStallFallbacks()  : 0;
        long heartbeatKicks  = bpfHandle != null ? bpfHandle.readHeartbeatKicks()  : 0;
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
        try {
            bpf.attachScheduler();
        } catch (Exception e) {
            bpf.close();
            throw new UserspaceSchedulerStartupException("attachScheduler failed", e);
        }
        this.bpfHandle = bpf;
    }

    /**
     * Close / release the BPF program after the run loop exits.
     * Tests may override to skip closing a fake handle.
     */
    protected void cleanupBpf() {
        if (bpfHandle != null) {
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

    // ── internal ─────────────────────────────────────────────────────────────

    /** BPF transport — set by {@link #loadAndAttachBpf}, cleared by {@link #cleanupBpf}. */
    UserspaceSchedulerBase bpfHandle;

    private void runLoop() {
        long lastTickNs   = System.nanoTime();
        long tickPeriodNs = 1_000_000_000L;
        while (!exitRequested.get() && isAttached()) {
            drainBatchOnce();
            long now = System.nanoTime();
            if (now - lastTickNs >= tickPeriodNs) {
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
     * The method is a package-private testability hook to allow unit tests to call
     * it directly on a fake/mocked handle without spinning up the full run loop.
     */
    protected void drainBatchOnce() {
        if (bpfHandle == null) {
            // No BPF handle — sleep briefly to avoid a busy spin in the lifecycle test.
            try { Thread.sleep(10); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            return;
        }
        batchCtx.count = 0;
        int drained = bpfHandle.queued.consumeRaw(drainCallback, batchCtx);
        if (drained <= 0) return;
        for (int i = 0; i < batchCtx.count; i++) {
            QueuedTask t = taskPool[i];
            int cpu;
            try {
                cpu = policy(t);
            } catch (Throwable th) {
                onPolicyException(t, th);
                continue;          // skip — do NOT fall through to dispatchInternal
            }
            dispatchInternal(t, cpu);
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
        int target = (cpu == ANY_CPU) ? pickIdleCpu() : cpu;
        int rc = submitDispatch(target, t.pid, t.enqCnt, 0L, t.vtime);
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
}
