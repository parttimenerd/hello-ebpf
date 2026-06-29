// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;

import java.util.concurrent.atomic.AtomicBoolean;

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
    @SuppressWarnings("unused")
    private Opts opts;

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
    private UserspaceSchedulerBase bpfHandle;

    private void runLoop() {
        long lastTickNs   = System.nanoTime();
        long tickPeriodNs = 1_000_000_000L;
        while (!exitRequested.get() && isAttached()) {
            // Drain one batch (replaced in Task 11 with real ring-buffer work).
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
     * Drain one batch of tasks from the ring buffer.
     *
     * <p>Stub — Task 11 replaces this with real ring-buffer + arena work. Until then,
     * sleeps 10 ms to yield the CPU so the loop doesn't spin at 100%.
     */
    protected void drainBatchOnce() {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
