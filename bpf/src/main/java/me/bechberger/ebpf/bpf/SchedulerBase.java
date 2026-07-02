// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.runtime.ScxDefinitions;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dsq_move_to_local;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Convenience base class for sched-ext schedulers.
 *
 * <p>Provides a pre-wired shared FIFO DSQ at {@link #SHARED_DSQ_ID}, a default
 * {@link #init()} that creates it, and a default {@link #dispatch(int, Ptr)} that
 * moves tasks from it to the local CPU queue.  Subclasses only need to implement
 * {@link Scheduler#enqueue(Ptr, long)}.
 *
 * <p>BPF-side helpers such as {@code dsqInsert}, {@code selectCpuDfl},
 * {@code selectCpuFifoIdleOrFallback}, {@code isSmaller},
 * and {@code vtimeCharge} are inherited from the {@link Scheduler} interface and
 * are available in BPF context to any class that implements {@link Scheduler}.
 *
 * <h2>Stats</h2>
 * <p>Use {@link SchedulerStats} to add per-CPU enqueue/dispatch counters with minimal
 * boilerplate.  Declare two {@code @BPFMapDefinition BPFPerCpuArray<Long>} fields
 * (e.g. {@code enqueuedCounts}, {@code dispatchedCounts}) and call
 * {@link SchedulerStats#incrementEnqueued} / {@link SchedulerStats#incrementDispatched}
 * from the BPF callbacks; read aggregate totals with
 * {@link SchedulerStats#totalEnqueued} / {@link SchedulerStats#totalDispatched}.
 *
 * <h2>Exit info</h2>
 * <p>After {@link #runSchedulerLoop()} returns, call {@link #getExitCode()} to get the
 * raw {@code scx_exit_code} bits captured from the kernel's {@code exit()} callback.
 * Override {@link #onSchedulerExit(long)} to react to specific exit codes inline.
 *
 * <p>Usage:
 * <pre>{@code
 * @BPF(license = "GPL")
 * @Property(name = "sched_name", value = "my_sched")
 * public abstract class MyScheduler extends SchedulerBase {
 *
 *     @Override
 *     public void enqueue(Ptr<task_struct> p, long enq_flags) {
 *         dsqInsert(p, enq_flags);  // insert into the shared DSQ
 *     }
 * }
 * }</pre>
 */
public abstract class SchedulerBase extends BPFProgram implements Scheduler {

    /** DSQ ID used by the pre-wired shared queue. */
    public static final long SHARED_DSQ_ID = 0;

    /** Raw {@code exit_code} populated by {@link #exit(Ptr)}.
     *  Prefixed with {@code _} to avoid name clash with the {@code exitCode} parameter in
     *  {@link #onSchedulerExit(long)}. */
    protected final GlobalVariable<Long> _exitCode = new GlobalVariable<>(0L);

    /** Raw {@code kind} from {@link ScxDefinitions.scx_exit_kind}; populated alongside {@link #_exitCode}.
     *  Zero means the kernel never called {@code exit()} (SCX_EXIT_NONE); non-zero encodes
     *  the reason (1=DONE, 64=UNREG, 66=UNREG_KERN, 1024=ERROR, 1026=ERROR_STALL, …). */
    protected final GlobalVariable<Long> _exitKind = new GlobalVariable<>(0L);

    /**
     * Default init: creates the shared FIFO DSQ.  Subclasses that override
     * {@code init()} should call {@code super.init()} first and propagate a
     * non-zero return value.
     */
    @Override
    @me.bechberger.ebpf.annotations.bpf.Sleepable
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    /**
     * Captures exit code into a global so it is readable from Java after the
     * scheduler unloads.  Override and call {@code super.exit(ei)} to add custom cleanup.
     */
    @Override
    public void exit(Ptr<ScxDefinitions.scx_exit_info> ei) {
        _exitCode.set(ei.val().exit_code);
        _exitKind.set((long) ei.val().kind.value());
    }

    /**
     * Moves all pending tasks from {@link #SHARED_DSQ_ID} to the current CPU's
     * local dispatch queue.
     */
    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    }

    // ---- Java-side exit info API ----

    /**
     * Returns the raw {@code exit_code} from {@code scx_exit_info}.
     * Non-zero typically indicates an error or a specific exit reason.
     * Call after {@link #runSchedulerLoop()} returns.
     */
    public long getExitCode() {
        return _exitCode.get();
    }

    /**
     * Returns the raw {@code kind} from {@code scx_exit_info}, populated alongside
     * {@link #getExitCode()}.  Zero means SCX_EXIT_NONE (the kernel never called
     * {@code exit()}, typically because we detached ourselves cleanly).
     * Non-zero encodes the reason: 1=DONE, 64=UNREG, 66=UNREG_KERN, 1024=ERROR, 1026=ERROR_STALL, …
     */
    public long getExitKindRaw() {
        return _exitKind.get();
    }

    /**
     * Called by {@link #runSchedulerLoop()} after the scheduler detaches.  Override to
     * react to specific exit reasons.
     *
     * <p>Default implementation: logs a warning when the exit code is non-zero.
     *
     * @param exitCode raw exit code from {@code scx_exit_info}
     */
    public void onSchedulerExit(long exitCode) {
        if (exitCode != 0) {
            System.err.println("[sched-ext] Scheduler exited with non-zero exit code: 0x" + Long.toHexString(exitCode));
        }
    }

    /**
     * Blocks until the scheduler detaches, then calls
     * {@link #onSchedulerExit(long)} with the captured exit code.
     * {@link BPFProgram#load(Class)} already attached all struct_ops automatically.
     */
    @Override
    public void runSchedulerLoop() {
        waitWhileSchedulerIsAttachedProperly();
        onSchedulerExit(getExitCode());
    }
}