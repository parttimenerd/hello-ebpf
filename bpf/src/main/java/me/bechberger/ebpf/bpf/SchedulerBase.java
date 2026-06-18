// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.ScxDefinitions;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
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
 * {@code selectCpuFifoIdleOrFallback}, {@code isSmaller}, {@code vtimeEnqueue},
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


    /** Raw {@code exit_code} from {@link ScxDefinitions#scx_exit_info}; populated by {@link #exit(Ptr)}.
     *  Prefixed with {@code _} to avoid name clash with the {@code exitCode} parameter in
     *  {@link #onSchedulerExit(long)}. */
    protected final GlobalVariable<Long> _exitCode = new GlobalVariable<>(0L);

    /**
     * Creates the shared DSQ on the local NUMA node.
     * Override to create additional DSQs or pin to a specific node.
     */
    @Override
    @BPFFunction(headerTemplate = "s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init)", addDefinition = false)
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    /**
     * Captures exit code into a global so it is readable from Java after the
     * scheduler unloads.  Override and call {@code super.exit(ei)} to add custom cleanup.
     */
    @Override
    @BPFFunction(headerTemplate = "void BPF_STRUCT_OPS(sched_exit, struct scx_exit_info *ei)", addDefinition = false)
    public void exit(Ptr<ScxDefinitions.scx_exit_info> ei) {
        _exitCode.set(ei.val().exit_code);
    }

    /**
     * Moves all pending tasks from {@link #SHARED_DSQ_ID} to the current CPU's
     * local dispatch queue.
     */
    @Override
    @BPFFunction(headerTemplate = "void BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev)", addDefinition = false)
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
     * Attaches the scheduler, blocks until it detaches, then calls
     * {@link #onSchedulerExit(long)} with the captured exit code.
     */
    @Override
    public void runSchedulerLoop() {
        attachScheduler();
        waitWhileSchedulerIsAttachedProperly();
        onSchedulerExit(getExitCode());
    }
}
