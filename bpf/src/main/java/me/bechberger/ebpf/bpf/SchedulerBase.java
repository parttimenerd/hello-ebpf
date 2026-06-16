// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.runtime.ScxDefinitions.scx_exit_kind;
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
 * <p>After {@link #runSchedulerLoop()} returns, call {@link #getExitKind()} to find out
 * why the scheduler stopped ({@code SCX_EXIT_DONE} for clean shutdown,
 * {@code SCX_EXIT_ERROR*} for failures, etc.) and {@link #getExitCode()} for the raw
 * {@code scx_exit_code} bits.  Override {@link #onSchedulerExit(scx_exit_kind, long)} to
 * react to specific exit reasons inline.
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

    /** Populated by {@link #exit(Ptr)} when the scheduler is unloaded; 0 = not yet set. */
    final GlobalVariable<@Unsigned Integer> _exitKind = new GlobalVariable<>(0);

    /** Raw {@code exit_code} from {@link ScxDefinitions#scx_exit_info}; populated by {@link #exit(Ptr)}. */
    final GlobalVariable<Long> _exitCode = new GlobalVariable<>(0L);

    /**
     * Creates the shared DSQ on the local NUMA node.
     * Override to create additional DSQs or pin to a specific node.
     */
    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    /**
     * Captures exit kind and code into globals so they are readable from Java after the
     * scheduler unloads.  Override and call {@code super.exit(ei)} to add custom cleanup.
     */
    @Override
    public void exit(Ptr<ScxDefinitions.scx_exit_info> ei) {
        _exitKind.set(ei.val().kind.value());
        _exitCode.set(ei.val().exit_code);
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
     * Returns the exit kind recorded when the scheduler last stopped, or
     * {@link scx_exit_kind#SCX_EXIT_NONE} if the scheduler has not yet exited.
     * Call after {@link #runSchedulerLoop()} returns.
     */
    public scx_exit_kind getExitKind() {
        int raw = _exitKind.get();
        for (var kind : scx_exit_kind.values()) {
            if (kind.value() == raw) return kind;
        }
        return scx_exit_kind.SCX_EXIT_NONE;
    }

    /**
     * Returns the raw {@code exit_code} from {@code scx_exit_info}.
     * Combine with {@link #getExitKind()} to diagnose unexpected exits.
     */
    public long getExitCode() {
        return _exitCode.get();
    }

    /**
     * Called by {@link #runSchedulerLoop()} after the scheduler detaches.  Override to
     * react to specific exit reasons.
     *
     * <p>Default implementation: logs a warning when the exit kind indicates an error.
     *
     * @param kind     exit reason enum value
     * @param exitCode raw exit code bits
     */
    public void onSchedulerExit(scx_exit_kind kind, long exitCode) {
        if (kind.value() >= scx_exit_kind.SCX_EXIT_ERROR.value()) {
            System.err.println("[sched-ext] Scheduler exited with error: " + kind + " (code=0x" + Long.toHexString(exitCode) + ")");
        }
    }

    /**
     * Attaches the scheduler, blocks until it detaches, then calls
     * {@link #onSchedulerExit(scx_exit_kind, long)} with the captured exit info.
     */
    @Override
    public void runSchedulerLoop() {
        attachScheduler();
        waitWhileSchedulerIsAttachedProperly();
        onSchedulerExit(getExitKind(), getExitCode());
    }
}

