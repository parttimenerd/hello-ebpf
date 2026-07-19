// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import me.bechberger.ebpf.bpf.userspace.Signal;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_strncmp;

/**
 * BPF-transport subclass that turns a kernel-side event into a typed {@link Signal}.
 *
 * <p>This is the {@code @BPF} half of {@link LockBoostSignalSample}. It overrides the
 * base {@link UserspaceSchedulerBase#runnable} callback — invoked by sched_ext the
 * moment a task becomes runnable — and, for tasks whose {@code comm} matches
 * {@link #WATCHED_COMM}, emits a {@link #LOCK_ACQUIRED} signal into the framework's
 * signals ring via the inherited {@link UserspaceSchedulerBase#emitSignal} kfunc-style
 * helper.
 *
 * <h2>Why a BPF subclass and not a separate companion program</h2>
 * <p>A {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler} subclass has no
 * BPF code of its own — its loaded program is the fixed {@code UserspaceSchedulerBase}.
 * To originate a signal from the kernel we must contribute a real BPF callback. Rather
 * than a second {@code @BPF} program sharing the ring by pin path (which risks the
 * verifier's "mixed program kfunc sharing" rejection), we extend the transport itself:
 * this subclass re-emits the base's complete eBPF program and adds one overridden
 * struct_ops entry. The policy side selects it via
 * {@code LockBoostSignalSample.bpfProgramClass()}.
 *
 * <p>{@code emitSignal} is inherited from {@code UserspaceSchedulerBase}; calling it
 * from an overridden callback exercises the subclass-calls-inherited-{@code @BPFFunction}
 * codegen path.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "lock_boost_signal")
public abstract class LockBoostSchedBpf extends UserspaceSchedulerBase {

    /**
     * comm (thread name, &le;15 chars) of tasks treated as lock holders to boost.
     * Compile-time constant because {@code bpf_strncmp}'s second operand must be a
     * read-only string literal. The smoke test names its worker threads to match.
     */
    static final String WATCHED_COMM = "lockholder";

    /** Author signal kind, safely above the framework-reserved range. */
    static final int LOCK_ACQUIRED = Signal.SignalKind.FIRST_USER_KIND;

    @Override
    public void runnable(Ptr<task_struct> p, @Unsigned long enq_flags) {
        if (bpf_strncmp(Ptr.of(p.val().comm).asString(), 16, WATCHED_COMM) == 0) {
            emitSignal(LOCK_ACQUIRED, p.val().pid, 0L);
        }
    }
}
