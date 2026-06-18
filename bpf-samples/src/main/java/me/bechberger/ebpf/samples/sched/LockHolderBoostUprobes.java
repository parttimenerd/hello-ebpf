// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.probe.ProbeContext;
import me.bechberger.ebpf.runtime.PtDefinitions.pt_regs;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

/**
 * Uprobe-side of the lock-holder priority-inheritance scheduler.
 *
 * <p>Owns the wait-graph and produces {@code boostState} via
 * {@code @SharedFrom}; {@link LockHolderBoostScheduler} consumes it from the
 * sched_ext side. Split out because uprobe context cannot call
 * {@code bpf_task_from_pid} on some kernels, and the verifier rejects mixed
 * uprobe + struct_ops programs sharing kfuncs.
 *
 * <p>Maps:
 * <ul>
 *   <li>{@code waiterToMonitor} — tid → monitor address (set on enter, cleared on acquire/exit)</li>
 *   <li>{@code monitorToHolder} — monitor address → tid (set when a thread acquires)</li>
 *   <li>{@code enterArgScratch} — tid → monitor address captured at enter, popped at uretprobe</li>
 *   <li>{@code contentionByMonitor} — monitor address → number of waiter-arrival events</li>
 *   <li>{@code boostState}      — holder tid → {@link BoostState}; <strong>shared</strong> with the scheduler</li>
 * </ul>
 */
@BPF(license = "GPL")
public abstract class LockHolderBoostUprobes extends BPFProgram {

    /** Per-task boost state; refcount of waiters helped by this thread. */
    @Type
    public static class BoostState {
        /** Number of waiters currently blocked behind this holder. Boost active iff &gt; 0. */
        @Unsigned int waiterCount;
        /** {@code bpf_ktime_get_ns()} of the most recent waiter arrival; used by the watchdog. */
        @Unsigned long lastBoostNs;
        /** Cumulative ns this task spent on the boosted DSQ — accumulated by the scheduler. */
        @Unsigned long totalBoostedNs;
        /** Timestamp of the current boosted on-CPU slice (set in {@code running}, consumed in {@code stopping}). */
        @Unsigned long onCpuStartNs;
    }

    /** Max distinct contended monitors tracked simultaneously. */
    public static final int MAX_MONITORS = 4096;
    /** Max waiting threads tracked. */
    public static final int MAX_WAITERS  = 4096;
    /** Max concurrently-tracked holder tasks. */
    public static final int MAX_HOLDERS  = 4096;

    @BPFMapDefinition(maxEntries = MAX_WAITERS)
    BPFHashMap<@Unsigned Long, @Unsigned Long> waiterToMonitor;

    @BPFMapDefinition(maxEntries = MAX_MONITORS)
    BPFHashMap<@Unsigned Long, @Unsigned Long> monitorToHolder;

    @BPFMapDefinition(maxEntries = MAX_WAITERS)
    BPFHashMap<@Unsigned Long, @Unsigned Long> enterArgScratch;

    @BPFMapDefinition(maxEntries = MAX_MONITORS)
    BPFHashMap<@Unsigned Long, @Unsigned Long> contentionByMonitor;

    /** Holder tid → boost state. Shared with the scheduler via {@code @SharedFrom}. */
    @BPFMapDefinition(maxEntries = MAX_HOLDERS)
    BPFHashMap<@Unsigned Long, BoostState> boostState;

    /** Lifetime counter: number of times a holder was boosted. */
    public final GlobalVariable<@Unsigned Long> boostActivations = new GlobalVariable<>(0L);

    /**
     * Uprobe entry on {@code ObjectMonitor::enter(JavaThread*)}.
     * @param ctx uprobe register context; {@code arg0} = {@code this} (monitor address)
     */
    @BPFFunction(section = "uprobe/ObjectMonitor_enter", autoAttach = false)
    public void onMonitorEnter(Ptr<pt_regs> ctx) {
        @Unsigned long monAddr = ProbeContext.of(ctx).arg0();
        @Unsigned long pidTid  = bpf_get_current_pid_tgid();
        @Unsigned long tid     = pidTid & 0xFFFFFFFFL;

        enterArgScratch.bpf_put(tid, monAddr);
        waiterToMonitor.bpf_put(tid, monAddr);

        Ptr<@Unsigned Long> count = contentionByMonitor.bpf_get(monAddr);
        if (count != null) {
            count.set(count.val() + 1);
        } else {
            @Unsigned long one = 1L;
            contentionByMonitor.bpf_put(monAddr, one);
        }

        Ptr<@Unsigned Long> holderPtr = monitorToHolder.bpf_get(monAddr);
        if (holderPtr == null) return;
        @Unsigned long holderTid = holderPtr.val();
        if (holderTid == 0 || holderTid == tid) return;

        Ptr<BoostState> bs = boostState.bpf_get(holderTid);
        if (bs != null) {
            bs.val().waiterCount = bs.val().waiterCount + 1;
            bs.val().lastBoostNs = bpf_ktime_get_ns();
        } else {
            BoostState fresh = new BoostState();
            fresh.waiterCount = 1;
            fresh.lastBoostNs = bpf_ktime_get_ns();
            fresh.totalBoostedNs = 0;
            fresh.onCpuStartNs = 0;
            boostState.bpf_put(holderTid, fresh);
        }
        boostActivations.set(boostActivations.get() + 1);
    }

    /** Uretprobe on {@code ObjectMonitor::enter}: caller acquired the monitor. */
    @BPFFunction(section = "uretprobe/ObjectMonitor_enter", autoAttach = false)
    public void onMonitorEnterRet(Ptr<pt_regs> ctx) {
        @Unsigned long pidTid = bpf_get_current_pid_tgid();
        @Unsigned long tid    = pidTid & 0xFFFFFFFFL;

        Ptr<@Unsigned Long> stashed = enterArgScratch.bpf_get(tid);
        if (stashed == null) return;
        @Unsigned long monAddr = stashed.val();
        enterArgScratch.bpf_delete(tid);

        waiterToMonitor.bpf_delete(tid);
        monitorToHolder.bpf_put(monAddr, tid);
    }

    /** Uprobe entry on {@code ObjectMonitor::exit(JavaThread*)}: caller releases. */
    @BPFFunction(section = "uprobe/ObjectMonitor_exit", autoAttach = false)
    public void onMonitorExit(Ptr<pt_regs> ctx) {
        @Unsigned long monAddr = ProbeContext.of(ctx).arg0();
        monitorToHolder.bpf_delete(monAddr);

        @Unsigned long pidTid = bpf_get_current_pid_tgid();
        @Unsigned long tid    = pidTid & 0xFFFFFFFFL;
        Ptr<BoostState> bs = boostState.bpf_get(tid);
        if (bs != null) {
            bs.val().waiterCount = 0;
        }
    }
}
