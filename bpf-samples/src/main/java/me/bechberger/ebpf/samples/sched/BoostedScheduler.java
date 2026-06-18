// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.BoundedBy;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.SchedulerStats;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A scheduler designed for performance testing: nominated process trees run at
 * maximum priority with generous time slices while everything else gets fair
 * weighted scheduling.
 *
 * <h2>How it works</h2>
 * <ul>
 *   <li>Two DSQs: {@link #BOOSTED_DSQ} (vtime-ordered, always drained first) and
 *       {@link #NORMAL_DSQ} (vtime-ordered fair queue).</li>
 *   <li>A {@link BPFHashMap} ({@code boostedTgids}) maps up to
 *       {@link #MAX_BOOSTED} thread-group IDs to a placeholder value.  Any task
 *       whose ancestor chain contains a boosted tgid is considered "boosted".</li>
 *   <li>When boost mode is enabled, boosted tasks are inserted into
 *       {@link #BOOSTED_DSQ} with a fixed vtime of 0 (i.e. always ahead of
 *       normal tasks) and a slice of {@link #BOOSTED_SLICE_NS}.</li>
 *   <li>Boost mode can be toggled at runtime without restarting or reloading the
 *       scheduler — all changes take effect on the next {@code enqueue()} call.
 *       While disabled, all tasks share the normal vtime-fair queue.</li>
 * </ul>
 *
 * <h2>Usage from a test harness</h2>
 * <pre>{@code
 * try (var sched = BPFProgram.load(BoostedScheduler.class)) {
 *     sched.boostTgid((int) ProcessHandle.current().pid());
 *     sched.setBoostEnabled(true);
 *     sched.attachScheduler();
 *
 *     runBenchmark();
 *
 *     sched.setBoostEnabled(false);
 *     sched.clearBoostedTgids();
 * }
 * }</pre>
 *
 * <p>Run as a stand-alone scheduler:
 * <pre>
 *   sudo ./run.sh BoostedScheduler
 * </pre>
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "boosted_scheduler")
@Property(name = "timeout_ms", value = "10000")
public abstract class BoostedScheduler extends SchedulerBase implements Scheduler {

    /** DSQ id used for boosted process trees (always drained before NORMAL_DSQ). */
    static final long BOOSTED_DSQ = 1;
    /** DSQ id used for all non-boosted tasks (vtime weighted-fair queue). */
    static final long NORMAL_DSQ  = 2;

    /** Maximum number of simultaneously boosted thread-group IDs. */
    static final int MAX_BOOSTED = 64;

    /** Time slice granted to boosted tasks (20 ms). */
    static final long BOOSTED_SLICE_NS = 20_000_000L;

    /** When {@code false}, all tasks use the normal fair queue regardless of tgid. */
    final GlobalVariable<Boolean> boostEnabled = new GlobalVariable<>(false);

    /** Global virtual time for the normal fair queue. */
    final GlobalVariable<@Unsigned Long> vtimeNow = new GlobalVariable<>(0L);

    /** Set of boosted thread-group IDs.  Key = tgid; value = 1 (unused). */
    @BPFMapDefinition(maxEntries = MAX_BOOSTED)
    BPFHashMap<Integer, Integer> boostedTgids;

    /** Per-CPU enqueue counters: index 0 = boosted DSQ, index 1 = normal DSQ. */
    @BPFMapDefinition(maxEntries = 2)
    BPFPerCpuArray<Long> enqueueCounters;

    // Both DSQs are created via the constructor; their scx_bpf_create_dsq calls
    // are automatically lifted to init() prologue in declaration order.
    // SchedulerBase.init() creates SHARED_DSQ_ID — just attach.
    final DispatchQueue boosted = new DispatchQueue(BOOSTED_DSQ);
    final DispatchQueue normal  = new DispatchQueue(NORMAL_DSQ);
    final DispatchQueue shared  = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public int init() {
        // scx_bpf_create_dsq for boosted and normal DSQs is injected before this
        // line by the compiler plugin (from the DispatchQueue field initializers above).
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    /** Returns {@code true} if any tgid in {@code p}'s ancestor chain is in {@code boostedTgids}. */
    @BPFFunction
    @AlwaysInline
    boolean isBoosted(Ptr<task_struct> p) {
        Ptr<task_struct> cur = p;
        for (@BoundedBy(8) int i = 0; i < 8; i++) {
            if (cur == null) return false;
            Ptr<Integer> found = boostedTgids.bpf_get(cur.val().tgid);
            if (found != null) return true;
            cur = cur.val().real_parent;
        }
        return false;
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        return selectCpuDfl(p, prev_cpu, wake_flags);
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        EnqFlags f = EnqFlags.passThrough(enq_flags);
        if (boostEnabled.get() && isBoosted(p)) {
            boosted.insertVtime(p, BOOSTED_SLICE_NS, 0, f);
            SchedulerStats.incrementEnqueuedAt(enqueueCounters, 0);
        } else {
            normal.insertVtimeClamped(p, vtimeNow.get(), f);
            SchedulerStats.incrementEnqueuedAt(enqueueCounters, 1);
        }
    }

    @Override
    public void running(Ptr<task_struct> p) {
        @Unsigned long vtime = p.val().scx.dsq_vtime;
        if (isSmaller(vtimeNow.get(), vtime)) {
            vtimeNow.set(vtime);
        }
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        vtimeCharge(p);
    }

    @Override
    public void enable(Ptr<task_struct> p) {
        p.val().scx.dsq_vtime = vtimeNow.get();
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        if (boosted.nonEmpty()) {
            boosted.moveToLocal();
        } else {
            normal.moveToLocal();
        }
    }

    // ---- Java-side API ----

    /** Enables or disables boost mode. */
    public void setBoostEnabled(boolean enabled) {
        boostEnabled.set(enabled);
    }

    /** Returns {@code true} when boost mode is currently active. */
    public boolean isBoostEnabled() {
        return boostEnabled.get();
    }

    /** Registers a thread-group ID for boosting. */
    public void boostTgid(int tgid) {
        boostedTgids.put(tgid, 1);
    }

    /** Removes a previously registered tgid. */
    public void unboostTgid(int tgid) {
        boostedTgids.delete(tgid);
    }

    /** Removes all registered tgids. */
    public void clearBoostedTgids() {
        boostedTgids.clear();
    }

    /** Returns total tasks enqueued into the boosted DSQ since the scheduler started. */
    public long getBoostedEnqueueCount() {
        return SchedulerStats.totalEnqueuedAt(enqueueCounters, 0);
    }

    /** Returns total tasks enqueued into the normal DSQ since the scheduler started. */
    public long getNormalEnqueueCount() {
        return SchedulerStats.totalEnqueuedAt(enqueueCounters, 1);
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(BoostedScheduler.class)) {
            prog.runSchedulerLoop();
        }
    }
}
