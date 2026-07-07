// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;

import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Shared base for JVM-only test subclasses of {@link UserspaceScheduler}.
 *
 * <p>Overrides all BPF lifecycle seams to no-ops and provides a
 * {@link #drainRaw()} implementation driven by {@link #fakeTasks}, so
 * the production {@code drainBatchOnce} path runs on controllable input
 * without a real kernel or BPF file descriptor.
 *
 * <p>Used by {@link JfrEmissionTest} and {@link HistogramsTest}.
 */
abstract class FakeSchedulerBase extends UserspaceScheduler {

    /** Tasks injected into {@link #drainRaw()} for the next {@code drainBatchOnce} call. */
    final List<QueuedTask> fakeTasks = new ArrayList<>();

    /** Return value for {@link #submitDispatch} — 0 = success, non-zero = failure. */
    int submitResult = 0;

    // ── BPF lifecycle seams ───────────────────────────────────────────────────
    @Override protected void loadAndAttachBpf()      { /* no-op */ }
    @Override protected void cleanupBpf()            { /* no-op */ }
    @Override protected boolean isAttached()         { return false; }
    @Override protected MemorySegment idleMaskView() { return null; }

    // ── framework-PID seams ───────────────────────────────────────────────────
    @Override protected void putFrameworkPid(int pid) { /* no-op */ }
    @Override
    protected Iterable<Map.Entry<Integer, Byte>> frameworkPidsIterable() {
        return Collections.emptyList();
    }

    // ── submit seam ───────────────────────────────────────────────────────────
    @Override
    protected int submitDispatch(int targetCpu, int pid, long enqCnt, long sliceNs, long vtime) {
        return submitResult;
    }

    /**
     * Drain seam: fill the real {@code taskPool} with {@link #fakeTasks} and return
     * their count. The production {@code drainBatchOnce} then runs the real dispatch
     * and event-emission path on those tasks.
     *
     * <p>Returns 0 when {@code fakeTasks} is empty so {@code drainBatchOnce}'s
     * early-return path is taken (no events or histograms recorded).
     */
    @Override
    protected int drainRaw() {
        int n = fakeTasks.size();
        ensureTaskPool(n);
        for (int i = 0; i < n; i++) {
            taskPool[i] = fakeTasks.get(i);
        }
        batchCtx.count = n;
        return n;
    }
}
