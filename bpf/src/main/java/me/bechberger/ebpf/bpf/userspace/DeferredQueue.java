// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;

import java.util.PriorityQueue;
import java.util.function.Consumer;

/**
 * Cross-batch task store for sorted/deferred scheduling policies (vtime, EDF, delay).
 * Stores {@link QueuedTask#copy() copies} so entries are safe to retain across batch
 * boundaries (the framework reuses the drained flyweights).
 *
 * <p>Two ordering modes share one heap:
 * <ul>
 *   <li>{@link #deferOrdered} — min-key first (vtime, deadline). {@code notBefore = Long.MIN_VALUE}
 *       so it is always time-eligible.</li>
 *   <li>{@link #deferUntil} — becomes eligible at {@code notBeforeNs}; among eligible entries,
 *       still drained in key order (key defaults to {@code notBeforeNs}).</li>
 * </ul>
 * Not thread-safe: a given pid is handled by one worker (see Sub-project B affinity).
 */
public final class DeferredQueue {

    private record Entry(QueuedTask task, long key, long notBeforeNs, long seq) {}

    // Order by (key, then pid, then insertion seq) for a total, stable order.
    private final PriorityQueue<Entry> heap = new PriorityQueue<>((a, b) -> {
        int c = Long.compare(a.key, b.key);
        if (c != 0) return c;
        c = Integer.compare(a.task.pid, b.task.pid);
        if (c != 0) return c;
        return Long.compare(a.seq, b.seq);
    });
    private long seqCounter = 0;

    /** Store a copy of {@code t} to (re)consider at or after {@code notBeforeNs}. */
    public void deferUntil(QueuedTask t, long notBeforeNs) {
        heap.add(new Entry(t.copy(), notBeforeNs, notBeforeNs, seqCounter++));
    }

    /** Store a copy of {@code t} keyed by {@code key} (vtime/deadline). Min-key drains first. */
    public void deferOrdered(QueuedTask t, long key) {
        heap.add(new Entry(t.copy(), key, Long.MIN_VALUE, seqCounter++));
    }

    /**
     * Drain up to {@code max} tasks that are time-eligible at {@code nowNs}, in key order,
     * handing each to {@code sink}. Time-ineligible entries block nothing behind them only
     * if they sort after eligible ones; to keep it simple and correct we scan-and-reinsert.
     */
    public void drainEligible(long nowNs, int max, Consumer<QueuedTask> sink) {
        if (max <= 0 || heap.isEmpty()) return;
        java.util.ArrayList<Entry> deferredBack = new java.util.ArrayList<>();
        int drained = 0;
        while (drained < max && !heap.isEmpty()) {
            Entry e = heap.poll();
            if (e.notBeforeNs <= nowNs) {
                sink.accept(e.task);
                drained++;
            } else {
                deferredBack.add(e);
            }
        }
        heap.addAll(deferredBack);
    }

    /** Evict entries whose {@code notBeforeNs} is strictly older than {@code horizonNs}. */
    public void evictOlderThan(long horizonNs) {
        heap.removeIf(e -> e.notBeforeNs < horizonNs);
    }

    public int size() { return heap.size(); }
}
