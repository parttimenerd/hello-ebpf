// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import java.util.ArrayList;
import java.util.List;

/**
 * Bounded, live ring of the last N scheduling decisions — answers "what did the scheduler
 * just do and why" without enabling JFR. Backed by pre-allocated parallel arrays (no
 * per-decision allocation), matching the hot-path discipline. Opt-in: capacity 0 disables it.
 *
 * <p>Not lock-free: {@link #recentDecisions()} copies out under {@code synchronized}; the run
 * loop's {@link #record} is a cheap array write under the same lock. Contention is negligible
 * at scheduling rates because reads are operator-initiated (a dashboard poll), not per-decision.
 */
public final class DecisionTrace {

    public enum Kind { DISPATCH, PREEMPT, KICK, DROP }

    /** One captured decision. */
    public record TraceEntry(long tsNs, int pid, int cpu, Kind kind, int reason) {}

    private static final Kind[] KINDS = Kind.values();

    private final int capacity;
    private final long[] tsNs;
    private final int[]  pid;
    private final int[]  cpu;
    private final byte[] kind;    // ordinal
    private final int[]  reason;
    private int head;             // next write index
    private int size;             // number of valid entries (<= capacity)

    public DecisionTrace(int capacity) {
        this.capacity = Math.max(0, capacity);
        this.tsNs   = new long[this.capacity];
        this.pid    = new int[this.capacity];
        this.cpu    = new int[this.capacity];
        this.kind   = new byte[this.capacity];
        this.reason = new int[this.capacity];
    }

    public boolean enabled() { return capacity > 0; }

    /** Record one decision. No-op when capacity is 0. */
    public synchronized void record(long tsNs, int pid, int cpu, Kind kind, int reason) {
        if (capacity == 0) return;
        this.tsNs[head]   = tsNs;
        this.pid[head]    = pid;
        this.cpu[head]    = cpu;
        this.kind[head]   = (byte) kind.ordinal();
        this.reason[head] = reason;
        head = (head + 1) % capacity;
        if (size < capacity) size++;
    }

    /** Snapshot of the most recent decisions, oldest to newest. */
    public synchronized List<TraceEntry> recentDecisions() {
        List<TraceEntry> out = new ArrayList<>(size);
        int start = (head - size + capacity) % Math.max(1, capacity);
        for (int i = 0; i < size; i++) {
            int idx = (start + i) % capacity;
            out.add(new TraceEntry(tsNs[idx], pid[idx], cpu[idx], KINDS[kind[idx]], reason[idx]));
        }
        return out;
    }
}
