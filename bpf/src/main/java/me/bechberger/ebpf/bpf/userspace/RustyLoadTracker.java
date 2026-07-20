// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import java.util.HashMap;
import java.util.Map;

/**
 * Per-pid decayed duty-cycle tracker — the userspace analogue of scx_rusty's BPF ravg buckets.
 * Duty cycle is an exponentially-decayed EWMA of {@code execRuntime / wallTime}, updated on each
 * enqueue and decayed again at read time (so a dormant task decays exactly as rusty's ravg would
 * when sampled at load-balance time). Task load = {@code dutyCycle * weight}.
 *
 * <p>Half-life {@code H}: decay factor over {@code dt} nanoseconds is {@code 2^(-dt/H)}, and the
 * blend weight for a new sample is {@code alpha = 1 - 2^(-dt/H)}.
 */
public final class RustyLoadTracker {

    private final long halfLifeNs;
    private final Map<Integer, State> byPid = new HashMap<>();

    public RustyLoadTracker(long halfLifeNs) {
        if (halfLifeNs <= 0) throw new IllegalArgumentException("halfLifeNs must be > 0");
        this.halfLifeNs = halfLifeNs;
    }

    private static final class State {
        double ewmaDutyCycle;
        long lastExecRuntime;
        long lastSeenNs;
    }

    private double decayFactor(long dt) {
        if (dt <= 0) return 1.0;
        return Math.pow(2.0, -((double) dt) / halfLifeNs);
    }

    /** Update duty-cycle EWMA for {@code pid} on enqueue. */
    public void onEnqueue(int pid, long execRuntime, long nowNs) {
        State s = byPid.computeIfAbsent(pid, k -> {
            State ns = new State();
            ns.lastExecRuntime = execRuntime;
            ns.lastSeenNs = nowNs;
            return ns;
        });
        long execDelta = Math.max(0, execRuntime - s.lastExecRuntime);
        long wallDelta = nowNs - s.lastSeenNs;
        double instantDuty = wallDelta > 0
                ? Math.min(1.0, execDelta / (double) wallDelta)
                : 0.0;
        double alpha = 1.0 - decayFactor(wallDelta);
        s.ewmaDutyCycle += (instantDuty - s.ewmaDutyCycle) * alpha;
        s.lastExecRuntime = execRuntime;
        s.lastSeenNs = nowNs;
    }

    /** Current decayed duty cycle for {@code pid} at read time {@code nowNs} (0 if unknown). */
    public double dutyCycle(int pid, long nowNs) {
        State s = byPid.get(pid);
        if (s == null) return 0.0;
        long dt = nowNs - s.lastSeenNs;
        if (dt > 0) {
            s.ewmaDutyCycle *= decayFactor(dt);
            s.lastSeenNs = nowNs;
        }
        return s.ewmaDutyCycle;
    }

    /** Decayed-at-read task load = dutyCycle * weight. */
    public double load(int pid, long weight, long nowNs) {
        return dutyCycle(pid, nowNs) * weight;
    }

    /** Remove a pid's state (e.g. when it has been dormant past the stale threshold). */
    public void forget(int pid) { byPid.remove(pid); }

    /** True if this pid is tracked. */
    public boolean tracks(int pid) { return byPid.containsKey(pid); }

    /** Snapshot of currently-tracked pids (for tick() iteration). */
    public java.util.Set<Integer> trackedPids() {
        return new java.util.HashSet<>(byPid.keySet());
    }

    /** Nanoseconds since this pid was last seen (Long.MAX_VALUE if unknown). */
    public long nanosSinceSeen(int pid, long nowNs) {
        State s = byPid.get(pid);
        return s == null ? Long.MAX_VALUE : (nowNs - s.lastSeenNs);
    }
}
