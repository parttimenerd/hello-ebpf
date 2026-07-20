// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import java.util.ArrayList;
import java.util.List;

/**
 * A scheduling domain: a set of CPUs (default: one last-level cache group) plus the
 * load state the balancer operates on. Mirrors scx_rusty's per-domain {@code LoadEntity}.
 *
 * <p>Constants ported 1:1 from upstream rusty ({@code /tmp/rusty_lb.rs}):
 * {@code cost_ratio = 0.05}, {@code xfer_ratio = 0.50}, {@code push_max_ratio = 0.50}.
 * A domain is {@code BALANCED} while {@code |imbal| <= load_avg * cost_ratio}; otherwise
 * it is {@code NEEDS_PUSH} (overloaded) or {@code NEEDS_PULL} (underloaded).
 */
public final class Domain {

    /** rusty Domain::LOAD_IMBAL_HIGH_RATIO analogue — imbalance tolerance band. */
    public static final double COST_RATIO = 0.05;
    /** Fraction of the smaller imbalance we aim to transfer in one move. */
    public static final double XFER_RATIO = 0.50;
    /** Cap on how much of a push domain's imbalance one balancing round may shed. */
    public static final double PUSH_MAX_RATIO = 0.50;

    public enum BalanceState { NEEDS_PUSH, NEEDS_PULL, BALANCED }

    private final int id;
    private final long cpuMask;
    private double loadSum;
    private final List<DomainLoadBalancer.TaskLoad> tasks = new ArrayList<>();

    public Domain(int id, long cpuMask) {
        this.id = id;
        this.cpuMask = cpuMask;
    }

    public int id() { return id; }
    public long cpuMask() { return cpuMask; }
    public double loadSum() { return loadSum; }
    public void setLoadSum(double v) { this.loadSum = v; }
    public List<DomainLoadBalancer.TaskLoad> tasks() { return tasks; }

    public void addTask(DomainLoadBalancer.TaskLoad t) {
        tasks.add(t);
        loadSum += t.load();
    }

    /** rusty imbal(): how far this domain's load is from the average. >0 = overloaded. */
    public double imbal(double loadAvg) { return loadSum - loadAvg; }

    public BalanceState state(double loadAvg) {
        double band = loadAvg * COST_RATIO;
        double imbal = imbal(loadAvg);
        if (imbal > band) return BalanceState.NEEDS_PUSH;
        if (imbal < -band) return BalanceState.NEEDS_PULL;
        return BalanceState.BALANCED;
    }
}
