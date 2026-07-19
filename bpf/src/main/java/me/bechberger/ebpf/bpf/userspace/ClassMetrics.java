// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/** A per-class latency/count summary derived from a {@link Log2Histogram}. */
public record ClassMetrics(long count, long p50, long p99) {
    /** Derive from a heap histogram. */
    public static ClassMetrics of(Log2Histogram h) {
        long c = h.totalCount();
        if (c == 0) return new ClassMetrics(0, 0, 0);
        return new ClassMetrics(c, h.percentile(0.50), h.percentile(0.99));
    }
}
