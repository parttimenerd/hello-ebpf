// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/**
 * Minimal in-heap log2-bucketed histogram for per-class latency/count metrics.
 *
 * <p>The framework's primary histograms ({@link me.bechberger.ebpf.bpf.map.BPFHistogram})
 * are backed by a BPF map and need a kernel file descriptor; this one is pure heap so it
 * can be created per task class without touching the kernel. 64 buckets: bucket {@code i}
 * counts samples in {@code [2^(i-1), 2^i)} (bucket 0 counts {@code 0}).
 *
 * <p>Thread-safe via {@code synchronized}; per-class metrics are opt-in and updated off the
 * hot path only when a classifier is attached, so contention is negligible.
 */
public final class Log2Histogram {

    private final long[] buckets = new long[64];
    private long count;

    /** Record one sample (a latency in some unit, or 1 for a plain count). */
    public synchronized void add(long value) {
        int b = value <= 0 ? 0 : Math.min(63, 64 - Long.numberOfLeadingZeros(value));
        buckets[b]++;
        count++;
    }

    public synchronized long totalCount() { return count; }

    /**
     * Approximate percentile as the upper bound of the bucket containing the p-th sample.
     * @param p fraction in [0,1]
     * @return {@code 2^bucket} upper bound, or 0 if empty
     */
    public synchronized long percentile(double p) {
        if (count == 0) return 0;
        long target = (long) Math.ceil(p * count);
        if (target < 1) target = 1;
        long cum = 0;
        for (int i = 0; i < buckets.length; i++) {
            cum += buckets[i];
            if (cum >= target) return i == 0 ? 0 : (1L << i);
        }
        return 1L << 63;
    }
}
