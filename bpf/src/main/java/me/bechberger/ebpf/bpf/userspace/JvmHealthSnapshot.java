// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/**
 * Lightweight JVM-side metrics surfaced by the run loop. Sampled once per second
 * by the heartbeat; users can read via {@code UserspaceScheduler#jvmHealth()}.
 */
public record JvmHealthSnapshot(
    long totalGcCountDelta,   // GC events in the last sample window
    long totalGcTimeMsDelta,  // GC pause ms in the last sample window
    long heapUsedBytes,
    long heapMaxBytes
) {
    public static final JvmHealthSnapshot ZERO = new JvmHealthSnapshot(0, 0, 0, 0);
}
