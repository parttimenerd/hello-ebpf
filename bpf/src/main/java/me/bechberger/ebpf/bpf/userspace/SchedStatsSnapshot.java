// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/**
 * Immutable snapshot of scheduler counters. Read from {@code UserspaceScheduler#stats()}.
 * All fields are cumulative since attach time.
 */
public record SchedStatsSnapshot(
    long ringEnqueued,    // events written by BPF select_cpu/enqueue
    long ringDropped,     // events BPF tried to enqueue but ring was full (kernel fast path)
    long ringDrained,     // events Java successfully consumed
    long ringCanceled,    // events Java consumed where enqCnt no longer matched (stale)
    long dispatched,      // dispatch() calls into the kernel
    long dispatchFailed,  // dispatch() that returned non-zero (e.g. -E2BIG)
    long stallFallbacks,  // tasks rescued by the 50 ms stall fallback
    long heartbeatKicks   // SCX_KICK_IDLE issued from the bpf_timer
) {
    public static final SchedStatsSnapshot ZERO = new SchedStatsSnapshot(0,0,0,0,0,0,0,0);
}
