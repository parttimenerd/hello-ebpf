// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import java.time.Duration;

/**
 * Tunables for {@code UserspaceScheduler}. All fields have safe defaults — override only
 * what you need.
 */
public final class Opts {
    /** Max events drained per BPF→Java round trip. Higher = better throughput, worse latency. */
    public int batchSize = 256;

    /** Ring buffer poll budget — return to Java after this many events even if more remain. */
    public int ringPollBudget = 1024;

    /** Warn (don't fail) if ZGC isn't detected at start. Recommend ZGC for sub-ms pauses. */
    public boolean verifyZgcOnStart = true;

    /** How often to refresh /proc/self/task and re-pin framework PIDs. */
    public Duration frameworkPidRescan = Duration.ofSeconds(5);

    /** Soft policy() exception budget per second — if exceeded, log loudly and continue. */
    public int policyExceptionBudgetPerSec = 100;

    public static Opts defaults() { return new Opts(); }
}
