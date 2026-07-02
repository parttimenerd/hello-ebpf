package me.bechberger.ebpf.bpf.features.probes;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Package-private syscall counter used by probes and read by cache tests.
 * Every probe increments this counter exactly once per underlying syscall
 * (or once per BTF load). The counter is process-global — tests reset it
 * before running.
 */
public final class ProbeSyscallCounter {
    private ProbeSyscallCounter() {}

    private static final AtomicLong COUNT = new AtomicLong();

    public static void increment() { COUNT.incrementAndGet(); }
    public static long value()     { return COUNT.get(); }
    public static void reset()     { COUNT.set(0L); }
}
