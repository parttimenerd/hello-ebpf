// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.SchedulerExtension;
import me.bechberger.ebpf.bpf.TestUtil;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Microbenchmark exercising the framework under sustained load.
 *
 * <p>Asserts that under CPU saturation:
 * <ul>
 *   <li>p50 BPF-side round-trip latency stays under 250 µs.</li>
 *   <li>p99 BPF-side round-trip latency stays under 2 ms.</li>
 *   <li>Drop rate stays under 1% of total enqueues.</li>
 * </ul>
 *
 * <p>Skipped unless {@code BENCH=1} is set in the environment — running this
 * is not a regression gate (numbers depend heavily on host load), only a
 * point-in-time SLO check.
 */
@ExtendWith(SchedulerExtension.class)
public class UserspaceSchedulerObsBenchTest {

    @Test
    @Timeout(90)
    void medianRoundTripUnder250us() throws Exception {
        Assumptions.assumeTrue("1".equals(System.getenv("BENCH")),
                "BENCH=1 not set; skipping micro-benchmark");

        var sched = new UserspaceScheduler() {
            @Override
            protected int policy(QueuedTask t) { return ANY_CPU; }
        };
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()), "bench-runner");
        runner.setDaemon(true);
        runner.start();
        Thread.sleep(500);
        TestUtil.spawnCpuHogs(Runtime.getRuntime().availableProcessors(), 10_000);
        Thread.sleep(11_000);

        // Snapshot histograms BEFORE requesting exit — cleanupBpf() nulls bpfHandle.
        var hist = sched.bpf().roundTripHistView();
        long total = hist.totalCount();
        long p50 = hist.percentile(0.50);
        long p99 = hist.percentile(0.99);

        sched.requestExit();
        runner.join(10_000);

        assertTrue(total > 1000, "not enough samples: " + total);
        var s = sched.stats();

        System.err.println("BENCH summary: " + sched.formatStats());
        System.err.printf("BENCH histogram: samples=%d p50=%dus p99=%dus%n", total, p50, p99);

        assertTrue(p50 < 250,  "p50 too high: " + p50 + "us");
        assertTrue(p99 < 2000, "p99 too high: " + p99 + "us");
        assertTrue(s.ringDropped() * 100 < Math.max(s.ringEnqueued(), 1),
                "drop > 1%: " + s);
    }
}
