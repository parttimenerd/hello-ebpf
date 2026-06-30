// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.SchedulerExtension;
import me.bechberger.ebpf.bpf.TestUtil;
import me.bechberger.ebpf.bpf.map.BPFHistogram;
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
 *   <li>p50 ring-consume latency (userspace drain wall time) stays under 250 µs.</li>
 *   <li>p99 ring-consume latency stays under 2 ms.</li>
 *   <li>Drop rate stays under 1% of total enqueues.</li>
 * </ul>
 *
 * <p>We assert on {@code ringConsumeUsHist} rather than {@code roundTripUsHist}:
 * the round-trip histogram depends on {@code TaskCtx.stopTs} being non-zero,
 * which only happens after a task has been context-switched out at least once
 * by our scheduler. With short-lived synthetic load this often produces zero
 * samples; ring-consume is recorded on every drain pass and reflects the
 * userspace half of the dispatch loop, which is what this benchmark exercises.
 *
 * <p>Skipped unless {@code BENCH=1} is set in the environment — running this
 * is not a regression gate (numbers depend heavily on host load), only a
 * point-in-time SLO check.
 */
@ExtendWith(SchedulerExtension.class)
public class UserspaceSchedulerObsBenchTest {

    @Test
    @Timeout(90)
    void medianRingConsumeUnder250us() throws Exception {
        Assumptions.assumeTrue("1".equals(System.getenv("BENCH")),
                "BENCH=1 not set; skipping micro-benchmark");

        var sched = new UserspaceScheduler() {
            @Override
            protected int policy(QueuedTask t) { return ANY_CPU; }
        };
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()), "bench-runner");
        runner.setDaemon(true);
        runner.setUncaughtExceptionHandler((t, e) -> {
            System.err.println("BENCH runner died: " + e);
            e.printStackTrace(System.err);
        });
        runner.start();

        // Wait until bpfHandle is set and capture a stable histogram reference.
        BPFHistogram hist = null;
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (System.nanoTime() < deadline) {
            var bpf = sched.bpf();
            if (bpf != null) { hist = bpf.ringConsumeHistView(); break; }
            Thread.sleep(50);
        }
        assertNotNull(hist, "bpfHandle never became non-null within 10s");

        TestUtil.spawnCpuHogs(Runtime.getRuntime().availableProcessors(), 10_000);

        // Sample percentiles while runner is alive. Latches the highest sample
        // count seen so a late detach doesn't erase the result.
        long total = 0, p50 = 0, p99 = 0;
        long sampleDeadline = System.nanoTime() + 5_000_000_000L;
        while (System.nanoTime() < sampleDeadline && sched.bpf() != null) {
            try {
                long t = hist.totalCount();
                if (t > total) { total = t; p50 = hist.percentile(0.50); p99 = hist.percentile(0.99); }
            } catch (Exception e) {
                System.err.println("BENCH: hist read failed (likely cleanup race): " + e);
                break;
            }
            Thread.sleep(200);
        }

        boolean prematureExit = sched.bpf() == null;
        if (!prematureExit) {
            sched.requestExit();
        }
        runner.join(10_000);

        var s = sched.stats();
        System.err.println("BENCH summary: " + sched.formatStats());
        System.err.printf("BENCH ringConsume: samples=%d p50=%dus p99=%dus prematureExit=%s%n",
                total, p50, p99, prematureExit);

        assertTrue(total > 1000, "not enough samples: " + total);
        assertTrue(p50 < 250,  "p50 too high: " + p50 + "us");
        assertTrue(p99 < 2000, "p99 too high: " + p99 + "us");
        assertTrue(s.ringDropped() * 100 < Math.max(s.ringEnqueued(), 1),
                "drop > 1%: " + s);
    }
}
