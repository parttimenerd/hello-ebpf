// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.SchedulerExtension;
import me.bechberger.ebpf.bpf.userspace.Opts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Kernel smoke test for {@link LatencyTierEdfSample}: proves the classify-then-EDF
 * path attaches and dispatches without error under real load. Asserts liveness and
 * error-freeness rather than a dispatch-count floor (vng dispatch throughput on this
 * host is near-zero — see the vng-scheduler-ring-enqueue-zero note).
 */
@ExtendWith(SchedulerExtension.class)
public class LatencyTierEdfSampleSmokeTest {

    @Test
    @Timeout(90)
    void tieredEdfDispatchesUnderLoad() throws Exception {
        var sched = new LatencyTierEdfSample();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();

        // Mixed nice levels so multiple tiers are exercised.
        List<Process> procs = new ArrayList<>();
        procs.addAll(spawn(2, 0));    // INTERACTIVE-ish
        procs.addAll(spawn(2, 19));   // BATCH-ish
        try {
            Thread.sleep(6000);
        } finally {
            procs.forEach(Process::destroyForcibly);
        }

        sched.requestExit();
        runner.join(30_000);

        var s = sched.stats();
        assertTrue(s.heartbeatKicks() > 0, "scheduler never ran its heartbeat: " + s);
        assertEquals(0, s.dispatchFailed(), "tiered EDF produced kernel dispatch errors: " + s);
    }

    private static List<Process> spawn(int n, int nice) {
        List<Process> procs = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            try {
                procs.add(new ProcessBuilder(
                        "nice", "-n", Integer.toString(nice), "sh", "-c", "yes > /dev/null").start());
            } catch (java.io.IOException e) {
                throw new RuntimeException("spawn failed: " + e.getMessage(), e);
            }
        }
        return procs;
    }
}
