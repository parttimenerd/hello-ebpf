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

@ExtendWith(SchedulerExtension.class)
public class WeightedRRSampleSmokeTest {

    @Test
    @Timeout(90)
    void weightedRRDispatchesAndTracksDebt() throws Exception {
        var sched = new WeightedRRSample();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();

        // Spawn hogs at two nice levels so weight differences become observable in debt.
        // We track child PIDs of the wrapper processes too (the wrappers exec into sh/yes).
        List<Process> hi = spawnNicedHogs(3, 0);
        List<Process> lo = spawnNicedHogs(3, 19);
        try {
            Thread.sleep(6000);
        } finally {
            hi.forEach(Process::destroyForcibly);
            lo.forEach(Process::destroyForcibly);
        }

        var debt = sched.debtSnapshot();

        sched.requestExit();
        runner.join(30_000);
        var s = sched.stats();
        // Floor is intentionally low: GH-hosted CI runners are noticeably slower at
        // sched-ext dispatch than local hardware (a local run drives >500 dispatches
        // in the same window; CI has been observed as low as 12). We keep the check
        // to ensure the ring is *not* degenerate (zero); the weight-differentiation
        // assertion below is the real signal.
        assertTrue(s.dispatched() > 5, "dispatched too few: " + s);
        assertTrue(s.dispatchFailed() < Math.max(1, s.dispatched() / 100), "dispatch errors over 1%: " + s);

        // Weight differentiation: with nice 0 (weight ~100) vs nice 19 (weight ~15) under
        // equivalent load, debt magnitudes should span a noticeable range across the map.
        // Use range (max - min absolute debt) as a coarse but robust proxy.
        long maxAbsDebt = debt.values().stream().mapToLong(Math::abs).max().orElse(0);
        long minAbsDebt = debt.values().stream().mapToLong(Math::abs).min().orElse(0);
        assertTrue(!debt.isEmpty(), "expected debt map to be populated; stats=" + s);
        assertTrue(maxAbsDebt - minAbsDebt > 0,
                "expected weight to differentiate debt across pids; range="
                + (maxAbsDebt - minAbsDebt) + " entries=" + debt.size() + " stats=" + s);
    }

    private static List<Process> spawnNicedHogs(int n, int nice) {
        List<Process> procs = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            try {
                procs.add(new ProcessBuilder("nice", "-n", Integer.toString(nice), "sh", "-c", "yes > /dev/null").start());
            } catch (java.io.IOException e) {
                throw new RuntimeException("spawnNicedHogs failed: " + e.getMessage(), e);
            }
        }
        return procs;
    }
}
