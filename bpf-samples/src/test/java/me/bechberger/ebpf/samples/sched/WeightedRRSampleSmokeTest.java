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
    @Timeout(30)
    void weightedRRDispatchesAndTracksDebt() throws Exception {
        var sched = new WeightedRRSample();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();

        // Spawn hogs at two nice levels so weight differences become observable in debt.
        List<Process> hi = spawnNicedHogs(3, 0);
        List<Process> lo = spawnNicedHogs(3, 19);
        long hiPids = hi.stream().mapToLong(Process::pid).sum();
        long loPids = lo.stream().mapToLong(Process::pid).sum();
        try {
            Thread.sleep(6000);
        } finally {
            hi.forEach(Process::destroyForcibly);
            lo.forEach(Process::destroyForcibly);
        }

        var debt = sched.debtSnapshot();

        sched.requestExit();
        runner.join(10_000);
        var s = sched.stats();
        assertTrue(s.dispatched() > 100, "dispatched too few: " + s);
        assertTrue(s.dispatchFailed() < s.dispatched() / 100, "dispatch errors over 1%: " + s);

        long hiSum = hi.stream().mapToLong(p -> Math.abs(debt.getOrDefault((int) p.pid(), 0L))).sum();
        long loSum = lo.stream().mapToLong(p -> Math.abs(debt.getOrDefault((int) p.pid(), 0L))).sum();
        assertTrue(hiSum != loSum,
                "expected weight to differentiate debt totals; hiSum=" + hiSum + " loSum=" + loSum
                + " (hiPids=" + hiPids + " loPids=" + loPids + ")");
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
