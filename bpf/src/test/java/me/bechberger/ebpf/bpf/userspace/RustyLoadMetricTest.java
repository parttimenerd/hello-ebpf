package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RustyLoadMetricTest {

    private static final long MS = 1_000_000L;   // ns per ms
    private static final long HALF_LIFE_NS = 1_000 * MS; // 1s

    @Test
    void fullyBusyTaskConvergesTowardWeight() {
        var tr = new RustyLoadTracker(HALF_LIFE_NS);
        long now = 0;
        long exec = 0;
        // 100%-busy: every 100ms of wall time, exec advances by the full 100ms.
        for (int i = 0; i < 50; i++) {
            now += 100 * MS;
            exec += 100 * MS;
            tr.onEnqueue(1, exec, now);
        }
        double load = tr.load(1, /*weight*/100, now);
        assertTrue(load > 90.0, "100%-busy task load should approach weight (100); was " + load);
    }

    @Test
    void mostlySleepingTaskStaysLow() {
        var tr = new RustyLoadTracker(HALF_LIFE_NS);
        long now = 0;
        long exec = 0;
        // 10%-busy: every 100ms wall, exec advances 10ms.
        for (int i = 0; i < 50; i++) {
            now += 100 * MS;
            exec += 10 * MS;
            tr.onEnqueue(1, exec, now);
        }
        double load = tr.load(1, 100, now);
        assertTrue(load < 25.0, "10%-busy task load should stay low; was " + load);
    }

    @Test
    void dormantTaskDecaysTowardZeroAtReadTime() {
        var tr = new RustyLoadTracker(HALF_LIFE_NS);
        long now = 0;
        long exec = 0;
        for (int i = 0; i < 50; i++) {   // build up high load
            now += 100 * MS;
            exec += 100 * MS;
            tr.onEnqueue(1, exec, now);
        }
        double busyLoad = tr.load(1, 100, now);
        // Now go dormant for 5 half-lives (5s). Read decays toward 0.
        long later = now + 5 * HALF_LIFE_NS;
        double decayed = tr.load(1, 100, later);
        assertTrue(decayed < busyLoad * 0.1,
                "dormant task must decay far below its busy load; busy=" + busyLoad
                        + " decayed=" + decayed);
    }
}
