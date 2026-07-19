package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WorkerShardingTest {

    @Test
    void samePidAlwaysSameWorker() {
        int n = 4;
        Map<Integer, Integer> pidToWorker = new HashMap<>();
        for (int rep = 0; rep < 3; rep++) {
            for (int pid = 1; pid <= 1000; pid++) {
                int w = UserspaceScheduler.workerForPid(pid, n);
                assertTrue(w >= 0 && w < n, "worker in range");
                Integer prev = pidToWorker.putIfAbsent(pid, w);
                if (prev != null) assertEquals(prev.intValue(), w, "pid " + pid + " stable across reps");
            }
        }
    }

    @Test
    void workerForPidIsUniformEnough() {
        int n = 4;
        int[] counts = new int[n];
        for (int pid = 1; pid <= 4000; pid++) counts[UserspaceScheduler.workerForPid(pid, n)]++;
        for (int c : counts) assertTrue(c > 500, "each worker gets a fair share, got " + c);
    }

    @Test
    void singleWorkerIsIdentity() {
        for (int pid = 0; pid < 100; pid++) assertEquals(0, UserspaceScheduler.workerForPid(pid, 1));
    }
}
