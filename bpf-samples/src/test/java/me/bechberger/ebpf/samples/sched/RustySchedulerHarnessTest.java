package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.CpuTopology;
import me.bechberger.ebpf.bpf.userspace.SchedulerHarness;
import org.junit.jupiter.api.Test;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.*;

class RustySchedulerHarnessTest {

    // Build a 2-domain topology (cpus {0,1} and {2,3}) via a fake sysfs tree.
    private static CpuTopology twoDomainTopo() throws IOException {
        Path root = Files.createTempDirectory("rusty-sysfs");
        for (int cpu = 0; cpu <= 3; cpu++) {
            Path idx = root.resolve("cpu" + cpu).resolve("cache").resolve("index3");
            Files.createDirectories(idx);
            Files.writeString(idx.resolve("level"), "3\n");
            Files.writeString(idx.resolve("shared_cpu_list"), (cpu <= 1 ? "0-1" : "2-3") + "\n");
        }
        return CpuTopology.detect(root);
    }

    private static QueuedTask task(int pid, int prevCpu, long execRuntime) {
        var t = new QueuedTask();
        t.pid = pid;
        t.prevCpu = prevCpu;
        t.weight = 100;
        t.execRuntime = execRuntime;
        t.nrCpusAllowed = 4;
        return t;
    }

    @Test
    void everyDispatchTargetsCpuInsideTaskDomain() throws IOException {
        var topo = twoDomainTopo();
        var sched = new RustyScheduler(topo, 1_000_000_000L, true, 10);
        var harness = SchedulerHarness.forScheduler(sched).withCpus(4).withVirtualClock(0);

        // Task with prevCpu=0 -> domain 0 (cpus 0,1); prevCpu=2 -> domain 1 (cpus 2,3).
        harness.feed(task(1, 0, 0), task(2, 2, 0));
        harness.runBatch();

        for (var d : harness.dispatches()) {
            if (d.targetCpu() < 0) continue; // ANY_CPU is allowed when no idle in-domain
            int expectedDom = topo.domainOfCpu(d.targetCpu());
            Integer assigned = sched.domainOf(d.pid());
            assertNotNull(assigned, "pid " + d.pid() + " must have an assigned domain");
            assertEquals(assigned.intValue(), expectedDom,
                    "dispatch of pid " + d.pid() + " landed on cpu " + d.targetCpu()
                            + " in domain " + expectedDom + " but task is assigned domain " + assigned);
        }
    }

    @Test
    void imbalanceTriggersMigration() throws IOException {
        var topo = twoDomainTopo();
        var sched = new RustyScheduler(topo, 1_000_000_000L, true, 10);
        var harness = SchedulerHarness.forScheduler(sched).withCpus(4).withVirtualClock(0);

        // Pile 3 busy tasks onto domain 0 (prevCpu 0), none on domain 1.
        // Enqueue repeatedly with advancing exec to build up load on domain 0.
        int[] pids = {1, 2, 3};
        long exec = 0;
        for (int round = 0; round < 20; round++) {
            harness.advanceMillis(100);
            exec += 100_000_000L; // 100ms busy
            harness.feed(task(pids[0], 0, exec), task(pids[1], 0, exec), task(pids[2], 0, exec));
            harness.runBatch();
        }
        // All three should currently be in domain 0.
        for (int pid : pids) assertEquals(0, sched.domainOf(pid).intValue());

        harness.tick();

        // At least one task should have been migrated to domain 1 to balance.
        long inDom1 = java.util.Arrays.stream(pids).filter(p -> sched.domainOf(p) != null
                && sched.domainOf(p) == 1).count();
        assertTrue(inDom1 >= 1, "expected >= 1 task migrated to domain 1 after tick(); "
                + "dom assignments: " + java.util.Arrays.stream(pids)
                        .mapToObj(p -> p + "->" + sched.domainOf(p)).toList());
    }
}
