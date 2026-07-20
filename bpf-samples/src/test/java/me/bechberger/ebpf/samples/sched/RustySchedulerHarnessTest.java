package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.CpuTopology;
import me.bechberger.ebpf.bpf.userspace.SchedulerHarness;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import static org.junit.jupiter.api.Assertions.*;

class RustySchedulerHarnessTest {

    // Build a 2-domain topology (cpus {0,1} and {2,3}) via a fake sysfs tree.
    private static CpuTopology twoDomainTopo(Path root) throws IOException {
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
    void assignsDomainFromPrevCpuAndDispatchesEveryTask(@TempDir Path root) throws IOException {
        var topo = twoDomainTopo(root);
        var sched = new RustyScheduler(topo, 1_000_000_000L, true, 10);
        var harness = SchedulerHarness.forScheduler(sched).withCpus(4).withVirtualClock(0);

        // prevCpu=0 -> domain 0 (cpus 0,1); prevCpu=2 -> domain 1 (cpus 2,3).
        harness.feed(task(1, 0, 0), task(2, 2, 0));
        harness.runBatch();

        // Domain assignment is derived from prevCpu's domain.
        assertEquals(topo.domainOfCpu(0), sched.domainOf(1).intValue());
        assertEquals(topo.domainOfCpu(2), sched.domainOf(2).intValue());
        assertNotEquals(sched.domainOf(1), sched.domainOf(2), "the two tasks land in different domains");

        // Both tasks must be dispatched (offline there is no idle bitmap, so target is ANY_CPU).
        assertEquals(2, harness.dispatches().size(), "every fed task must produce a dispatch");

        // Any dispatch that DID target a concrete CPU must land inside the task's assigned domain.
        for (var d : harness.dispatches()) {
            if (d.targetCpu() < 0) continue; // ANY_CPU: kernel picks within the domain's constraints
            assertEquals(sched.domainOf(d.pid()).intValue(), topo.domainOfCpu(d.targetCpu()),
                    "concrete dispatch of pid " + d.pid() + " on cpu " + d.targetCpu()
                            + " must be inside its assigned domain");
        }
    }

    @Test
    void imbalanceTriggersMigration(@TempDir Path root) throws IOException {
        var topo = twoDomainTopo(root);
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
        // All three should currently be in domain 0 (pre-condition, so a domain-1 result below
        // can only come from a real migration).
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
