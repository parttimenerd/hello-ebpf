package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class CpuTopologyTest {

    /** Write a fake sysfs cache node: cpuN/cache/indexK/{level,shared_cpu_list}. */
    private static void writeCache(Path root, int cpu, int index, int level, String sharedList)
            throws IOException {
        Path dir = root.resolve("cpu" + cpu).resolve("cache").resolve("index" + index);
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("level"), level + "\n");
        Files.writeString(dir.resolve("shared_cpu_list"), sharedList + "\n");
    }

    @Test
    void groupsCpusByHighestSharedCache(@TempDir Path root) throws IOException {
        // 4 CPUs: {0,1} share an L3, {2,3} share a different L3 -> 2 domains.
        for (int cpu = 0; cpu <= 1; cpu++) {
            writeCache(root, cpu, 0, 1, cpu + "");     // private L1
            writeCache(root, cpu, 3, 3, "0-1");        // shared L3
        }
        for (int cpu = 2; cpu <= 3; cpu++) {
            writeCache(root, cpu, 0, 1, cpu + "");
            writeCache(root, cpu, 3, 3, "2-3");
        }
        var topo = CpuTopology.detect(root);
        assertEquals(4, topo.nrCpus());
        assertEquals(2, topo.nrDomains());
        assertEquals(topo.domainOfCpu(0), topo.domainOfCpu(1));
        assertEquals(topo.domainOfCpu(2), topo.domainOfCpu(3));
        assertNotEquals(topo.domainOfCpu(0), topo.domainOfCpu(2));
        // cpuMask of cpu 0's domain covers exactly {0,1}
        assertEquals(0b0011L, topo.cpuMask(topo.domainOfCpu(0)));
        assertEquals(0b1100L, topo.cpuMask(topo.domainOfCpu(2)));
    }

    @Test
    void fallsBackToSingleDomainWhenNoCacheInfo(@TempDir Path root) throws IOException {
        // Create cpu dirs with NO cache subdir.
        Files.createDirectories(root.resolve("cpu0"));
        Files.createDirectories(root.resolve("cpu1"));
        Files.createDirectories(root.resolve("cpu2"));
        var topo = CpuTopology.detect(root);
        assertEquals(3, topo.nrCpus());
        assertEquals(1, topo.nrDomains(), "missing cache info -> single all-CPU domain");
        assertEquals(0, topo.domainOfCpu(0));
        assertEquals(0, topo.domainOfCpu(2));
        assertEquals(0b0111L, topo.cpuMask(0));
    }

    @Test
    void neverThrowsOnMissingRoot() {
        var topo = CpuTopology.detect(Path.of("/definitely/not/here/sysfs"));
        assertTrue(topo.nrDomains() >= 1, "missing root must still yield >= 1 domain");
    }
}
