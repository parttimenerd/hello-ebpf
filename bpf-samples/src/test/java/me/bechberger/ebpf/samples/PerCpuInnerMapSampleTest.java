package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PerCpuInnerMapSampleTest {

    @Test
    void perCpuHashOfMapsCollectsSyscallCounts() throws InterruptedException {
        int numCpus = Runtime.getRuntime().availableProcessors();
        try (PerCpuInnerMapSample program = BPFProgram.load(PerCpuInnerMapSample.class)) {
            Map<Long, Long> counts = program.run(3, numCpus);

            long total = counts.values().stream().mapToLong(Long::longValue).sum();
            assertTrue(total > 0, "expected nonzero syscall count total, got " + total);

            assertFalse(counts.isEmpty(), "no syscalls captured across " + numCpus + " CPUs");

            // Exercise unregister on one CPU and confirm it no longer reports back.
            program.perCpu.unregister(0);
            assertNull(program.perCpu.get(0), "unregister should clear the slot");
        }
    }
}
