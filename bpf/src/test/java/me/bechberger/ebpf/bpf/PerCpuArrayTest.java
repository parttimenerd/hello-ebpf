package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PerCpuArrayTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1)
        BPFPerCpuArray<Integer> counter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int countOpenAt(Ptr<PtDefinitions.pt_regs> ctx) {
            int key = 0;
            Ptr<Integer> val = counter.bpf_get(key);
            if (val != null) {
                me.bechberger.ebpf.bpf.BPFJ.sync_fetch_and_add(val, 1);
            }
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testPerCpuCounter() {
        try (var program = BPFProgram.load(Program.class)) {
            int numCpus = Lib_2.libbpf_num_possible_cpus();
            assertTrue(numCpus > 0);

            // Before attaching: test Java-side read/write without racing BPF writes
            List<Integer> initial = program.counter.getAll(0);
            assertEquals(numCpus, initial.size(), "getAll must return numCpus entries");

            // setAll + getAll round-trip (no BPF writes yet)
            program.counter.setAll(0, Collections.nCopies(numCpus, 77));
            List<Integer> after = program.counter.getAll(0);
            assertTrue(after.stream().allMatch(v -> v == 77),
                    "Expected all 77 after setAll, got " + after);

            // sumAll
            assertEquals(77L * numCpus, program.counter.sumAll(0));

            // Now attach and verify increments accumulate
            program.counter.setAll(0, Collections.nCopies(numCpus, 0));
            program.autoAttachPrograms();
            for (int i = 0; i < 5; i++) {
                TestUtil.triggerOpenAt();
            }
            long total = program.counter.sumAll(0);
            assertTrue(total >= 5, "Expected at least 5 increments, got " + total);
        }
    }
}
