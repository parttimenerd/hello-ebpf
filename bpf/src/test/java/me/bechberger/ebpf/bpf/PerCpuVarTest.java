package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFPerCpuVar;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class PerCpuVarTest {

    @BPF(license = "GPL")
    public static abstract class IncrementProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1)
        BPFPerCpuVar<Long> counter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int countOpenAt(Ptr<PtDefinitions.pt_regs> ctx) {
            Ptr<Long> v = counter.bpf_get();
            if (v != null) {
                BPFJ.sync_fetch_and_add(v, 1L);
            }
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testJavaSideRoundTrip() {
        try (var program = BPFProgram.load(IncrementProgram.class)) {
            int numCpus = Lib_2.libbpf_num_possible_cpus();
            assertTrue(numCpus > 0);

            // getAll should have one entry per CPU.
            List<Long> initial = program.counter.getAll();
            assertEquals(numCpus, initial.size(), "getAll must return numCpus entries");

            // setAll round-trip.
            program.counter.setAll(Collections.nCopies(numCpus, 42L));
            assertTrue(program.counter.getAll().stream().allMatch(v -> v == 42L),
                    "Expected 42 on every CPU");
            assertEquals(42L * numCpus, program.counter.sumAll());

            // set(value) writes to all CPUs.
            program.counter.set(7L);
            assertEquals(7L * numCpus, program.counter.sumAll());

            // get() returns CPU 0's value.
            assertEquals(7L, program.counter.get());

            // setCpu only touches one CPU.
            program.counter.setCpu(0, 100L);
            List<Long> mixed = program.counter.getAll();
            assertEquals(100L, mixed.get(0));
            for (int i = 1; i < numCpus; i++) {
                assertEquals(7L, mixed.get(i),
                        "setCpu(0, ...) must not affect CPU " + i);
            }
        }
    }

    @Test
    @Timeout(15)
    public void testBpfIncrementAccumulates() {
        try (var program = BPFProgram.load(IncrementProgram.class)) {
            program.counter.set(0L);
            program.autoAttachPrograms();
            for (int i = 0; i < 5; i++) {
                TestUtil.triggerOpenAt();
            }
            long total = program.counter.sumAll();
            assertTrue(total >= 5, "Expected at least 5 increments, got " + total);
        }
    }

    @Test
    @Timeout(15)
    public void testBpfGetReturnsLiveSlot() {
        try (var program = BPFProgram.load(IncrementProgram.class)) {
            program.counter.set(0L);
            program.autoAttachPrograms();
            for (int i = 0; i < 3; i++) {
                TestUtil.triggerOpenAt();
            }
            long total = program.counter.sumAll();
            assertTrue(total >= 3, "Expected at least 3, got " + total);
        }
    }
}
