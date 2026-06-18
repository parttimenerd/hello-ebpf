package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests {@link BPFPerCpuArray} with multiple keys to verify that each key's
 * per-cpu values are independent and that {@code setAll}/{@code getAll}
 * and {@code sumAll} work correctly with multi-key arrays.
 */
public class PerCpuArrayMultiKeyTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        /** 4 keys, each with per-cpu values. */
        @BPFMapDefinition(maxEntries = 4)
        BPFPerCpuArray<Integer> counters;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        /**
         * Increments each per-cpu slot for its key index.
         * Key 0 incremented 1×, key 1 incremented 2×, etc.
         */
        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Increment key 0 once
            Ptr<Integer> v0 = counters.bpf_get(0);
            if (v0 != null) BPFJ.sync_fetch_and_add(v0, 1);

            // Increment key 1 twice
            Ptr<Integer> v1 = counters.bpf_get(1);
            if (v1 != null) {
                BPFJ.sync_fetch_and_add(v1, 1);
                BPFJ.sync_fetch_and_add(v1, 1);
            }

            // Increment key 2 three times
            Ptr<Integer> v2 = counters.bpf_get(2);
            if (v2 != null) {
                BPFJ.sync_fetch_and_add(v2, 1);
                BPFJ.sync_fetch_and_add(v2, 1);
                BPFJ.sync_fetch_and_add(v2, 1);
            }

            // Leave key 3 at 0.
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testMultiKeyPerCpuArray() throws InterruptedException {
        try (var program = BPFProgram.load(Program.class)) {
            int numCpus = Lib_2.libbpf_num_possible_cpus();
            assertTrue(numCpus > 0, "should have at least 1 CPU");

            // Zero-initialise all keys.
            for (int k = 0; k < 4; k++) {
                program.counters.setAll(k, Collections.nCopies(numCpus, 0));
            }

            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            // The kprobe ran on exactly one CPU so exactly that CPU's slot is incremented.
            // sumAll over all CPUs should reflect total increments.
            long sum0 = program.counters.sumAll(0);
            long sum1 = program.counters.sumAll(1);
            long sum2 = program.counters.sumAll(2);
            long sum3 = program.counters.sumAll(3);

            assertEquals(1, sum0, "key 0 sum should be 1 after 1 increment");
            assertEquals(2, sum1, "key 1 sum should be 2 after 2 increments");
            assertEquals(3, sum2, "key 2 sum should be 3 after 3 increments");
            assertEquals(0, sum3, "key 3 sum should be 0 (not incremented)");
        }
    }

    @Test
    @Timeout(10)
    public void testSetAllAndSumAll() {
        try (var program = BPFProgram.load(Program.class)) {
            int numCpus = Lib_2.libbpf_num_possible_cpus();

            // Set key 0: all CPUs = 5
            program.counters.setAll(0, Collections.nCopies(numCpus, 5));
            assertEquals(5L * numCpus, program.counters.sumAll(0),
                    "sumAll after setAll(5) should be 5 * numCpus");

            // Set key 1: all CPUs = 100
            program.counters.setAll(1, Collections.nCopies(numCpus, 100));
            assertEquals(100L * numCpus, program.counters.sumAll(1),
                    "sumAll after setAll(100) should be 100 * numCpus");

            // Verify keys don't interfere with each other.
            assertEquals(5L * numCpus, program.counters.sumAll(0),
                    "key 0 should not be affected by writes to key 1");

            // Set key 2: all CPUs = 0
            program.counters.setAll(2, Collections.nCopies(numCpus, 0));
            assertEquals(0L, program.counters.sumAll(2),
                    "sumAll after setAll(0) should be 0");
        }
    }

    @Test
    @Timeout(10)
    public void testGetAllSize() {
        try (var program = BPFProgram.load(Program.class)) {
            int numCpus = Lib_2.libbpf_num_possible_cpus();

            for (int k = 0; k < 4; k++) {
                List<Integer> vals = program.counters.getAll(k);
                assertEquals(numCpus, vals.size(),
                        "getAll(key=" + k + ") should return numCpus=" + numCpus + " elements");
            }
        }
    }
}
