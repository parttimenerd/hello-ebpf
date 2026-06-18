package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFPerCpuHashMap;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for {@link BPFPerCpuHashMap}.
 *
 * <p>A kprobe on {@code do_sys_openat2} increments a per-CPU counter keyed by 0.
 * The Java side reads back all per-CPU values and verifies the sum equals the
 * number of open-at calls made.
 */
public class PerCpuHashMapTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFPerCpuHashMap<Integer, Long> counter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int countOpenAt(Ptr<PtDefinitions.pt_regs> ctx) {
            int key = 0;
            Ptr<Long> val = counter.bpf_get(key);
            if (val != null) {
                BPFJ.sync_fetch_and_add(val, 1L);
            } else {
                long one = 1L;
                counter.bpf_put(key, one);
            }
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testPerCpuHashCounter() {
        try (var program = BPFProgram.load(Program.class)) {
            int numCpus = Lib_2.libbpf_num_possible_cpus();
            assertTrue(numCpus > 0);

            // Seed value 0 on all CPUs so BPF increments work without a branch
            program.counter.putAll(0, Collections.nCopies(numCpus, 0L));

            // Java-side round-trip
            List<Long> all = program.counter.getAll(0);
            assertEquals(numCpus, all.size());
            assertTrue(all.stream().allMatch(v -> v == 0L));

            // sumAll before BPF activity
            assertEquals(0L, program.counter.sumAll(0));

            // Attach and trigger syscalls
            program.autoAttachPrograms();
            for (int i = 0; i < 5; i++) {
                TestUtil.triggerOpenAt();
            }

            long total = program.counter.sumAll(0);
            assertTrue(total >= 5,
                    "Expected sum >= 5 openat calls across all CPUs, got " + total);

            // delete removes the entry
            assertTrue(program.counter.delete(0));
            assertTrue(program.counter.getAll(0).isEmpty());
        }
    }
}
