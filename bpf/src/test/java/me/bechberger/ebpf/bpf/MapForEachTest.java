package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration test for {@link BPFHashMap#forEach} (Phase D.3).
 * <p>
 * The kprobe pre-populates a small hash map and then calls
 * {@code map.forEach((k, v) -> ...)} to count the number of entries and
 * accumulate their values into global variables. After the triggering
 * open() returns, user-space asserts the counts match.
 */
public class MapForEachTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Integer> map;

        final GlobalVariable<Integer> count = new GlobalVariable<>(0);
        final GlobalVariable<Integer> sum = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) {
                return 0;
            }
            done.set(true);
            // Insert three known entries.
            int k0 = 1, v0 = 10;
            int k1 = 2, v1 = 20;
            int k2 = 3, v2 = 30;
            map.put(k0, v0);
            map.put(k1, v1);
            map.put(k2, v2);
            // Reset accumulators (defensive — this kprobe runs at most once).
            count.set(0);
            sum.set(0);
            // Iterate via bpf_for_each_map_elem; lambda must NOT capture locals.
            // Per-entry state lives in global variables, which are addressable.
            map.forEach((k, v) -> {
                count.set(count.get() + 1);
                sum.set(sum.get() + v);
                return 0;
            }, null);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testMapForEach() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(3, program.count.get().intValue(), "forEach should visit all 3 entries");
            assertEquals(60, program.sum.get().intValue(), "forEach should sum values 10+20+30=60");
        }
    }
}
