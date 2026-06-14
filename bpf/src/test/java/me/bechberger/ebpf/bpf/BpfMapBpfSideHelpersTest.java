package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for the BPF-side map helpers defined in {@link me.bechberger.ebpf.bpf.map.BPFBaseMap}:
 * <ul>
 *   <li>{@code bpf_increment(key, delta)} — atomically increments the value at a key</li>
 *   <li>{@code bpf_getOrDefault(key, defaultValue)} — reads a value or returns a default</li>
 * </ul>
 * Both helpers are annotated with {@code @BuiltinBPFFunction} and {@code @NotUsableInJava}.
 * These tests verify the BPF-side path by running a kprobe that uses them, then reading
 * the result user-side via normal Java map accessors.
 */
public class BpfMapBpfSideHelpersTest {

    @BPF(license = "GPL")
    public static abstract class IncrementProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Integer> counters;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);
            // Increment key 1 three times (by 1 each time)
            counters.bpf_increment(1, 1);
            counters.bpf_increment(1, 1);
            counters.bpf_increment(1, 1);
            // Increment key 2 once by 10
            counters.bpf_increment(2, 10);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfIncrementFromKprobe() {
        try (var program = BPFProgram.load(IncrementProgram.class)) {
            program.autoAttachPrograms();

            // Pre-seed key 1 with 5 so we test increment on an existing entry.
            program.counters.put(1, 5);

            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");

            // key 1: started at 5, incremented 3×1 = +3 → 8
            assertEquals(8, program.counters.get(1).intValue(),
                    "bpf_increment(1,1) x3 on seed 5 should give 8");

            // key 2: absent, bpf_increment on absent key is a no-op (bpf_map_lookup_elem returns NULL)
            // Verify key 2 is still absent (bpf_increment only updates if key exists)
            assertNull(program.counters.get(2),
                    "bpf_increment on absent key 2 should be a no-op, key should remain absent");
        }
    }

    @BPF(license = "GPL")
    public static abstract class GetOrDefaultProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Integer> data;

        final GlobalVariable<Integer> resultPresent = new GlobalVariable<>(0);
        final GlobalVariable<Integer> resultAbsent = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // key 7 is pre-seeded to 42 from user-space; getOrDefault should return 42
            resultPresent.set(data.bpf_getOrDefault(7, -1));

            // key 99 is absent; getOrDefault should return the default (99)
            resultAbsent.set(data.bpf_getOrDefault(99, 99));

            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfGetOrDefaultFromKprobe() {
        try (var program = BPFProgram.load(GetOrDefaultProgram.class)) {
            program.autoAttachPrograms();

            // Pre-seed key 7 → 42 before firing the probe
            program.data.put(7, 42);

            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");

            assertEquals(42, program.resultPresent.get().intValue(),
                    "bpf_getOrDefault with present key 7 should return 42");
            assertEquals(99, program.resultAbsent.get().intValue(),
                    "bpf_getOrDefault with absent key 99 should return default 99");
        }
    }
}
