package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Additional integration tests for {@link BPFHashMap} focusing on BPF-side helpers:
 * <ul>
 *   <li>BPF-side {@code put} then {@code bpf_get} round-trip.</li>
 *   <li>Multiple values written from BPF are all visible from Java.</li>
 *   <li>{@code bpf_getOrDefault} with absent key returns the supplied default.</li>
 *   <li>BPF-side delete removes the entry.</li>
 * </ul>
 */
public class HashMapBpfOperationsTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Integer> map;

        final GlobalVariable<Integer> lookupResult  = new GlobalVariable<>(0);
        final GlobalVariable<Integer> defaultResult = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> deleteOk      = new GlobalVariable<>(false);
        final GlobalVariable<Boolean> done          = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Insert entries from BPF side (unrolled to avoid verifier E2BIG).
            map.put(0, 0);
            map.put(1, 1);
            map.put(2, 4);
            map.put(3, 9);
            map.put(4, 16);

            // Lookup key 3 → should return 9.
            Ptr<Integer> v3 = map.bpf_get(3);
            if (v3 != null) lookupResult.set(v3.val());

            // getOrDefault: key 100 absent → returns 42.
            defaultResult.set(map.bpf_getOrDefault(100, 42));

            // Delete key 2; subsequent lookup should fail.
            int key2 = 2;
            map.bpf_delete(key2);
            Ptr<Integer> after = map.bpf_get(key2);
            deleteOk.set(after == null);

            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfHashMapOperations() throws InterruptedException {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            // Verify BPF-side put results are visible from Java.
            assertEquals(0, program.map.get(0).intValue(), "map[0] = 0^2 = 0");
            assertEquals(1, program.map.get(1).intValue(), "map[1] = 1^2 = 1");
            // key 2 was deleted
            assertNull(program.map.get(2), "map[2] should be null after BPF-side delete");
            assertEquals(9, program.map.get(3).intValue(), "map[3] = 3^2 = 9");
            assertEquals(16, program.map.get(4).intValue(), "map[4] = 4^2 = 16");

            // Verify BPF-side lookup and default results.
            assertEquals(9,  program.lookupResult.get().intValue(),
                    "bpf_get(3) should return 9");
            assertEquals(42, program.defaultResult.get().intValue(),
                    "bpf_getOrDefault(100, 42) should return 42");
            assertTrue(program.deleteOk.get(),
                    "bpf_get(2) after delete should return null");
        }
    }

    /**
     * Verifies that Java-written entries are readable from BPF via {@code bpf_get}.
     */
    @BPF(license = "GPL")
    public static abstract class JavaWriteBpfReadProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Integer> map;

        // Stores the values read by BPF for keys 10, 20, 30.
        @BPFMapDefinition(maxEntries = 3)
        BPFArray<Integer> bpfReadValues;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Read BPF-visible values for keys 10, 20, 30 (unrolled).
            Ptr<Integer> v0 = map.bpf_get(10);
            if (v0 == null) return 0;
            bpfReadValues.put(0, v0.val());
            Ptr<Integer> v1 = map.bpf_get(20);
            if (v1 == null) return 0;
            bpfReadValues.put(1, v1.val());
            Ptr<Integer> v2 = map.bpf_get(30);
            if (v2 == null) return 0;
            bpfReadValues.put(2, v2.val());
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testJavaWriteBpfRead() throws InterruptedException {
        try (var program = BPFProgram.load(JavaWriteBpfReadProgram.class)) {
            // Write from Java before attaching BPF.
            program.map.put(10, 111);
            program.map.put(20, 222);
            program.map.put(30, 333);

            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            assertEquals(111, program.bpfReadValues.get(0).intValue(),
                    "BPF bpf_get(10) should see Java-written value 111");
            assertEquals(222, program.bpfReadValues.get(1).intValue(),
                    "BPF bpf_get(20) should see Java-written value 222");
            assertEquals(333, program.bpfReadValues.get(2).intValue(),
                    "BPF bpf_get(30) should see Java-written value 333");
        }
    }
}
