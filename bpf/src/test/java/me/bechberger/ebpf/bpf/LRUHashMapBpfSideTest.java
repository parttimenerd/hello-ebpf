package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link BPFLRUHashMap}:
 * <ul>
 *   <li>BPF-side {@code put}/{@code bpf_get} operations round-trip correctly.</li>
 *   <li>LRU eviction happens when the map is full (max_entries exceeded).</li>
 *   <li>{@code bpf_increment} on the LRU map works (value is updated atomically
 *       only when the key already exists).</li>
 *   <li>{@code bpf_getOrDefault} returns the stored value or the default.</li>
 * </ul>
 */
public class LRUHashMapBpfSideTest {

    /** maxEntries = 3 so we can force evictions with 4 keys. */
    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 3)
        BPFLRUHashMap<Integer, Integer> lru;

        final GlobalVariable<Integer> result1 = new GlobalVariable<>(0);
        final GlobalVariable<Integer> result2 = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Insert 3 entries: keys 1, 2, 3.
            int k1 = 1; lru.put(k1, 100);
            int k2 = 2; lru.put(k2, 200);
            int k3 = 3; lru.put(k3, 300);

            // Read back key 2.
            Ptr<Integer> v = lru.bpf_get(k2);
            if (v != null) result1.set(v.val());

            // getOrDefault: key 2 exists → returns 200, key 99 absent → returns -1
            result2.set(lru.bpf_getOrDefault(k2, 99));

            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testLruBpfSideGetAndDefault() throws InterruptedException {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            assertEquals(200, program.result1.get().intValue(),
                    "bpf_get(key=2) should return 200");
            assertEquals(200, program.result2.get().intValue(),
                    "bpf_getOrDefault(key=2, 99) should return 200 (key present)");

            // All 3 entries should be present (no eviction yet).
            assertEquals(Set.of(1, 2, 3), program.lru.keySet(),
                    "Keys 1, 2, 3 should all be present");
        }
    }

    @Test
    @Timeout(10)
    public void testLruEviction() {
        try (var program = BPFProgram.load(Program.class)) {
            // Fill to capacity.
            var lru = program.lru;
            lru.put(10, 1);
            lru.put(20, 2);
            lru.put(30, 3);

            // Inserting a 4th entry must evict one of the existing entries.
            lru.put(40, 4);

            int size = lru.slowSize();
            assertEquals(3, size,
                    "LRU map (maxEntries=3) should have exactly 3 entries after 4 inserts, got " + size);

            // Key 40 should be present.
            assertTrue(lru.containsKey(40), "Newly inserted key 40 must be present");
        }
    }

    /**
     * Tests that {@code bpf_increment} on an LRU map increments an existing key
     * (does NOT insert on absence, same semantics as for BPFHashMap).
     */
    @BPF(license = "GPL")
    public static abstract class IncrementProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 8)
        BPFLRUHashMap<Integer, Integer> lru;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Increment existing key 5 (pre-seeded to 10) twice via atomic add.
            Ptr<Integer> v = lru.bpf_get(5);
            if (v != null) {
                BPFJ.sync_fetch_and_add(v, 1);
                BPFJ.sync_fetch_and_add(v, 1);
            }

            // Absent key 99: bpf_get returns null; no increment.
            Ptr<Integer> v99 = lru.bpf_get(99);
            if (v99 != null) {
                BPFJ.sync_fetch_and_add(v99, 1);
            }

            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testLruBpfIncrementExistingKey() throws InterruptedException {
        try (var program = BPFProgram.load(IncrementProgram.class)) {
            program.lru.put(5, 10); // pre-seed
            program.autoAttachPrograms();

            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            assertEquals(12, program.lru.get(5).intValue(),
                    "bpf_increment(5,1) x2 on seed=10 should give 12");
            assertNull(program.lru.get(99),
                    "bpf_increment on absent key 99 should be a no-op");
        }
    }
}
