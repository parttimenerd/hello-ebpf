package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for BPF-side atomic operations via {@link BPFJ}:
 * <ul>
 *   <li>{@link BPFJ#sync_fetch_and_add} — atomic fetch-and-add (returns old value)</li>
 *   <li>{@link BPFJ#sync_add_and_fetch} — atomic add-and-fetch (returns new value)</li>
 *   <li>{@link BPFJ#sync_fetch_and_sub} — atomic fetch-and-sub (returns old value)</li>
 *   <li>{@link BPFJ#sync_sub_and_fetch} — atomic sub-and-fetch (returns new value)</li>
 *   <li>{@link BPFJ#sync_fetch_and_or} — atomic fetch-and-or</li>
 *   <li>{@link BPFJ#sync_fetch_and_and} — atomic fetch-and-and</li>
 * </ul>
 *
 * <p>Each operation is performed from a kprobe on {@code do_sys_openat2} and the results
 * (both the return value and the updated map entry) are checked from user-space.
 */
public class BpfAtomicOpsTest {

    /**
     * Index constants for the {@code results} BPFArray:
     * <pre>
     *   0 — initial value written to map slot 0 before atomic op
     *   1 — return value of sync_fetch_and_add(ptr, 5)   → old value
     *   2 — map value after sync_fetch_and_add            → initial + 5
     *   3 — return value of sync_add_and_fetch(ptr, 3)   → new value (initial+5+3)
     *   4 — map value after sync_add_and_fetch
     *   5 — return value of sync_fetch_and_sub(ptr, 2)   → old value
     *   6 — map value after sync_fetch_and_sub
     *   7 — return value of sync_sub_and_fetch(ptr, 1)   → new value
     *   8 — map value after sync_sub_and_fetch
     * </pre>
     */
    @BPF(license = "GPL")
    public static abstract class AtomicProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 10)
        BPFArray<Integer> results;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        // The value we perform atomics on lives in a BPFArray; bpf_get returns a
        // Ptr<Integer> (a direct reference into map memory) that we can pass to
        // the __sync_* builtins.
        @BPFMapDefinition(maxEntries = 2)
        BPFArray<Integer> counter;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Initialise counter[0] = 10.
            counter.put(0, 10);
            Ptr<Integer> cptr = counter.bpf_get(0);
            if (cptr == null) return 0;

            // Save the initial value.
            results.put(0, cptr.val());

            // sync_fetch_and_add: returns OLD value, then adds 5
            // counter before: 10, returns 10, counter after: 15
            int oldVal = BPFJ.sync_fetch_and_add(cptr, 5);
            results.put(1, oldVal);
            results.put(2, cptr.val());

            // sync_add_and_fetch: adds 3, returns NEW value
            // counter before: 15, counter after: 18, returns 18
            int newVal = BPFJ.sync_add_and_fetch(cptr, 3);
            results.put(3, newVal);
            results.put(4, cptr.val());

            // sync_fetch_and_sub: returns OLD value, then subtracts 2
            // counter before: 18, returns 18, counter after: 16
            int oldVal2 = BPFJ.sync_fetch_and_sub(cptr, 2);
            results.put(5, oldVal2);
            results.put(6, cptr.val());

            // sync_sub_and_fetch: subtracts 1, returns NEW value
            // counter before: 16, counter after: 15, returns 15
            int newVal2 = BPFJ.sync_sub_and_fetch(cptr, 1);
            results.put(7, newVal2);
            results.put(8, cptr.val());

            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testAtomicFetchAndAdd() throws InterruptedException {
        try (var program = BPFProgram.load(AtomicProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            int initial   = program.results.get(0);
            int fetchAdd  = program.results.get(1); // returned old value
            int afterAdd  = program.results.get(2); // new counter value
            int addFetch  = program.results.get(3); // returned new value
            int afterAdd2 = program.results.get(4);
            int fetchSub  = program.results.get(5); // returned old value
            int afterSub  = program.results.get(6);
            int subFetch  = program.results.get(7); // returned new value
            int afterSub2 = program.results.get(8);

            assertEquals(10, initial, "initial counter value should be 10");

            // fetch_and_add(10, 5) → returns 10, counter becomes 15
            assertEquals(10, fetchAdd, "sync_fetch_and_add should return old value 10");
            assertEquals(15, afterAdd, "counter after +5 should be 15");

            // add_and_fetch(15, 3) → counter becomes 18, returns 18
            assertEquals(18, addFetch, "sync_add_and_fetch should return new value 18");
            assertEquals(18, afterAdd2, "counter after +3 should be 18");

            // fetch_and_sub(18, 2) → returns 18, counter becomes 16
            assertEquals(18, fetchSub, "sync_fetch_and_sub should return old value 18");
            assertEquals(16, afterSub, "counter after -2 should be 16");

            // sub_and_fetch(16, 1) → counter becomes 15, returns 15
            assertEquals(15, subFetch, "sync_sub_and_fetch should return new value 15");
            assertEquals(15, afterSub2, "counter after -1 should be 15");
        }
    }

    /**
     * Tests {@link BPFJ#sync_fetch_and_or} and {@link BPFJ#sync_fetch_and_and}
     * on bit-mask values.
     */
    @BPF(license = "GPL")
    public static abstract class BitwiseProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 6)
        BPFArray<Integer> results;

        // bits[0] is the value we apply bitwise atomics to.
        @BPFMapDefinition(maxEntries = 2)
        BPFArray<Integer> bits;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Initialise bits[0] = 0b1010 (10).
            bits.put(0, 0b1010);
            Ptr<Integer> bptr = bits.bpf_get(0);
            if (bptr == null) return 0;

            // OR with 0b0101 (5): 0b1010 | 0b0101 = 0b1111 (15), returns old 0b1010 (10)
            results.put(0, bptr.val());
            int oldOr = BPFJ.sync_fetch_and_or(bptr, 0b0101);
            results.put(1, oldOr);
            results.put(2, bptr.val());

            // AND with 0b1100 (12): 0b1111 & 0b1100 = 0b1100 (12), returns old 0b1111 (15)
            int oldAnd = BPFJ.sync_fetch_and_and(bptr, 0b1100);
            results.put(3, oldAnd);
            results.put(4, bptr.val());

            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testAtomicBitwiseOps() throws InterruptedException {
        try (var program = BPFProgram.load(BitwiseProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            int initial  = program.results.get(0);
            int oldOr    = program.results.get(1);
            int afterOr  = program.results.get(2);
            int oldAnd   = program.results.get(3);
            int afterAnd = program.results.get(4);

            assertEquals(0b1010, initial, "initial bits should be 0b1010 (10)");
            assertEquals(0b1010, oldOr,   "OR should return old value 0b1010 (10)");
            assertEquals(0b1111, afterOr,  "0b1010 | 0b0101 should give 0b1111 (15)");
            assertEquals(0b1111, oldAnd,   "AND should return old value 0b1111 (15)");
            assertEquals(0b1100, afterAnd, "0b1111 & 0b1100 should give 0b1100 (12)");
        }
    }
}
