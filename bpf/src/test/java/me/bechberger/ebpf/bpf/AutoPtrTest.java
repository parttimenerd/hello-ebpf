package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Verifies that Ptr.of(value) correctly generates &value in C and
 * that passing a struct pointer to a @BPFFunction works end-to-end.
 */
public class AutoPtrTest {

    @BPF(license = "GPL")
    public static abstract class AutoPtrProgram extends BPFProgram {

        @Type
        record Pair(int a, int b) {}

        @BPFMapDefinition(maxEntries = 1)
        BPFArray<Pair> result;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        /** Helper that receives a Pair by pointer and stores a*b in the map. */
        @BPFFunction
        void store(Ptr<Pair> p) {
            Pair out = new Pair(p.val().a * p.val().b, 0);
            result.put(0, out);
        }

        @Kprobe("do_sys_openat2")
        int probe(Ptr<PtDefinitions.pt_regs> ctx) {
            Pair local = new Pair(3, 7);
            store(Ptr.of(local));  // Ptr.of(x) → &x in generated C
            done.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(5)
    public void testPtrOf() {
        try (var program = BPFProgram.load(AutoPtrProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            while (!program.done.get()) {}
            var pair = program.result.get(0);
            assertEquals(21, pair.a(), "3 * 7 should be 21");
        }
    }
}
