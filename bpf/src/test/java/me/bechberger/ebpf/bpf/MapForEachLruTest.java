package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * BPFLRUHashMap.forEach inherits from BPFHashMap. Verify the inherited helper
 * lifts the lambda correctly when the receiver is the LRU subclass.
 */
public class MapForEachLruTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFLRUHashMap<Integer, Integer> map;

        final GlobalVariable<Integer> count = new GlobalVariable<>(0);
        final GlobalVariable<Integer> sum = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            int k0 = 1, v0 = 100;
            int k1 = 2, v1 = 200;
            map.put(k0, v0);
            map.put(k1, v1);
            count.set(0);
            sum.set(0);
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
    public void testLruForEach() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(2, program.count.get().intValue());
            assertEquals(300, program.sum.get().intValue());
        }
    }
}
