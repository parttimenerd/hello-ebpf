package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFProgArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real-kernel test for {@link BPFProgArray#replaceSlot}. Slot 0 initially
 * points at {@code countA}; after {@code replaceSlot(0, countB)} more traffic
 * is routed through {@code countB}. Both counters must reflect the swap.
 */
public class TailCallReplaceSlotTest {

    @BPF(license = "GPL")
    public abstract static class Prog extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1)
        BPFProgArray progs;

        final GlobalVariable<Integer> callsA = new GlobalVariable<>(0);
        final GlobalVariable<Integer> callsB = new GlobalVariable<>(0);

        @BPFFunction(section = "kprobe/do_sys_openat2")
        int countA(Ptr<PtDefinitions.pt_regs> ctx) {
            callsA.set(callsA.get() + 1);
            return 0;
        }

        // A second kprobe program that counts B invocations.
        // Loaded in the same object; the test swaps slot 0 to point here.
        @BPFFunction(section = "kprobe/do_sys_openat2")
        int countB(Ptr<PtDefinitions.pt_regs> ctx) {
            callsB.set(callsB.get() + 1);
            return 0;
        }

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            progs.tailCall(ctx, 0);
            return 0;
        }
    }

    @Test
    @Timeout(30)
    public void replaceSlotHotSwapsTarget() throws InterruptedException {
        try (Prog p = BPFProgram.load(Prog.class)) {
            p.progs.register(0, p.getProgramByName("countA"));
            p.autoAttachPrograms();

            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);
            int aBefore = p.callsA.get();
            int bBefore = p.callsB.get();
            assertTrue(aBefore >= 3, "countA should have fired: " + aBefore);
            assertTrue(bBefore == 0, "countB must be 0 before replaceSlot: " + bBefore);

            // Hot-swap slot 0 to point at countB.
            p.progs.replaceSlot(0, p.getProgramByName("countB"));

            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);
            int bAfter = p.callsB.get();
            // countA MAY still tick from in-flight tail calls, so only assert
            // that countB has advanced strictly after the swap.
            assertTrue(bAfter >= 3, "countB should have fired after swap: " + bAfter);
            assertTrue(bAfter > bBefore, "callsB must have advanced: "
                    + bBefore + " -> " + bAfter);
        }
    }
}
