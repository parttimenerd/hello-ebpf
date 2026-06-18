package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Typed-ctx with `Ptr<Integer>` (primitive box). Verifies the cast prologue
 * emits a sensible C type when the ctx is a primitive pointer rather than a
 * struct pointer.
 */
public class BpfLoopPrimitiveCtxTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        final GlobalVariable<Integer> finalSum = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            int sum = 0;
            Ptr<Integer> sp = Ptr.of(sum);
            BPFJ.<Ptr<Integer>>bpfLoop(5, (i, st) -> {
                st.set(st.val() + (i + 1));
                return 0;
            }, sp);
            finalSum.set(sp.val());
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testPrimitiveCtx() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(15, program.finalSum.get().intValue(), "1+2+3+4+5 = 15");
        }
    }
}
