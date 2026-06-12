package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Lambda body that declares a local @Type struct on the BPF stack. Lifted
 * lambda is __always_inline so the local should reuse the caller's stack.
 */
public class BpfLoopLocalStructTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        static class Pair { int a; int b; }

        final GlobalVariable<Integer> finalSum = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            // For each i in 0..4, build Pair{a=i, b=i*2}, total += a+b = 3*i.
            // Sum: 0+3+6+9+12 = 30.
            BPFJ.bpfLoop(5, (i, c) -> {
                Pair p = new Pair();
                p.a = i;
                p.b = i * 2;
                finalSum.set(finalSum.get() + p.a + p.b);
                return 0;
            }, null);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testLambdaLocalStruct() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(30, program.finalSum.get().intValue(), "sum of (i + 2i) for i=0..4");
        }
    }
}
