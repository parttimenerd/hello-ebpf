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
 * Nested typed-ctx bpf_loop — both the outer AND the inner lambda receive
 * a typed ctx. The inner lambda mutates ITS own ctx struct (not the outer's,
 * which would require a capture and would be correctly rejected).
 */
public class BpfLoopNestedTypedCtxTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        static class Outer { int outerSum; }

        @Type
        static class Inner { int innerSum; }

        final GlobalVariable<Integer> finalOuter = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            Outer o = new Outer();
            o.outerSum = 0;
            Ptr<Outer> op = Ptr.of(o);
            // Outer 3 iterations × inner 4 iterations: each inner step adds 1 to inner.innerSum.
            // After inner loop, inner.innerSum == 4. Outer adds inner.innerSum to outer.outerSum.
            // After outer loop: outer.outerSum == 3*4 == 12.
            BPFJ.<Ptr<Outer>>bpfLoop(3, (i, op2) -> {
                Inner inn = new Inner();
                inn.innerSum = 0;
                Ptr<Inner> ip = Ptr.of(inn);
                BPFJ.<Ptr<Inner>>bpfLoop(4, (j, ip2) -> {
                    ip2.val().innerSum = ip2.val().innerSum + 1;
                    return 0;
                }, ip);
                op2.val().outerSum = op2.val().outerSum + ip.val().innerSum;
                return 0;
            }, op);
            finalOuter.set(op.val().outerSum);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testNestedTypedCtx() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(12, program.finalOuter.get().intValue(), "3 outer × 4 inner");
        }
    }
}
