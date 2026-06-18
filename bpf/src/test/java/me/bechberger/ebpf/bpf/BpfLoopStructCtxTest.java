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
 * Phase D — exercises {@link BPFJ#bpfLoop} where {@code ctx} is a typed
 * pointer to a stack-allocated struct carrying multi-field state. Proves
 * the user can thread state through ctx instead of GlobalVariables,
 * matching how idiomatic BPF C uses bpf_loop.
 */
public class BpfLoopStructCtxTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        static class State {
            int sum;
            int product;
        }

        final GlobalVariable<Integer> finalSum = new GlobalVariable<>(0);
        final GlobalVariable<Integer> finalProduct = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) {
                return 0;
            }
            done.set(true);
            State s = new State();
            s.sum = 0;
            s.product = 1;
            Ptr<State> sp = Ptr.of(s);
            BPFJ.<Ptr<State>>bpfLoop(5, (i, st) -> {
                st.val().sum = st.val().sum + (i + 1);
                st.val().product = st.val().product * (i + 1);
                return 0;
            }, sp);
            // 1+2+3+4+5 = 15;  1*2*3*4*5 = 120
            finalSum.set(sp.val().sum);
            finalProduct.set(sp.val().product);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfLoopStructCtx() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(15, program.finalSum.get().intValue(),
                    "ctx struct sum should be 1+2+3+4+5=15");
            assertEquals(120, program.finalProduct.get().intValue(),
                    "ctx struct product should be 1*2*3*4*5=120");
        }
    }
}
