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
 * Nested bpf_loop calls — verifies the inner lambda doesn't accidentally treat the
 * outer lambda's parameters as captured locals (capture analysis must walk into
 * nested lambdas correctly).
 */
public class BpfLoopNestedTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        final GlobalVariable<Integer> total = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            // Outer loop runs i=0..2; inner loop runs j=0..2; total += 1 each step → 9.
            BPFJ.bpfLoop(3, (i, c) -> {
                BPFJ.bpfLoop(3, (j, c2) -> {
                    total.set(total.get() + 1);
                    return 0;
                }, null);
                return 0;
            }, null);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testNestedBpfLoop() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(9, program.total.get().intValue(), "3 outer × 3 inner");
        }
    }
}
