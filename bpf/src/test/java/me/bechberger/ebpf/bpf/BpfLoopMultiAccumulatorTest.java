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
 * Phase D — exercises {@link BPFJ#bpfLoop} with a non-trivial body that uses
 * the iteration index {@code i} in arithmetic and conditionally updates two
 * different global accumulators. Complements {@code BpfLoopTest} (single
 * accumulator) by proving multi-state and conditional logic survive the
 * lambda lift.
 */
public class BpfLoopMultiAccumulatorTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        final GlobalVariable<Integer> evenSum = new GlobalVariable<>(0);
        final GlobalVariable<Integer> oddSum = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) {
                return 0;
            }
            done.set(true);
            // 0..9: 0+2+4+6+8 = 20 even; 1+3+5+7+9 = 25 odd.
            BPFJ.bpfLoop(10, (i, c) -> {
                if (i % 2 == 0) {
                    evenSum.set(evenSum.get() + i);
                } else {
                    oddSum.set(oddSum.get() + i);
                }
                return 0;
            }, null);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfLoopMultiAccumulator() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(0 + 2 + 4 + 6 + 8, program.evenSum.get().intValue(),
                    "evenSum should be 20");
            assertEquals(1 + 3 + 5 + 7 + 9, program.oddSum.get().intValue(),
                    "oddSum should be 25");
        }
    }
}
