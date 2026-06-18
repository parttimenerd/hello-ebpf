package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises chained {@code @BPFFunction} helpers: the kprobe calls a helper,
 * which calls another helper, forming a 3-level call stack.
 *
 * <p>This verifies that:
 * <ul>
 *   <li>A {@code @BPFFunction} can call another {@code @BPFFunction} (call-chaining).</li>
 *   <li>Return values flow correctly through the chain.</li>
 *   <li>All three levels participate in the computation and the final result is correct.</li>
 * </ul>
 *
 * <p>Logic: the probe calls {@code add(3, 4)}, which calls {@code multiply(3, 2)}.
 * {@code multiply} returns 6; {@code add} returns 6 + 4 = 10; the probe stores 10.
 */
public class ChainedBpfFunctionTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        final GlobalVariable<Integer> result = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        /** Level 2: multiply two integers and return the product. */
        @BPFFunction
        int multiply(int a, int b) {
            return a * b;
        }

        /** Level 1: return {@code multiply(a, 2) + b}. */
        @BPFFunction
        int add(int a, int b) {
            return multiply(a, 2) + b;
        }

        /** Level 0 (kprobe): call add(3, 4) = multiply(3,2) + 4 = 6 + 4 = 10. */
        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);
            result.set(add(3, 4));
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testChainedBpfFunctions() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(10, program.result.get().intValue(),
                    "add(3,4) = multiply(3,2)+4 = 6+4 should be 10");
        }
    }
}
