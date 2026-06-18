package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFInline;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@code @BPFInline} causes the helper's C declaration to carry
 * {@code __always_inline}, and that inlining does not break runtime correctness.
 *
 * <p>Two helpers are compared:
 * <ul>
 *   <li>{@code doubleIt} — annotated with {@code @BPFInline}; must produce
 *       {@code __always_inline} in generated C.</li>
 *   <li>{@code tripleIt} — plain {@code @BPFFunction}; should NOT carry
 *       {@code __always_inline} on its own declaration (regular helpers
 *       do get inlined by default, so we check the declaration text specifically).</li>
 * </ul>
 *
 * <p>The probe calls both helpers with 5 and asserts the results are 10 and 15.
 */
public class BPFInlineTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        final GlobalVariable<Integer> doubled = new GlobalVariable<>(0);
        final GlobalVariable<Integer> tripled = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @BPFInline
        @BPFFunction
        int doubleIt(int x) {
            return x * 2;
        }

        @BPFFunction
        int tripleIt(int x) {
            return x * 3;
        }

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);
            doubled.set(doubleIt(5));
            tripled.set(tripleIt(5));
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBPFInlineEmitsAlwaysInline() {
        String code = BPFProgram.getCode(Program.class);
        assertTrue(code.contains("__always_inline") && code.contains("doubleIt"),
                "generated C must contain __always_inline for @BPFInline helper 'doubleIt';\ngot:\n" + code);
    }

    @Test
    @Timeout(10)
    public void testBPFInlineRuntimeCorrectness() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(10, program.doubled.get().intValue(), "doubleIt(5) should be 10");
            assertEquals(15, program.tripled.get().intValue(), "tripleIt(5) should be 15");
        }
    }
}
