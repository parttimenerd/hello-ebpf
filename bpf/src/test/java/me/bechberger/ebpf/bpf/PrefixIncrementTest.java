package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Verifies that the prefix-increment ({@code ++x}) and prefix-decrement ({@code --x})
 * operators emit correctly as C prefix operators (not postfix).
 *
 * <p>The fix in CAST.java added dedicated PREFIX_INCREMENT / PREFIX_DECREMENT operators
 * so that {@code ++x} generates {@code ++x} in C. Before the fix, both prefix and
 * postfix increment were emitted as {@code x++}.
 */
public class PrefixIncrementTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        final GlobalVariable<Integer> counter = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // prefix increment/decrement: ++n must yield the new value immediately
            int n = 3;
            ++n;   // n becomes 4
            ++n;   // n becomes 5
            --n;   // n becomes 4
            counter.set(n);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testPrefixIncDecYieldsCorrectValue() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertEquals(true, program.done.get(), "kprobe never fired");
            // 3 → ++n,++n,--n → 4
            assertEquals(4, program.counter.get().intValue(),
                    "prefix ++/-- should: 3 -> ++,++ -> 5 -> -- -> 4");
        }
    }
}
