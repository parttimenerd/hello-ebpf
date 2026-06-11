package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Integration test for {@link BPFJ#bpfLoop} (Phase D.3).
 * <p>
 * The probe runs once on {@code do_sys_openat2}, calls {@code BPFJ.bpfLoop(10, ...)}
 * and accumulates {@code 0..9} into the global variable {@code sum}. After the
 * triggering open() returns, user-space asserts {@code sum == 45}.
 */
public class BpfLoopTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Integer> sum = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @BPFFunction(
                section = "kprobe/do_sys_openat2",
                autoAttach = true
        )
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) {
                return 0;
            }
            done.set(true);
            // Sum 0..9 via bpf_loop. The lambda captures nothing — accumulator lives
            // in the global variable, which is addressable from the lifted C function.
            BPFJ.bpfLoop(10, (i, c) -> {
                sum.set(sum.get() + i);
                return 0;
            }, null);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfLoopSum() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            // Trigger the kprobe. The probe is gated by `done` so subsequent opens are no-ops.
            TestUtil.triggerOpenAt();
            // Wait briefly for the kprobe to run; busy-poll on `done` keeps the test fast.
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertEquals(true, program.done.get(), "kprobe never fired");
            assertEquals(45, program.sum.get().intValue(), "bpf_loop should accumulate 0..9 = 45");
        }
    }
}
