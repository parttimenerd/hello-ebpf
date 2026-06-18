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
 * Phase D — exercises {@link BPFJ#bpfLoop} with a lambda that returns {@code 1}
 * to break out of the loop early. {@code bpf_loop} stops on a non-zero return,
 * so a request for 100 iterations that breaks after 3 should observe exactly
 * 3 increments.
 */
public class BpfLoopEarlyBreakTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        final GlobalVariable<Integer> count = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) {
                return 0;
            }
            done.set(true);
            // Request 100 iterations but break at i==3 so total visits = 3.
            BPFJ.bpfLoop(100, (i, c) -> {
                count.set(count.get() + 1);
                if (i >= 3) {
                    return 1;
                }
                return 0;
            }, null);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfLoopEarlyBreak() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(4, program.count.get().intValue(),
                    "loop should visit i=0,1,2,3 then break (return 1 happens on i==3 after increment)");
        }
    }
}
