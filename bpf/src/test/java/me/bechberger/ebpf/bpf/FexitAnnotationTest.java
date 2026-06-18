package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Fexit;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the {@code @Fexit} shorthand annotation attaches and fires correctly.
 *
 * <p>An fexit probe fires on return from the probed BTF-annotated kernel function.
 * This tests the {@link me.bechberger.ebpf.annotations.bpf.Fexit} annotation as a
 * shorthand for {@code @BPFFunction(section = "fexit/<fn>", autoAttach = true)}.
 */
public class FexitAnnotationTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Boolean> triggered = new GlobalVariable<>(false);

        @Fexit("do_sys_openat2")
        int onExit(Ptr<PtDefinitions.pt_regs> ctx) {
            triggered.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testFexitFires() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.triggered.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.triggered.get(), "@Fexit on do_sys_openat2 should have fired");
        }
    }
}
