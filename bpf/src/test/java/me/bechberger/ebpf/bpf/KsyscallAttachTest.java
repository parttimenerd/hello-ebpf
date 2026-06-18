package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Ksyscall;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the {@code @Ksyscall} shorthand annotation attaches and fires when
 * the named syscall is invoked.
 *
 * <p>{@code ksyscall/openat} fires on entry to the {@code openat} syscall. Unlike a
 * kprobe on {@code do_sys_openat2}, this attaches at the syscall-entry level, which is
 * portable across architectures (no ABI prefix needed).
 */
public class KsyscallAttachTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Boolean> triggered = new GlobalVariable<>(false);

        @Ksyscall("openat")
        int onSyscall(Ptr<PtDefinitions.pt_regs> ctx) {
            triggered.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testKsyscallFires() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.triggered.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.triggered.get(), "@Ksyscall on openat should have fired");
        }
    }
}
