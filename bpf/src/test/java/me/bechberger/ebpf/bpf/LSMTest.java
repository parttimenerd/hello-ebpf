package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.LSM;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for {@code @LSM} hook programs.
 *
 * <p>Requires {@code CONFIG_BPF_LSM=y} and {@code lsm=...,bpf} — VNG boots the
 * reference kernel which has both.
 */
public class LSMTest {

    @BPF(license = "GPL")
    public static abstract class FileOpenProgram extends BPFProgram {
        final GlobalVariable<Boolean> triggered = new GlobalVariable<>(false);

        @LSM("file_open")
        int onFileOpen(Ptr<runtime.file> file) {
            triggered.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testLsmFileOpenFires() {
        assumeTrue(BPFProgram.isLSMEnabled(), "BPF LSM not enabled on this kernel");
        try (var program = BPFProgram.load(FileOpenProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            assertTrue(program.triggered.get(), "@LSM(file_open) should have fired on file open");
        }
    }

    // ── deny test ────────────────────────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class DenyBpfProgram extends BPFProgram {
        final GlobalVariable<Integer> callCount = new GlobalVariable<>(0);

        @LSM("bpf")
        int onBpf(int cmd, Ptr<?> attr, int size) {
            callCount.set(callCount.get() + 1);
            return 0;  // allow — we just count
        }
    }

    @Test
    @Timeout(10)
    public void testLsmBpfHookFires() {
        assumeTrue(BPFProgram.isLSMEnabled(), "BPF LSM not enabled on this kernel");
        try (var program = BPFProgram.load(DenyBpfProgram.class)) {
            program.autoAttachPrograms();
            // Trigger another BPF syscall by creating a temporary program
            TestUtil.triggerOpenAt();
            // The hook fires on BPF syscalls; at minimum our own load triggers it
            assertTrue(program.callCount.get() > 0, "@LSM(bpf) should have counted at least one BPF syscall");
        }
    }
}
