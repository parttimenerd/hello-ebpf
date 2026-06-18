package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Fentry;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for shorthand attach annotations ({@code @Kprobe}, {@code @Fentry}, etc.).
 */
public class AttachAnnotationTest {

    @BPF(license = "GPL")
    public static abstract class KprobeProgram extends BPFProgram {
        final GlobalVariable<Boolean> triggered = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int probe(Ptr<PtDefinitions.pt_regs> ctx) {
            triggered.set(true);
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class FentryProgram extends BPFProgram {
        final GlobalVariable<Boolean> triggered = new GlobalVariable<>(false);

        @Fentry("do_sys_openat2")
        int probe(Ptr<PtDefinitions.pt_regs> ctx) {
            triggered.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(5)
    public void testKprobe() {
        try (var program = BPFProgram.load(KprobeProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            assertTrue(program.triggered.get(), "@Kprobe should have fired");
        }
    }

    @Test
    @Timeout(5)
    public void testFentry() {
        try (var program = BPFProgram.load(FentryProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            assertTrue(program.triggered.get(), "@Fentry should have fired");
        }
    }
}
