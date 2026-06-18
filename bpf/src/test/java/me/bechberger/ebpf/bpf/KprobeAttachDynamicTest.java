package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link BPFProgram#attachKProbe(BPFProgram.ProgramHandle, String)} and
 * {@link BPFProgram#attachKProbe(BPFProgram.ProgramHandle, String, boolean)} attach and
 * fire kprobes dynamically at runtime (no compile-time {@code @Kprobe} annotation).
 *
 * <p>Runs two sub-tests:
 * <ol>
 *   <li>kprobe (entry) — {@code attachKProbe(prog, "do_sys_openat2")}
 *   <li>kretprobe (return) — {@code attachKProbe(prog, "do_sys_openat2", true)}
 * </ol>
 */
public class KprobeAttachDynamicTest {

    @BPF(license = "GPL")
    public static abstract class KprobeProgram extends BPFProgram {
        final GlobalVariable<Integer> kprobeCount = new GlobalVariable<>(0);

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int onEntry(Ptr<PtDefinitions.pt_regs> ctx) {
            kprobeCount.set(kprobeCount.get() + 1);
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class KretprobeProgram extends BPFProgram {
        final GlobalVariable<Integer> kretprobeCount = new GlobalVariable<>(0);

        @BPFFunction(section = "kretprobe/do_sys_openat2", autoAttach = false)
        int onReturn(Ptr<PtDefinitions.pt_regs> ctx) {
            kretprobeCount.set(kretprobeCount.get() + 1);
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testKprobeDynamicAttach() throws Exception {
        try (var program = BPFProgram.load(KprobeProgram.class)) {
            program.attachKProbe(
                    program.getProgramByName("onEntry"), "do_sys_openat2");
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (program.kprobeCount.get() == 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.kprobeCount.get() > 0,
                    "dynamic kprobe on do_sys_openat2 should have fired at least once");
        }
    }

    @Test
    @Timeout(15)
    public void testKretprobeDynamicAttach() throws Exception {
        try (var program = BPFProgram.load(KretprobeProgram.class)) {
            program.attachKProbe(
                    program.getProgramByName("onReturn"), "do_sys_openat2", true);
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (program.kretprobeCount.get() == 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.kretprobeCount.get() > 0,
                    "dynamic kretprobe on do_sys_openat2 should have fired at least once");
        }
    }
}
