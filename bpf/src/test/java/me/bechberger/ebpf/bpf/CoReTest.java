package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase E — CO-RE integration test.
 *
 * <p>Loads a kprobe that reads {@code task_struct.pid} via
 * {@code bpf_get_current_task_btf()}, stores the PID in a
 * {@link GlobalVariable}, then asserts the captured PID is non-zero
 * after triggering an {@code openat2} syscall. The interesting part
 * is the field access on {@code task_struct} — Phase E lifts that to
 * {@code BPF_CORE_READ(task, pid)} in the generated C, which produces
 * a CO-RE relocation entry in the .o file.
 */
public class CoReTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Integer> capturedPid = new GlobalVariable<>(0);

        @BPFFunction(
                section = "kprobe/do_sys_openat2",
                autoAttach = true
        )
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            Ptr<task_struct> task = BPFHelpers.bpf_get_current_task_btf();
            capturedPid.set(task.val().pid);
            return 0;
        }
    }

    @Test
    @Timeout(5)
    public void testCoreReadCapturesPid() {
        // Verify the generated C uses BPF_CORE_READ for the kernel-BTF field access.
        String code = BPFProgram.getCode(Program.class);
        assertTrue(code.contains("BPF_CORE_READ(task, pid)"),
                "generated C must contain BPF_CORE_READ(task, pid); got:\n" + code);

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            int pid = program.capturedPid.get();
            assertTrue(pid > 0, "capturedPid should be > 0 after openat2 fires; got " + pid);
        }
    }
}
