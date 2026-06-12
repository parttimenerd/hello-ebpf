package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CO-RE access from inside a lifted lambda body. Verifies
 * {@code BPF_CORE_READ} emission survives the lambda-to-static-function
 * lowering and that relocations resolve at libbpf load time.
 */
public class CoReInLambdaTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Integer> capturedPid = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            BPFJ.bpfLoop(1, (i, c) -> {
                Ptr<task_struct> task = BPFHelpers.bpf_get_current_task_btf();
                capturedPid.set(task.val().pid);
                return 0;
            }, null);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testCoreInLambda() {
        String code = BPFProgram.getCode(Program.class);
        assertTrue(code.contains("BPF_CORE_READ(task, pid)"),
                "expected BPF_CORE_READ(task, pid) inside lifted lambda; got:\n" + code);

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertTrue(program.capturedPid.get() > 0,
                    "capturedPid should be > 0; got " + program.capturedPid.get());
        }
    }
}
