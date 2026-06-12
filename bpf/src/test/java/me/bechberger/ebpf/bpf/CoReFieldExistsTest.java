package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link BPFJ#coreFieldExists(String)} runtime CO-RE field-presence
 * check. {@code task_struct.pid} exists on every supported kernel, so we
 * expect {@code true}.
 *
 * <p><b>Note:</b> {@code bpf_core_field_exists} is a compile-time CO-RE
 * macro that expands to a struct member reference — the field name must be
 * a valid identifier in the BPF object's type description (i.e. it has to
 * exist *somewhere* in BTF). The verifier later dead-code-eliminates the
 * false branch on kernels that lack the field. So you can't use it to
 * probe completely fabricated names; only fields that exist in some kernel
 * version are valid arguments.
 */
public class CoReFieldExistsTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Integer> pidExists = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            if (BPFJ.<task_struct>coreFieldExists("pid")) {
                pidExists.set(1);
            }
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testCoreFieldExists() {
        String code = BPFProgram.getCode(Program.class);
        assertTrue(code.contains("bpf_core_field_exists(((struct task_struct*)0)->pid)")
                        || code.contains("bpf_core_field_exists(((task_struct*)0)->pid)"),
                "expected bpf_core_field_exists on task_struct.pid; got:\n" + code);

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertEquals(1, program.pidExists.get().intValue(),
                    "task_struct.pid is universal — must report present");
        }
    }
}
