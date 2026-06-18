package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
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
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Mixed-chain CO-RE: a user {@code @Type} record holds a
 * {@code Ptr<task_struct>}. Reading {@code rec.taskPtr.pid} should fold
 * only the kernel suffix into {@code BPF_CORE_READ(rec.taskPtr, pid)},
 * leaving the user-side {@code rec.taskPtr} as a plain field access.
 */
public class CoReMixedChainTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        static class Wrapper {
            Ptr<task_struct> taskPtr;
            int marker;
        }

        final GlobalVariable<Integer> capturedPid = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            Wrapper w = new Wrapper();
            w.taskPtr = BPFHelpers.bpf_get_current_task_btf();
            w.marker = 42;
            // w.taskPtr is the user-side prefix (plain access),
            // .val().pid is the kernel suffix (BPF_CORE_READ).
            capturedPid.set(w.taskPtr.val().pid);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testMixedChain() {
        String code = BPFProgram.getCode(Program.class);
        // The kernel suffix must be lifted; because the root `w.taskPtr`
        // is a non-trivial expression, the Translator binds it to a local
        // first to keep clang's __builtin_preserve_access_index from
        // generating a bogus CO-RE relocation against the user struct.
        assertTrue(code.contains("BPF_CORE_READ(__core_root, pid)"),
                "expected BPF_CORE_READ on a bound root for kernel suffix; got:\n" + code);
        assertTrue(code.contains("__core_root = w.taskPtr"),
                "expected w.taskPtr bound to __core_root; got:\n" + code);

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            int pid = program.capturedPid.get();
            assertTrue(pid > 0, "capturedPid should be > 0; got " + pid);
        }
    }
}
