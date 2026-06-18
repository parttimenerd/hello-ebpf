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
 * Multi-level CO-RE chain: {@code task.real_parent.pid} crosses two
 * {@code Ptr<task_struct>} hops. The Translator must fold the entire
 * chain into a single {@code BPF_CORE_READ(task, real_parent, pid)} call
 * (variadic libbpf macro that walks pointer fields automatically).
 */
public class CoReMultiLevelTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Integer> parentPid = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            Ptr<task_struct> task = BPFHelpers.bpf_get_current_task_btf();
            // task.real_parent is Ptr<task_struct>. .val().pid traverses
            // the pointer and reads pid on the parent. The whole thing
            // should fold into BPF_CORE_READ(task, real_parent, pid).
            parentPid.set(task.val().real_parent.val().pid);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testMultiLevelCoreRead() {
        String code = BPFProgram.getCode(Program.class);
        assertTrue(code.contains("BPF_CORE_READ(task, real_parent, pid)"),
                "expected variadic BPF_CORE_READ to fold the whole chain; got:\n" + code);

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            int ppid = program.parentPid.get();
            assertTrue(ppid > 0, "parent pid should be > 0; got " + ppid);
        }
    }
}
