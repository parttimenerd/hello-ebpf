package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CO-RE chain whose root is a method-call expression rather than a bare
 * identifier. Verifies the Translator's stmt-expr binding kicks in to
 * keep the helper invocation's relocation-free.
 */
public class CoReMethodCallRootTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Integer> pid = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            // Chain: bpf_get_current_task_btf().val().pid — root is the
            // method call, not an identifier.
            pid.set(BPFHelpers.bpf_get_current_task_btf().val().pid);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testMethodCallRoot() {
        String code = BPFProgram.getCode(Program.class);
        // Root is non-trivial → expect statement-expression binding.
        assertTrue(code.contains("__core_root = bpf_get_current_task_btf()")
                        || code.contains("__core_root = (bpf_get_current_task_btf())"),
                "expected method-call root bound via __core_root; got:\n" + code);
        assertTrue(code.contains("BPF_CORE_READ(__core_root, pid)"),
                "expected BPF_CORE_READ on bound root; got:\n" + code);

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertTrue(program.pid.get() > 0, "pid > 0; got " + program.pid.get());
        }
    }
}
