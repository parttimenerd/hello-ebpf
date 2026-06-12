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
 * Use the CO-RE-read value in arithmetic and conditionals to verify the
 * folded BPF_CORE_READ expression composes correctly.
 */
public class CoReInExpressionTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Integer> pidPlusOne = new GlobalVariable<>(0);
        final GlobalVariable<Integer> isPositive = new GlobalVariable<>(0);
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) { return 0; }
            done.set(true);
            Ptr<task_struct> task = BPFHelpers.bpf_get_current_task_btf();
            // CO-RE read inside an arithmetic expression.
            pidPlusOne.set(task.val().pid + 1);
            // CO-RE read inside a comparison.
            if (task.val().pid > 0) {
                isPositive.set(1);
            }
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testCoReInExpression() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertTrue(program.pidPlusOne.get() > 1, "pid+1 should be > 1");
            assertEquals(1, program.isPositive.get().intValue(), "pid > 0 should be true");
        }
    }
}
