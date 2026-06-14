package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFStack;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@link BPFStack} push and pop operations work correctly when
 * called from a BPF program.
 *
 * <p>The kprobe pushes three integer values (1, 2, 3) onto the stack and then
 * pops them back; since stacks are LIFO the pop order should be 3, 2, 1. The
 * results are stored in a second stack so user-space can inspect them.
 */
public class BpfStackTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        /** Input: BPF program pushes 1, 2, 3 onto this stack. */
        @BPFMapDefinition(maxEntries = 8)
        BPFStack<Integer> input;

        /** Output: BPF program pops from input and pushes onto output. */
        @BPFMapDefinition(maxEntries = 8)
        BPFStack<Integer> output;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);
        final GlobalVariable<Boolean> ok = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Push 1, 2, 3 — LIFO so they come back as 3, 2, 1.
            int v1 = 1;
            int v2 = 2;
            int v3 = 3;
            input.push(v1);
            input.push(v2);
            input.push(v3);

            // Pop in LIFO order and push onto the output stack.
            int popped = 0;
            if (!input.bpf_pop(popped)) return 0;
            output.push(popped);  // should be 3
            if (!input.bpf_pop(popped)) return 0;
            output.push(popped);  // should be 2
            if (!input.bpf_pop(popped)) return 0;
            output.push(popped);  // should be 1

            // Verify input is now empty
            if (input.bpf_pop(popped)) return 0;  // should fail (empty)

            ok.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfStackPushPop() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            assertTrue(program.ok.get(), "BPF-side stack operations failed");

            // Output stack is LIFO: last pushed (1) comes out first.
            assertEquals(1, program.output.pop(), "first pop from output should be 1 (LIFO)");
            assertEquals(2, program.output.pop(), "second pop from output should be 2");
            assertEquals(3, program.output.pop(), "third pop from output should be 3");
            assertNull(program.output.pop(), "output stack should be empty after 3 pops");
        }
    }
}
