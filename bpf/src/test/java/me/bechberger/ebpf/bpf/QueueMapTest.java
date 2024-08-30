package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFQueue;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class QueueMapTest {

    @BPF(license = "GPL")
    public static abstract class KernelLandTestProgram extends BPFProgram implements SystemCallHooks {

        @BPFMapDefinition(maxEntries = 2)
        BPFQueue<Integer> queue;
        final GlobalVariable<Boolean> alreadyPut = new GlobalVariable<>(false);
        final GlobalVariable<Boolean> worked = new GlobalVariable<>(false);

        @Override
        public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
            if (!alreadyPut.get()) {
                var value = 1;
                queue.push(value);
                value = 2;
                queue.push(value);
                worked.set(false);
                // expect that peek is 1 and pop is 1, then peek is 2 and pop is 2
                queue.bpf_peek(value);
                if (value != 1) {
                    return;
                }
                queue.bpf_pop(value);
                if (value != 1) {
                    return;
                }
                queue.bpf_peek(value);
                if (value != 2) {
                    return;
                }
                queue.bpf_pop(value);
                if (value != 2) {
                    return;
                }
                if (queue.bpf_peek(value)) {
                    return;
                }
                if (queue.bpf_pop(value)) {
                    return;
                }
                worked.set(true);
                alreadyPut.set(true);
            }
        }
    }

    @Test
    public void testKernelLand() throws InterruptedException {
        try (var program = BPFProgram.load(KernelLandTestProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            while (!program.alreadyPut.get()) {
                Thread.sleep(100);
            }
            assertTrue(program.worked.get());
        }
    }

    @BPF
    public static abstract class UserLandTestProgram extends BPFProgram {
        @BPFMapDefinition(maxEntries = 2)
        BPFQueue<Integer> queue;
    }

    @Test
    public void testUserLand() {
        try (var program = BPFProgram.load(UserLandTestProgram.class)) {
            var queue = program.queue;
            queue.push(1);
            queue.push(2);
            var value = queue.peek();
            assertTrue(value != null && value == 1);
            value = queue.pop();
            assertTrue(value != null && value == 1);
            value = queue.peek();
            assertTrue(value != null && value == 2);
            value = queue.pop();
            assertTrue(value != null && value == 2);
            value = queue.peek();
            assertNull(value);
            value = queue.pop();
            assertNull(value);
        }
    }
}
