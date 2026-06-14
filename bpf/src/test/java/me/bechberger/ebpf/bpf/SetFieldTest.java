package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link BPFJ#setField} correctly mutates a field of an immutable
 * {@code @Type} record on the BPF stack and that the modified value reaches user-space.
 *
 * <p>{@code setField(record, "a", value)} lowers to {@code (record).a = value} in C,
 * bypassing the Java record's immutability. This test creates a {@code Pair(0, 0)},
 * uses {@code setField} to set both fields, then stores the result in a map.
 */
public class SetFieldTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        record Pair(int a, int b) {}

        @BPFMapDefinition(maxEntries = 1)
        BPFArray<Pair> result;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            Pair p = new Pair(0, 0);
            BPFJ.setField(p, "a", 42);
            BPFJ.setField(p, "b", 99);
            result.put(0, p);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testSetFieldMutatesRecord() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");
            var pair = program.result.get(0);
            assertEquals(42, pair.a(), "setField(p, \"a\", 42) should set a to 42");
            assertEquals(99, pair.b(), "setField(p, \"b\", 99) should set b to 99");
        }
    }
}
