package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.GlobalVariableTest.Program.InnerRecord;
// GlobalVariableTest$ProgramImpl is the annotation-processor-generated implementation class;
// it exposes InnerRecordWiths (a with-builder for the @Type record InnerRecord).
import me.bechberger.ebpf.bpf.GlobalVariableTest$ProgramImpl;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;


public class GlobalVariableTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        @Type
        record InnerRecord(int a, byte b) {}

        final GlobalVariable<InnerRecord> recordVariable = new GlobalVariable<>(new InnerRecord(1, (byte) 2));
        final GlobalVariable<Integer> intVariable = new GlobalVariable<>(42);

        @BPFMapDefinition(maxEntries = 2)
        BPFArray<Integer> values;

        @Kprobe("do_sys_openat2")
        int kprobe__do_sys_openat2(Ptr<PtDefinitions.pt_regs> ctx) {
            values.put(0, recordVariable.get().a());
            values.put(1, intVariable.get());
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testGlobals() throws InterruptedException {
        try (var program = BPFProgram.load(GlobalVariableTest.Program.class)) {
            program.autoAttachPrograms();
            program.recordVariable.set(new InnerRecord(3, (byte) 4));
            assertEquals(new InnerRecord(3, (byte) 4), program.recordVariable.get());
            TestUtil.triggerOpenAt();
            assertEquals(Set.of(3, 42), program.values.values());
            program.intVariable.set(43);
            TestUtil.triggerOpenAt();
            assertEquals(Set.of(3, 43), program.values.values());
        }
    }

    @Test
    @Timeout(10)
    public void testAtomicOpsJavaSide() {
        try (var program = BPFProgram.load(GlobalVariableTest.Program.class)) {
            program.autoAttachPrograms();
            var v = program.intVariable;

            // incrementAndGet
            v.set(10);
            assertEquals(11, v.incrementAndGet());
            assertEquals(11, v.get());

            // addAndGet
            assertEquals(16, v.addAndGet(5));
            assertEquals(16, v.get());

            // compareAndSet: success
            assertTrue(v.compareAndSet(16, 99));
            assertEquals(99, v.get());

            // compareAndSet: failure (wrong expected)
            assertFalse(v.compareAndSet(0, 200));
            assertEquals(99, v.get());
        }
    }

    @Test
    public void testWithBuilders() {
        var r = new InnerRecord(1, (byte) 2);
        assertEquals(new InnerRecord(99, (byte) 2),
                GlobalVariableTest$ProgramImpl.InnerRecordWiths.withA(r, 99));
        assertEquals(new InnerRecord(1, (byte) 7),
                GlobalVariableTest$ProgramImpl.InnerRecordWiths.withB(r, (byte) 7));
    }
}
