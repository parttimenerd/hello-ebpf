package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Type;
import me.bechberger.ebpf.bpf.GlobalVariableTest.Program.InnerRecord;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.shared.TraceLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class GlobalVariableTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        @Type
        record InnerRecord(int a, byte b) {}

        final GlobalVariable<InnerRecord> recordVariable = new GlobalVariable<>(new InnerRecord(1, (byte) 2));
        final GlobalVariable<Integer> intVariable = new GlobalVariable<>(42);

        @BPFMapDefinition(maxEntries = 2)
        BPFArray<Integer> values;

        static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_endian.h>

            SEC ("kprobe/do_sys_openat2")
                 int kprobe__do_sys_openat2 (struct pt_regs *ctx)
            {
              // put recordVariable.a into the first element of the array and the intVariable into the second
              int idx = 0;
              bpf_map_update_elem(&values, &idx, &recordVariable.a, BPF_ANY);
              idx = 1;
                bpf_map_update_elem(&values, &idx, &intVariable, BPF_ANY);
              return 0;
            }
        """;
    }

    @Test
    @Timeout(10)
    public void testGlobals() throws InterruptedException {
        try (var program = BPFProgram.load(GlobalVariableTest.Program.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            program.recordVariable.set(new InnerRecord(3, (byte) 4));
            assertEquals(new InnerRecord(3, (byte) 4), program.recordVariable.get());
            TestUtil.triggerOpenAt();
            assertEquals(Set.of(3, 42), program.values.values());
            program.intVariable.set(43);
            TestUtil.triggerOpenAt();
            assertEquals(Set.of(3, 43), program.values.values());
        }
    }
}
