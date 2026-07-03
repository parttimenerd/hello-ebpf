package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFArrayOfMaps;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ArrayOfMapsSmokeTest {

    @BPF(license = "GPL")
    static abstract class ArrayOfMapsProg extends BPFProgram {

        @BPFMapDefinition(maxEntries = 64)
        BPFHashMap<@Unsigned Long, @Unsigned Long> innerTemplate;

        @InnerMap("innerTemplate")
        @BPFMapDefinition(maxEntries = 8)
        BPFArrayOfMaps<BPFHashMap<@Unsigned Long, @Unsigned Long>> slots;

        @BPFFunction(
                headerTemplate = "int BPF_PROG($name, $params)",
                lastStatement = "return 0;",
                section = "raw_tracepoint/sys_enter",
                autoAttach = false
        )
        public void countSyscall(Ptr<PtDefinitions.pt_regs> regs, @Unsigned long nr) {
            int slot = BPFJ.currentCpuId() & 7;
            Ptr<BPFHashMap<Long, Long>> inner = slots.lookup(slot);
            if (inner == null) return;
            Ptr<Long> counter = inner.val().bpf_get(nr);
            if (counter != null) counter.set(counter.val() + 1);
            else { long one = 1L; inner.val().bpf_put(nr, one); }
        }
    }

    @Test
    void arrayOfMapsCollectsSyscalls() throws InterruptedException {
        try (ArrayOfMapsProg program = BPFProgram.load(ArrayOfMapsProg.class)) {
            // Register the innerTemplate at every slot.
            for (int i = 0; i < 8; i++) program.slots.register(i, program.innerTemplate);
            program.rawTracepointAttach("countSyscall", "sys_enter");
            Thread.sleep(3000);

            long total = 0;
            for (var e : program.innerTemplate) total += e.getValue();
            assertTrue(total > 0, "expected nonzero syscalls across ARRAY_OF_MAPS slots");

            program.slots.unregister(0);
            assertNull(program.slots.get(0), "unregister clears slot");
        }
    }
}
