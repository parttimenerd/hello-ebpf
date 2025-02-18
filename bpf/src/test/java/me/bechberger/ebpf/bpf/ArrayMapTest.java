package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ArrayMapTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        @BPFMapDefinition(maxEntries = 256)
        BPFArray<Integer> array;

        private static final int KEY = 11;
        private static final int EXPECTED_VALUE = 11;

        @Type
        protected enum Result implements Enum<Result> {
            UNKNOWN,
            NOT_FOUND,
            CORRECT,
            WRONG
        }

        final GlobalVariable<Result> result = new GlobalVariable<>(Result.UNKNOWN);

        @BPFFunction(
                section = "kprobe/do_sys_openat2"
        )
        int kprobe__do_sys_openat2(Ptr<PtDefinitions.pt_regs> ctx) {
            int key = KEY;
            Ptr<Integer> value = array.bpf_get(key);

            if (value == null) {
                result.set(Result.NOT_FOUND);
            } else if (value.val() == EXPECTED_VALUE) {
                result.set(Result.CORRECT);
            } else {
                result.set(Result.WRONG);
                bpf_trace_printk("Value is not 11, but %d", value.val());
            }
            return 0;
        }
    }

    @Test
    public void testBasicArrayMap() {
        try (var program = BPFProgram.load(ArrayMapTest.Program.class)) {
            var array = program.array;
            assertEquals(256, array.size());
            array.put(Program.KEY, Program.EXPECTED_VALUE);
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            TestUtil.triggerOpenAt();
            while (program.result.get() == Program.Result.UNKNOWN) {
                // Wait
            }
            assertEquals(Program.Result.CORRECT, program.result.get());
        }
        TraceLog.getInstance().readAllAvailableLines(Duration.ofMillis(100));
    }
}
