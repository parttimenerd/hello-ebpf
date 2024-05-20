package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.shared.TraceLog;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ArrayMapTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        @BPFMapDefinition(maxEntries = 256)
        BPFArray<Integer> array;

        static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_endian.h>

            SEC ("kprobe/do_sys_openat2")
                 int kprobe__do_sys_openat2 (struct pt_regs *ctx)
            {
              int key = 11;
              int* val = bpf_map_lookup_elem(&array, &key);
              if (val == NULL) {
                bpf_printk("Value not found");
              } else if (*val == 11) {
                bpf_printk("Value is 11");
              } else {
                bpf_printk("Value is not 11, but %d", *val);
              }
              return 0;
            }
        """;
    }

    @Test
    public void testBasicArrayMap() throws InterruptedException {
        try (var program = BPFProgram.load(ArrayMapTest.Program.class)) {
            var array = program.array;
            assertEquals(256, array.size());
            array.put(11, 11);
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            TestUtil.triggerOpenAt();
            while (true) {
                var msg = program.readTraceFields().msg();
                if (msg != null && msg.contains("Value is 11")) {
                    break;
                } else {
                    System.out.println("Waiting for message " + msg);
                }
            }
        }
        TraceLog.getInstance().readAllAvailableLines(Duration.ofMillis(100));
    }
}
