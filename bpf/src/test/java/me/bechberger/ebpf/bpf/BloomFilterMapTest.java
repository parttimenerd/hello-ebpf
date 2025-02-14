package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFBloomFilter;
import me.bechberger.ebpf.shared.TraceLog;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class BloomFilterMapTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        @BPFMapDefinition(maxEntries = 256)
        BPFBloomFilter<Integer> filter;

        static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_endian.h>

            SEC ("kprobe/do_sys_openat2")
                 int kprobe__do_sys_openat2 (struct pt_regs *ctx)
            {
              int placed_value = 12;
              int placed_value_in_filter = bpf_map_lookup_elem(&filter, &placed_value);
              if (placed_value_in_filter == 0) {
                bpf_printk("Placed OK");
              } else {
                bpf_printk("Placed NOT OK");
              }

              int value = 11;
              int maybe_in_filter = bpf_map_lookup_elem(&filter, &value);
              if (maybe_in_filter != 0) {
                bpf_printk("Before OK");
              } else {
                bpf_printk("Before NOT OK");
              }

              bpf_map_push_elem(&filter, &value, BPF_ANY);
              maybe_in_filter = bpf_map_lookup_elem(&filter, &value);
              if (maybe_in_filter == 0) {
                bpf_printk("After OK");
              } else {
                bpf_printk("After NOT OK");
              }
              return 0;
            }
        """;
    }

    @Test
    public void testBasicArrayMap() throws InterruptedException {
        try (var program = BPFProgram.load(BloomFilterMapTest.Program.class)) {
            var filter = program.filter;
            filter.put(12);
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            TestUtil.triggerOpenAt();

            while (true) {
                var msg = program.readTraceFields().msg();
                if (msg != null) {
                    assertEquals("Placed OK", msg);
                    break;
                }
            }

            while (true) {
                var msg = program.readTraceFields().msg();
                if (msg != null) {
                    assertEquals("Before OK", msg);
                    break;
                }
            }

            while (true) {
                var msg = program.readTraceFields().msg();
                if (msg != null) {
                    assertEquals("After OK", msg);
                    break;
                }
            }
        }
        TraceLog.getInstance().readAllAvailableLines(Duration.ofMillis(100));
    }
}
