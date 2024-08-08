package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.bpf.map.BPFArray;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DataTypeTest {

    @BPF(license = "GPL")
    public static abstract class RecordArrayProgram extends BPFProgram {
        @Type
        record InnerRecord(int a, byte b) {}

        record OuterRecord(@Size(2) InnerRecord[] records) {}

        @BPFMapDefinition(maxEntries = 256)
        BPFArray<OuterRecord> array;

        @BPFMapDefinition(maxEntries = 256)
        BPFArray<@Size(2) InnerRecord[]> array2;

        static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_endian.h>

            SEC ("kprobe/do_sys_openat2")
                 int kprobe__do_sys_openat2 (struct pt_regs *ctx)
            {
              int key = 11;
              struct OuterRecord* val = bpf_map_lookup_elem(&array, &key);
              if (val == NULL) {
                struct InnerRecord* val2 = bpf_map_lookup_elem(&array2, &key);
                if (val2 == NULL) {
                  bpf_printk("Value not found");
                } else if (val2[0].a == 1 && val2[0].b == 11 && val2[1].a == 2 && val2[1].b == 12) {
                  bpf_printk("Value is correct");
                } else {
                  bpf_printk("Value is incorrect");
                }
              } else if (val->records[0].a == 1 && val->records[0].b == 11 && val->records[1].a == 2 && val->records[1].b == 12) {
                bpf_printk("Value is correct");
              } else {
                bpf_printk("Value is incorrect");
              }
              return 0;
            }
        """;
    }

    @Test
    @Timeout(10)
    public void testArrayMapWithRecordArray() {
        try (var program = BPFProgram.load(DataTypeTest.RecordArrayProgram.class)) {
            var array = program.array;
            assertEquals(256, array.size());
            array.put(11, new RecordArrayProgram.OuterRecord(new RecordArrayProgram.InnerRecord[] {
                    new RecordArrayProgram.InnerRecord(1, (byte) 11),
                    new RecordArrayProgram.InnerRecord(2, (byte) 12) }));
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            TestUtil.triggerOpenAt();
//            assertEquals("Value is correct", program.readTraceFields().msg()); // TODO
        }
    }

    @Test
    @Timeout(10)
    public void testArrayMapWithRecordArray2() {
        try (var program = BPFProgram.load(DataTypeTest.RecordArrayProgram.class)) {
            assertEquals(256, program.array2.size());
            program.array2.put(0, new RecordArrayProgram.InnerRecord[] {
                    new RecordArrayProgram.InnerRecord(1, (byte) 11),
                    new RecordArrayProgram.InnerRecord(2, (byte) 12) });
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            TestUtil.triggerOpenAt();
           // assertEquals("Value is correct", program.readTraceFields().msg()); // TODO
        }
    }
}
