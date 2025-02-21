package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DataTypeTest {

    private static final int KEY = 11;

    @BPF(license = "GPL")
    public static abstract class RecordArrayProgram extends BPFProgram {
        @Type
        record InnerRecord(int a, byte b) {
        }

        @Type
        record OuterRecord(@Size(2) InnerRecord[] records) {
        }

        @BPFMapDefinition(maxEntries = 256)
        BPFArray<OuterRecord> array;

        @BPFMapDefinition(maxEntries = 256)
        BPFArray<@Size(2) InnerRecord[]> array2;

        @Type
        protected enum Result implements Enum<Result> {
            UNKNOWN,
            NOT_FOUND,
            CORRECT,
            INCORRECT
        }

        final GlobalVariable<Result> result = new GlobalVariable<>(Result.UNKNOWN);

        @BPFFunction(
                section = "kprobe/do_sys_openat2"
        )
        int testDataTypes1(Ptr<PtDefinitions.pt_regs> ctx) {
            int key = KEY;
            Ptr<OuterRecord> value = array.bpf_get(key);
            if (value == null) {
                result.set(Result.NOT_FOUND);
            } else {
                testInnerRecords(value.val().records);
            }
            return 0;
        }

        @BPFFunction(
                section = "kprobe/do_sys_openat2"
        )
        int testDataTypes2(Ptr<PtDefinitions.pt_regs> ctx) {
            int key = KEY;
            Ptr<@Size(2) InnerRecord[]> value = array2.bpf_get(key);
            if (value == null) {
                result.set(Result.NOT_FOUND);
            } else {
                testInnerRecords(value.val());
            }
            return 0;
        }

        @BPFFunction
        void testInnerRecords(@Size(2) InnerRecord[] records) {
            if (records[0].a == 1 && records[0].b == 11 && records[1].a == 2 && records[1].b == 12) {
                result.set(Result.CORRECT);
            } else {
                result.set(Result.INCORRECT);
            }
        }
    }

    @Test
    @Timeout(10)
    public void testArrayMapWithRecordArray() {
        try (var program = BPFProgram.load(DataTypeTest.RecordArrayProgram.class)) {
            var array = program.array;
            assertEquals(256, array.size());
            array.put(KEY, new RecordArrayProgram.OuterRecord(new RecordArrayProgram.InnerRecord[]{
                    new RecordArrayProgram.InnerRecord(1, (byte) 11),
                    new RecordArrayProgram.InnerRecord(2, (byte) 12)}));
            program.autoAttachProgram("testDataTypes1");
            TestUtil.triggerOpenAt();

            while (program.result.get() == RecordArrayProgram.Result.UNKNOWN) {
            }
            assertEquals(RecordArrayProgram.Result.CORRECT, program.result.get());
        }
    }

    @Test
    @Timeout(10)
    public void testArrayMapWithRecordArray2() {
        try (var program = BPFProgram.load(DataTypeTest.RecordArrayProgram.class)) {
            assertEquals(256, program.array2.size());
            program.array2.put(KEY, new RecordArrayProgram.InnerRecord[]{
                    new RecordArrayProgram.InnerRecord(1, (byte) 11),
                    new RecordArrayProgram.InnerRecord(2, (byte) 12)});
            program.autoAttachProgram("testDataTypes2");
            TestUtil.triggerOpenAt();

            while (program.result.get() == RecordArrayProgram.Result.UNKNOWN) {
            }
            assertEquals(RecordArrayProgram.Result.CORRECT, program.result.get());
            TraceLog.getInstance().readAllAvailableLines(Duration.ofMillis(100));
        }
    }
}
