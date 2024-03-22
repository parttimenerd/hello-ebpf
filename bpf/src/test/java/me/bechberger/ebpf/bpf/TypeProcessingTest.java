package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Type;
import me.bechberger.ebpf.shared.BPFType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static me.bechberger.ebpf.shared.BPFType.BPFIntType.CHAR;
import static me.bechberger.ebpf.shared.BPFType.BPFIntType.UINT32;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class TypeProcessingTest {

    @BPF
    public static abstract class SimpleRecordTestProgram extends BPFProgram {
        static final String EBPF_PROGRAM = "";

        @Type
        public record SimpleRecord(@Unsigned int value) {
        }

        @Type(name = "Name")
        public record SimpleNamedRecord(@Unsigned int value) {
        }

        @Type
        public record RecordWithString(@Size(10) String name) {
        }

        static final int SIZE = 11;

        @Type
        public record RecordWithSizeFromVariable(@Size(SIZE) String name) {
        }

        @Type
        public record RecordWithMultipleMembers(byte value, @Size(10) String name, long longValue) {
        }

        @Type
        public record RecordWithOtherType(@Unsigned int value, SimpleRecord other) {
        }

        @Type
        public record RecordWithDirectMemberType(@Unsigned int value, @Type.Member(bpfType = "me.bechberger.ebpf" +
                ".shared.BPFType.BPFIntType.CHAR") byte other) {
        }
    }

    @Test
    public void testSimpleRecord() {
        var type =
                BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                        SimpleRecordTestProgram.SimpleRecord.class);
        assertEquals("SimpleRecord", type.bpfName());
        assertEquals(4, type.size());
        assertEquals(4, type.alignment());
        assertEquals(UINT32, type.getMember("value").type());
        // check that type.constructor works
        assertEquals(new SimpleRecordTestProgram.SimpleRecord(42), type.constructor().apply(List.of(42)));
    }

    @Test
    public void testSimpleNamedRecord() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.SimpleNamedRecord.class);
        assertEquals("Name", type.bpfName());
    }

    @Test
    public void testRecordWithString() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithString.class);
        assertEquals(10, type.size());
        assertInstanceOf(BPFType.StringType.class, type.getMember("name").type());
        // check that type.constructor works
        assertEquals(new SimpleRecordTestProgram.RecordWithString("Hello"), type.constructor().apply(List.of("Hello")));
    }

    @Test
    public void testRecordWithSizeFromVariable() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithSizeFromVariable.class);
        assertEquals(11, type.size());
        assertInstanceOf(BPFType.StringType.class, type.getMember("name").type());
        // check that type.constructor works
        assertEquals(new SimpleRecordTestProgram.RecordWithSizeFromVariable("Hello"), type.constructor().apply(List.of("Hello")));
    }

    @Test
    public void testRecordWithMultipleMembers() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithMultipleMembers.class);
        assertEquals(24, type.size());
        assertEquals(3, type.members().size());
        // check that constructor works
        assertEquals(new SimpleRecordTestProgram.RecordWithMultipleMembers((byte) 42, "Hello", 1234567890L),
                type.constructor().apply(List.of((byte) 42, "Hello", 1234567890L)));
    }

    @Test
    public void testRecordWithOtherType() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithOtherType.class);
        assertEquals(8, type.size());
        assertEquals(2, type.members().size());
        // check that constructor works
        assertEquals(new SimpleRecordTestProgram.RecordWithOtherType(42, new SimpleRecordTestProgram.SimpleRecord(43)),
                type.constructor().apply(List.of(42, new SimpleRecordTestProgram.SimpleRecord(43))));
    }

    @Test
    public void testRecordWithDirectMemberType() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithDirectMemberType.class);
        assertEquals(CHAR, type.getMember("other").type());
        // check that constructor works
        assertEquals(new SimpleRecordTestProgram.RecordWithDirectMemberType(42, (byte)43),
                type.constructor().apply(List.of(42, (byte)43)));
    }
}
