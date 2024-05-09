package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.CustomType;
import me.bechberger.ebpf.annotations.bpf.Type;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.BPFType.BPFStructType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static me.bechberger.ebpf.bpf.TypeProcessingTest.SimpleRecordTestProgram.ARRAY_SIZE;
import static me.bechberger.ebpf.bpf.TypeProcessingTest.SimpleRecordTestProgram.STRING_SIZE;
import static me.bechberger.ebpf.type.BPFType.BPFIntType.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

public class TypeProcessingTest {

    @BPF(includeTypes = {IncludedType.class})
    public static abstract class SimpleRecordTestProgram extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Type
        record SimpleRecord(@Unsigned int value) {
        }

        @Type(name = "Name")
        record SimpleNamedRecord(@Unsigned int value) {
        }

        @Type
        record RecordWithString(@Size(10) String name) {
        }

        static final int SIZE = 11;

        @Type
        record RecordWithSizeFromVariable(@Size(SIZE) String name) {
        }

        @Type
        record RecordWithMultipleMembers(byte value, @Size(10) String name, long longValue) {
        }

        @Type
        record RecordWithOtherType(@Unsigned int value, SimpleRecord other) {
        }

        @Type
        record RecordWithStringWithRecordOutOfProgram(RecordWithStringOutOfProgram name) {
        }

        public static BPFStructType<IntPair> INT_PAIR = BPFStructType.autoLayout("IntPair",
                List.of(new BPFType.UBPFStructMember<>("x", INT32, IntPair::x),
                        new BPFType.UBPFStructMember<>("y", INT32, IntPair::y)),
                new BPFType.AnnotatedClass(IntPair.class, List.of()),
                fields -> new IntPair((int) fields.get(0), (int) fields.get(1)));

        @CustomType(
                isStruct = true,
                specFieldName = "$outerClass.INT_PAIR", cCode = """
                struct $name {
                  int x;
                  int y;
                };
                """)
        record IntPair(int x, int y) {}

        @Type
        record RecordWithCustomType(IntPair pair) {}

        static final int ARRAY_SIZE = 11;
        static final int STRING_SIZE = 12;

        @Type
        record RecordWithIntArray(@Size(ARRAY_SIZE) int[] values) {
        }

        // alignment of 4
        @Type
        record SimpleRecord2(@Unsigned int a, byte b) {
        }

        // alignment of 4, padding between elements
        @Type
        record RecordWithOtherTypeArray(@Size(ARRAY_SIZE) SimpleRecord2[] values) {
        }

        @Type
        record RecordWithStringArray(@Size(ARRAY_SIZE) @Size(STRING_SIZE) String[] values) {
        }
    }

    @Type
    record RecordWithStringOutOfProgram(@Size(10) String name) {
    }

    @Type
    record IncludedType(int value) {
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
    public void testGeneratedCCode() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithOtherType.class);
        assertEquals("""
                struct RecordWithOtherType {
                  u32 value;
                  struct SimpleRecord other;
                };
                """.trim(),
                type.toCDeclarationStatement().get().toPrettyString());
    }

    @Test
    public void testRecordWithOutOfProgramRecord() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithStringWithRecordOutOfProgram.class);
        assertEquals(10, type.size());
        assertInstanceOf(BPFType.BPFStructType.class, type.getMember("name").type());
    }

    @Test
    public void testCustomType() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithCustomType.class);
        assertEquals(8, type.size());
        assertEquals("pair", type.members().getFirst().name());
        assertEquals("""
                struct IntPair {
                  s32 x;
                  s32 y;
                };
                """.trim(), type.members().getFirst().type().toCDeclarationStatement().get().toPrettyString());
    }

    @Test
    public void testIncludedType() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                IncludedType.class);
        assertEquals(4, type.size());
        assertEquals("value", type.members().getFirst().name());
        assertEquals(INT32, type.members().getFirst().type());
    }

    @Test
    public void testRecordWithIntArray() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithIntArray.class);
        assertEquals(ARRAY_SIZE * 4, type.size());
        assertEquals(ARRAY_SIZE * 4, type.getMember("values").type().size());
        assertEquals(4, type.getMember("values").type().alignment());
        assertEquals(4, type.alignment());
        assertEquals(INT32, ((BPFArrayType<?>)type.getMember("values").type()).memberType());
        assertEquals("""
                struct RecordWithIntArray {
                  s32 values[$s];
                };
                """.replace("$s", "" + ARRAY_SIZE).trim(),
                type.toCDeclarationStatement().get().toPrettyString());
    }

    @Test
    public void testRecordWithOtherTypeArray() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithOtherTypeArray.class);
        assertEquals(ARRAY_SIZE * 8, type.size());
        assertEquals(ARRAY_SIZE * 8, type.getMember("values").type().size());
        assertEquals(4, type.getMember("values").type().alignment());
        assertEquals(4, type.alignment());
        assertEquals("""
                struct RecordWithOtherTypeArray {
                  struct SimpleRecord2 values[$s];
                };
                """.replace("$s", "" + ARRAY_SIZE).trim(),
                type.toCDeclarationStatement().get().toPrettyString());
    }

    @Test
    public void testRecordWithStringArray() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithStringArray.class);
        assertEquals(ARRAY_SIZE * STRING_SIZE, type.size());
        assertEquals(ARRAY_SIZE * STRING_SIZE, type.getMember("values").type().size());
        assertEquals("""
                struct RecordWithStringArray {
                  char values[$a][$s];
                };
                """.replace("$s", "" + STRING_SIZE).replace("$a", "" + ARRAY_SIZE).trim(),
                type.toCDeclarationStatement().get().toPrettyString());
    }
}