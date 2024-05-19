package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.CustomType;
import me.bechberger.ebpf.annotations.bpf.Type;
import me.bechberger.ebpf.type.*;
import me.bechberger.ebpf.type.BPFType.BPFStructType;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.util.List;
import java.util.stream.IntStream;

import static me.bechberger.ebpf.bpf.TypeProcessingTest.SimpleRecordTestProgram.*;
import static me.bechberger.ebpf.type.BPFType.BPFIntType.*;
import static org.junit.jupiter.api.Assertions.*;

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
        static final int SMALL_ARRAY_SIZE = 2;

        @Type
        record RecordWithIntArray(@Size(ARRAY_SIZE) int[] values) {
        }

        @Type
        record RecordWithIntArrayArray(  int @Size(SMALL_ARRAY_SIZE) [] @Size(SMALL_ARRAY_SIZE) [] values) {
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

        @Type
        static class SimpleUnion extends Union {
            @Unsigned int a;
            @Size(16) byte[] b;
            @Size(2) @Size(2) int[][] c;
        }

        @Type
        static class ClassRecord extends Struct {
            int a;
            @Size(6) String b;
        }

        @Type
        static class ClassRecordWithoutStruct {
            int a;
        }

        @Type
        static class ClassWithPointer {
            Ptr<SimpleRecord> recordPointer;
            Ptr<@Unsigned Integer> intPointer;
            Ptr<@Size(10) int[]> intArrayPointer;
            Ptr<@Size(10) String> stringPointer;
            Ptr<@Size(2) @Size(2) int[][]> intArrayArrayPointer;
            Ptr<Ptr<SimpleRecord>> recordPointerPointer;
            Ptr<@Size(2) Ptr<Integer>[]> intPointerArrayPointer;
        }

        @Type
        static class UnionWithPointer extends Union {
            Ptr<SimpleRecord> recordPointer;
            Ptr<@Unsigned Integer> intPointer;
            Ptr<@Size(10) int[]> intArrayPointer;
            Ptr<@Size(10) String> stringPointer;
            Ptr<@Size(2) @Size(2) int[][]> intArrayArrayPointer;
            Ptr<Ptr<SimpleRecord>> recordPointerPointer;
            Ptr<@Size(2) Ptr<Integer>[]> intPointerArrayPointer;
        }

        @Type
        record InterfaceBasedTypedef(int[] val) implements Typedef<@Size(10) int[]> {}

        @Type
        static class ClassBasedTypedef extends TypedefBase<@Size(10) int[]> {
            public ClassBasedTypedef(int[] val) {
                super(val);
            }
        }

        @Type
        record InterfaceBasedTypedefWithPtrOfArrays(Ptr<int[]> val) implements Typedef<Ptr<@Size(10) int[]>> {}

        @Type
        record InterfaceBasedTypedefOfTypedef(InterfaceBasedTypedef val) implements Typedef<InterfaceBasedTypedef> {}

        @Type
        record IntType(@Unsigned Integer val) implements Typedef<@Unsigned Integer> {}
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
                BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
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
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithString.class);
        assertEquals(10, type.size());
        assertInstanceOf(BPFType.StringType.class, type.getMember("name").type());
        // check that type.constructor works
        assertEquals(new SimpleRecordTestProgram.RecordWithString("Hello"), type.constructor().apply(List.of("Hello")));
    }

    @Test
    public void testRecordWithSizeFromVariable() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithSizeFromVariable.class);
        assertEquals(11, type.size());
        assertInstanceOf(BPFType.StringType.class, type.getMember("name").type());
        // check that type.constructor works
        assertEquals(new SimpleRecordTestProgram.RecordWithSizeFromVariable("Hello"), type.constructor().apply(List.of("Hello")));
    }

    @Test
    public void testRecordWithMultipleMembers() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithMultipleMembers.class);
        assertEquals(24, type.size());
        assertEquals(3, type.members().size());
        // check that constructor works
        assertEquals(new SimpleRecordTestProgram.RecordWithMultipleMembers((byte) 42, "Hello", 1234567890L),
                type.constructor().apply(List.of((byte) 42, "Hello", 1234567890L)));
    }

    @Test
    public void testRecordWithOtherType() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
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
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithStringWithRecordOutOfProgram.class);
        assertEquals(10, type.size());
        assertInstanceOf(BPFType.BPFStructType.class, type.getMember("name").type());
    }

    @Test
    public void testCustomType() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
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
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                IncludedType.class);
        assertEquals(4, type.size());
        assertEquals("value", type.members().getFirst().name());
        assertEquals(INT32, type.members().getFirst().type());
    }

    @Test
    public void testRecordWithIntArray() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
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

        var record = new SimpleRecordTestProgram.RecordWithIntArray(new int[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11});
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(1, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(2, memory.get(ValueLayout.JAVA_INT, 4));
            assertEquals(3, memory.get(ValueLayout.JAVA_INT, 8));
            assertArrayEquals(record.values, type.parseMemory(memory).values);
        }
    }

    @Test
    public void testRecordWithIntArrayArray() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithIntArrayArray.class);
        assertEquals(SMALL_ARRAY_SIZE * SMALL_ARRAY_SIZE * 4, type.size());
        assertEquals(SMALL_ARRAY_SIZE * SMALL_ARRAY_SIZE * 4, type.getMember("values").type().size());
        assertEquals(4, type.getMember("values").type().alignment());
        assertEquals(4, type.alignment());
        assertEquals(INT32, ((BPFArrayType<?>)((BPFArrayType<?>)type.getMember("values").type()).memberType()).memberType());
        assertEquals("""
                struct RecordWithIntArrayArray {
                  s32 values[$s][$s];
                };
                """.replace("$s", "" + SMALL_ARRAY_SIZE).trim(),
                type.toCDeclarationStatement().orElseThrow().toPrettyString());

        var record = new SimpleRecordTestProgram.RecordWithIntArrayArray(new int[][] {new int[]{1, 2}, new int[]{3, 4}});
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(1, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(2, memory.get(ValueLayout.JAVA_INT, 4));
            assertEquals(3, memory.get(ValueLayout.JAVA_INT, 8));
            assertArrayEquals(record.values, type.parseMemory(memory).values);
        }
    }

    @Test
    public void testRecordWithOtherTypeArray() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
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
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithStringArray.class);
        assertEquals(ARRAY_SIZE * STRING_SIZE, type.size());
        assertEquals(ARRAY_SIZE * STRING_SIZE, type.getMember("values").type().size());
        assertEquals("""
                struct RecordWithStringArray {
                  char values[$a][$s];
                };
                """.replace("$s", "" + STRING_SIZE).replace("$a", "" + ARRAY_SIZE).trim(),
                type.toCDeclarationStatement().orElseThrow().toPrettyString());
    }

    @Test
    public void testSampleUnion() {
        var type = BPFProgram.getUnionTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.SimpleUnion.class);
        assertEquals(16, type.size());
        assertEquals(4, type.alignment());
        assertEquals("""
                union SimpleUnion {
                  u32 a;
                  s8 b[16];
                  s32 c[2][2];
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var union = new SimpleRecordTestProgram.SimpleUnion();
        union.a = 42;
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, union);
            assertEquals(42, memory.get(ValueLayout.JAVA_BYTE, 0));
            assertEquals(0, memory.get(ValueLayout.JAVA_BYTE, 4));
            assertEquals(union.a, type.parseMemory(memory).a);
        }
        union.a = 0;
        union.c = new int[][]{ new int[]{1, 2}, new int[]{3, 4} };
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, union);
            assertEquals(1, memory.get(ValueLayout.JAVA_INT, 0));
            assertArrayEquals(union.c, type.parseMemory(memory).c);
        }
    }

    @Test
    public void testClassRecord() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.ClassRecord.class);
        assertEquals("""
                struct ClassRecord {
                  s32 a;
                  char b[6];
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.ClassRecord();
        record.a = 42;
        record.b = "Hello";
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(42, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(record, type.parseMemory(memory));
        }
    }

    @Test
    public void testClassRecordWithoutStruct() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.ClassRecordWithoutStruct.class);
        assertEquals("""
                struct ClassRecordWithoutStruct {
                  s32 a;
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.ClassRecordWithoutStruct();
        record.a = 42;
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(42, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(record.a, type.parseMemory(memory).a);
        }
    }

    @Test
    public void testClassWithPointer() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.ClassWithPointer.class);
        assertEquals("""
                struct ClassWithPointer {
                  struct SimpleRecord *recordPointer;
                  u32 *intPointer;
                  s32 (*intArrayPointer)[10];
                  char (*stringPointer)[10];
                  s32 (*intArrayArrayPointer)[2][2];
                  struct SimpleRecord **recordPointerPointer;
                  s32* (*intPointerArrayPointer)[2];
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
    }

    @Test
    public void testUnionWithPointer() {
        var type = BPFProgram.getUnionTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.UnionWithPointer.class);
        assertEquals("""
                union UnionWithPointer {
                  struct SimpleRecord *recordPointer;
                  u32 *intPointer;
                  s32 (*intArrayPointer)[10];
                  char (*stringPointer)[10];
                  s32 (*intArrayArrayPointer)[2][2];
                  struct SimpleRecord **recordPointerPointer;
                  s32* (*intPointerArrayPointer)[2];
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
    }

    @Test
    public void testInterfaceBasedTypedef() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.InterfaceBasedTypedef.class);
        assertEquals("""
                typedef s32 InterfaceBasedTypedef[10];
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
    }

    @Test
    public void testClassBasedTypedef() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.ClassBasedTypedef.class);
        assertEquals("""
                typedef s32 ClassBasedTypedef[10];
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.ClassBasedTypedef(new int[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10});
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertArrayEquals(record.val(), type.parseMemory(memory).val());
        }
    }

    @Test
    public void testInterfaceBasedTypedefWithPtrOfArrays() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.InterfaceBasedTypedefWithPtrOfArrays.class);
        assertEquals("""
                typedef s32 (*InterfaceBasedTypedefWithPtrOfArrays)[10];
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
    }

    @Test
    public void testInterfaceBasedTypedefOfTypedef() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.InterfaceBasedTypedefOfTypedef.class);
        assertEquals("""
                typedef InterfaceBasedTypedef InterfaceBasedTypedefOfTypedef;
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
    }

    @Test
    public void testIntType() {
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.IntType.class);
        assertEquals("""
                typedef u32 IntType;
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.IntType(42);
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(42, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(record.val(), type.parseMemory(memory).val());
        }
    }
}