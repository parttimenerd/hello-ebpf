package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.*;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Enum.EnumSupport;
import me.bechberger.ebpf.type.*;
import me.bechberger.ebpf.type.BPFType.BPFStructType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.util.List;

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

        @Type
        enum Kind implements Enum<Kind> {
            A, @EnumMember(value = 23, name = "KIND_42") B, C, D
        }

        @Type
        enum KindLong implements Enum<KindLong>, TypedEnum<KindLong, Long> {
            @EnumMember(value = 100000000000L)
            A
        }

        @Type
        enum KindShort implements Enum<KindShort>, TypedEnum<KindShort, Short> {
            @EnumMember(value = 23)
            A
        }

        @Type
        record RecordWithEnumArray(@Size(2) Kind[] values) {
        }

        @Type
        record RecordWithCustomOffset(@Offset(4) int a) {
        }

        @Type
        static class ClassWithCustomOffset {
            @Offset(12) @Size(3) int[] b;
        }

        @Type(typedefed = true)
        record RecordWithTypedefedType(@Size(10) int[] values) {
        }

        /**
         * Record with an inline union member
         * <p>
         * {@code :
         * struct StructWithInlineUnion {
         *   int a;
         *   union {
         *     int x;
         *     int y;
         *   };
         * }
         * }
         */
        @Type
        static class StructWithInlineUnion extends Struct {
            int a;
            @InlineUnion(1)
            int x;
            @InlineUnion(1)
            long y;
        }

        @Type
        static class StructWithMultipleInlineUnions extends Struct {
            @InlineUnion(1) int unionA;
            @InlineUnion(1) long unionB;
            @InlineUnion(2) int unionC;
        }

        @Type
        record RecordStructWithInlineUnion(int a, @InlineUnion(2) int unionA, @InlineUnion(2) long unionB) {
        }

        @Type
        static class StructWithMultipleInlineUnionsAndOffsets extends Struct {
            @InlineUnion(1) int unionA;
            @InlineUnion(1) long unionB;
            @Offset(16)
            @InlineUnion(2) int unionC;
            @Offset(16)
            @InlineUnion(2) long unionD;
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

    @Test
    public void testKindEnum() {
        Assertions.assertAll(
                () -> assertEquals(0, Kind.A.value(), "A has value 0"),
                () -> assertEquals(23, Kind.B.value(), "B has value 23"),
                () -> assertEquals(24, Kind.C.value(), "C has value 24"),
                () -> assertEquals(25, Kind.D.value(), "D has value 25"),
                () -> assertEquals("A(0)", Kind.A.toStr()),
                () -> assertEquals(Kind.C, EnumSupport.fromValue(Kind.class, 24))
        );
        for (var kind : Kind.values()) {
            assertEquals(kind, EnumSupport.fromValue(Kind.class, kind.value()));
        }
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class, Kind.class);
        assertEquals("""
                enum Kind {
                  KIND_A = 0,
                  KIND_42 = 23,
                  KIND_C = 24,
                  KIND_D = 25
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = Kind.B;
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(23, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(record, type.parseMemory(memory));
        }
    }

    @Test
    public void testKindLongEnum() {
        Assertions.assertAll(
                () -> assertEquals(100000000000L, KindLong.A.value(), "A has value 100000000000"),
                () -> assertEquals("A(100000000000)", KindLong.A.toStr())
        );
        for (var kind : KindLong.values()) {
            assertEquals(kind, EnumSupport.fromValue(KindLong.class, kind.value()));
        }
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class, KindLong.class);
        assertEquals(8, type.size());
        assertEquals("""
                enum KindLong {
                  KIND_LONG_A = 100000000000L
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = KindLong.A;
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(100000000000L, memory.get(ValueLayout.JAVA_LONG, 0));
            assertEquals(record, type.parseMemory(memory));
        }
    }

    @Test
    public void testKindShortEnum() {
        Assertions.assertAll(
                () -> assertEquals(23, KindShort.A.value(), "A has value 23"),
                () -> assertEquals("A(23)", KindShort.A.toStr())
        );
        for (var kind : KindShort.values()) {
            assertEquals(kind, EnumSupport.fromValue(KindShort.class, kind.value()));
        }
        var type = BPFProgram.getTypeForClass(SimpleRecordTestProgram.class, KindShort.class);
        assertEquals(2, type.size());
        assertEquals("""
                enum KindShort {
                  KIND_SHORT_A = 23
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = KindShort.A;
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(23, memory.get(ValueLayout.JAVA_SHORT, 0));
            assertEquals(record, type.parseMemory(memory));
        }
    }

    @Test
    public void testRecordWithEnumArray() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithEnumArray.class);
        assertEquals(8, type.size());
        assertEquals(8, type.getMember("values").type().size());
        assertEquals(4, type.getMember("values").type().alignment());
        assertEquals(4, type.alignment());
        assertEquals("""
                struct RecordWithEnumArray {
                  enum Kind values[2];
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.RecordWithEnumArray(new Kind[]{Kind.A, Kind.B});
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(0, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(23, memory.get(ValueLayout.JAVA_INT, 4));
            assertArrayEquals(record.values, type.parseMemory(memory).values);
        }
    }

    @Test
    public void testRecordWithCustomOffset() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithCustomOffset.class);
        assertEquals(8, type.size());
        assertEquals(4, type.getMember("a").offset());
        assertEquals(4, type.getMember("a").type().size());
        assertEquals(4, type.getMember("a").type().alignment());
        assertEquals("""
                struct RecordWithCustomOffset {
                  char __padding0[4];
                  s32 a;
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
    }

    @Test
    public void testClassWithCustomOffsets() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.ClassWithCustomOffset.class);
        assertEquals(12 + 3 * 4, type.size());
        assertEquals(12, type.getMember("b").offset());
        assertEquals("""
                struct ClassWithCustomOffset {
                  char __padding0[12];
                  s32 b[3];
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
    }

    @Test
    public void testRecordWithTypedefedType() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordWithTypedefedType.class);
        assertEquals("""
                typedef struct {
                  s32 values[10];
                } RecordWithTypedefedType;
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        assertEquals("RecordWithTypedefedType", type.toCUse().toPrettyString());
    }

    @Test
    public void testStructWithInlineUnion() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.StructWithInlineUnion.class);
        assertEquals(16, type.size());
        assertEquals(8, type.alignment()); // because of the long in the union, checked with godbolt
        assertEquals(2, type.members().size());
        // the inline union is just syntactic sugar for a union
        assertInstanceOf(BPFUnionType.class, type.members().get(1).type());
        assertEquals("""
                struct StructWithInlineUnion {
                  s32 a;
                  union {
                    s32 x;
                    s64 y;
                  };
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.StructWithInlineUnion();
        record.a = 42;
        record.x = 43;
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(42, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(43, memory.get(ValueLayout.JAVA_INT, 8));
            var parsed = type.parseMemory(memory);
            assertEquals(record.a, parsed.a);
            assertEquals(record.x, parsed.x);
            assertEquals(record.x, parsed.y);
        }

        // TODO: also support in Generator: anon union in struct is converted into an inlined union
    }

    @Test
    public void testStructWithMultipleInlineUnions() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.StructWithMultipleInlineUnions.class);
        assertEquals(12, type.size());
        assertEquals(8, type.alignment());
        assertEquals(2, type.members().size());
        assertEquals("""
                struct StructWithMultipleInlineUnions {
                  union {
                    s32 unionA;
                    s64 unionB;
                  };
                  union {
                    s32 unionC;
                  };
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.StructWithMultipleInlineUnions();
        record.unionA = 42;
        record.unionB = 43;
        record.unionC = 44;
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(42, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(44, memory.get(ValueLayout.JAVA_INT, 8));
            var parsed = type.parseMemory(memory);
            assertEquals(record.unionA, parsed.unionA);
            assertEquals(record.unionA, parsed.unionB);
            assertEquals(record.unionC, parsed.unionC);
        }
    }

    @Test
    public void testRecordStructWithInlineUnion() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.RecordStructWithInlineUnion.class);
        assertEquals(16, type.size());
        assertEquals(8, type.alignment());
        assertEquals(2, type.members().size());
        assertEquals("""
                struct RecordStructWithInlineUnion {
                  s32 a;
                  union {
                    s32 unionA;
                    s64 unionB;
                  };
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.RecordStructWithInlineUnion(42, 43, 44);
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(42, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(43, memory.get(ValueLayout.JAVA_LONG, 8));
            var parsed = type.parseMemory(memory);
            assertEquals(record.a, parsed.a);
            assertEquals(record.unionA, parsed.unionA);
            assertEquals(record.unionA, parsed.unionB);
        }
    }

    @Test
    public void testStructWithMultipleInlineUnionsAndOffsets() {
        var type = BPFProgram.getStructTypeForClass(SimpleRecordTestProgram.class,
                SimpleRecordTestProgram.StructWithMultipleInlineUnionsAndOffsets.class);
        assertEquals(24, type.size());
        assertEquals(8, type.alignment());
        assertEquals(2, type.members().size());
        assertEquals("""
                struct StructWithMultipleInlineUnionsAndOffsets {
                  union {
                    s32 unionA;
                    s64 unionB;
                  };
                  char __padding0[8];
                  union {
                    s32 unionC;
                    s64 unionD;
                  };
                };
                """.trim(), type.toCDeclarationStatement().orElseThrow().toPrettyString());
        var record = new SimpleRecordTestProgram.StructWithMultipleInlineUnionsAndOffsets();
        record.unionA = 42;
        record.unionB = 43;
        record.unionC = 44;
        record.unionD = 45;
        try (var arena = Arena.ofConfined()) {
            var memory = type.allocate(arena, record);
            assertEquals(42, memory.get(ValueLayout.JAVA_INT, 0));
            assertEquals(44, memory.get(ValueLayout.JAVA_INT, 16));
            var parsed = type.parseMemory(memory);
            assertEquals(record.unionA, parsed.unionA);
            assertEquals(record.unionA, parsed.unionB);
            assertEquals(record.unionC, parsed.unionC);
            assertEquals(record.unionC, parsed.unionD);
        }
    }

    @BPFInterface(before = "int x = 0;", after = "int y = 0;")
    @Includes({"string.h", "unistd.h"})
    interface Lib {

    }

    @BPF(includes = "vmlinux.h")
    @Includes("string.h")
    static abstract class TestLibsProgram extends BPFProgram implements Lib {
        public static final String EBPF_PROGRAM = """
                #include "vmlinux.h";
                int z = 1;
                """;
    }

    @Test
    public void testIncludesAndInterface() {
        var code = BPFProgram.getCode(TestLibsProgram.class);
        assertEquals("""
                #include "vmlinux.h";
                #include <unistd.h>
                #include <string.h>
                
                int x = 0;
                
                int z = 1;
                
                int y = 0;
                """.strip(), code.strip());
    }
}