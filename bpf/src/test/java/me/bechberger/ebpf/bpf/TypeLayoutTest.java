package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.type.BPFType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.foreign.MemoryLayout;
import java.util.List;
import java.util.stream.Stream;

import static me.bechberger.ebpf.type.BPFType.BPFStructType;
import static me.bechberger.ebpf.type.BPFType.UBPFStructMember;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests the auto-layouting of types
 */
public class TypeLayoutTest {

    private static Stream<Arguments> provideTestAlignmentOfScalarsParameters() {
        return Stream.of(Arguments.of(1, BPFType.BPFIntType.INT8), Arguments.of(2, BPFType.BPFIntType.INT16),
                Arguments.of(4, BPFType.BPFIntType.INT32), Arguments.of(8, BPFType.BPFIntType.INT64), Arguments.of(1,
                        BPFType.BPFIntType.UINT8), Arguments.of(2, BPFType.BPFIntType.UINT16), Arguments.of(4,
                        BPFType.BPFIntType.UINT32), Arguments.of(8, BPFType.BPFIntType.UINT64), Arguments.of(8,
                        BPFType.BPFIntType.POINTER));
    }

    @ParameterizedTest
    @MethodSource("provideTestAlignmentOfScalarsParameters")
    public void testAlignmentOfScalars(int expectedAlignment, BPFType<?> bpfType) {
        assertEquals(expectedAlignment, bpfType.alignment());
    }

    private static void assertOffsetSameInLayoutAndMembers(BPFStructType<?> type) {
        for (var member : type.members()) {
            assertEquals(type.getOffsetOfMember(member.name()),
                    type.layout().byteOffset(MemoryLayout.PathElement.groupElement(member.name())));
        }
    }

    /**
     * Test layouting of {@link RingBufferTest.Event} struct
     */
    @Test
    public void testRingSampleStruct() {

        final int FILE_NAME_LEN = 256;
        final int TASK_COMM_LEN = 16;
        record Event(@Unsigned int pid, String filename, String comm) {
        }

        var eventType = BPFStructType.autoLayout("rb", List.of(new UBPFStructMember<>("e_pid",
                BPFType.BPFIntType.UINT32, null), new UBPFStructMember<>("e_filename",
                new BPFType.StringType(FILE_NAME_LEN), null), new UBPFStructMember<>("e_comm",
                new BPFType.StringType(TASK_COMM_LEN), null)), null, fields -> null);

        assertEquals(0, eventType.getOffsetOfMember("e_pid"));
        assertEquals(4, eventType.getOffsetOfMember("e_filename"));
        assertEquals(260, eventType.getOffsetOfMember("e_comm"));
        assertOffsetSameInLayoutAndMembers(eventType);
        assertEquals(276, eventType.layout().byteSize());
        assertEquals(4, eventType.layout().byteAlignment());
        assertEquals(276, eventType.sizePadded());
    }

    /**
     * Test layouting more complex struct
     */
    @Test
    public void testStructWithPadding() {
        record PaddingEvent(byte c, long l, int i, @Unsigned long x, boolean b) {
        }

        var type = BPFStructType.autoLayout("padding", List.of(new UBPFStructMember<>("c", BPFType.BPFIntType.UINT8,
                null), new UBPFStructMember<>("l", BPFType.BPFIntType.UINT64, null), new UBPFStructMember<>("i",
                BPFType.BPFIntType.INT32, null), new UBPFStructMember<>("x", BPFType.BPFIntType.UINT64, null),
                new UBPFStructMember<>("b", BPFType.BPFIntType.BOOL, null)), null, fields -> null);

        assertEquals(0, type.getOffsetOfMember("c"));
        assertEquals(8, type.getOffsetOfMember("l"));
        assertEquals(16, type.getOffsetOfMember("i"));
        assertEquals(24, type.getOffsetOfMember("x"));
        assertEquals(32, type.getOffsetOfMember("b"));
        assertOffsetSameInLayoutAndMembers(type);
        assertEquals(8, type.alignment());
        assertEquals(8, type.layout().byteAlignment());
        assertEquals(33, type.size());
        assertEquals(40, type.sizePadded());
    }

    /**
     * Test layouting of basic array
     */
    @Test
    public void testBasicArray() {
        var type = new BPFType.BPFArrayType<>("arr", BPFType.BPFIntType.INT32, 10);

        assertEquals(0, type.getOffsetAtIndex(0));
        assertEquals(4, type.getOffsetAtIndex(1));
        assertEquals(40, type.size());
        assertEquals(40, type.sizePadded());
        assertEquals(4, type.alignment());
    }

    @Test
    public void testArrayWithPadding() {
        // assume inner struct has 8 byte alignment and size 16
        record PaddingEntry(long l, byte c) {
        }

        var entryType = BPFStructType.autoLayout("entry", List.of(new UBPFStructMember<>("l", BPFType.BPFIntType.UINT64,
                null), new UBPFStructMember<>("c", BPFType.BPFIntType.UINT8, null)), null, fields -> null);

        var type = BPFType.BPFArrayType.of(entryType, 10);
        assertEquals(0, type.getOffsetAtIndex(0));
        assertEquals(16, type.getOffsetAtIndex(1));
        assertEquals(160, type.size());
        assertEquals(160, type.sizePadded());
        assertEquals(8, type.alignment());
    }

}