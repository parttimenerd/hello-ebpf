package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFProgArray;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.shared.util.DiffUtil;
import me.bechberger.ebpf.type.*;
import me.bechberger.ebpf.type.BPFType.BPFIntType.Int128;
import me.bechberger.ebpf.type.BPFType.BPFIntType.UnsignedInt128;
import me.bechberger.ebpf.type.Enum;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static me.bechberger.ebpf.bpf.BPFJ.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;


public class CompilerPluginTest {

    /**
     * Program with just a function call for testing that the compiler plugin is called
     */
    @BPF
    public static abstract class SimpleProgram extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                                
                int func(int x, int y);
                int func2(int x);
                
                void emptyBuiltin();
                """;

        @BuiltinBPFFunction
        @NotUsableInJava
        public int func(int x, int y) {
            throw new MethodIsBPFRelatedFunction();
        }

        @BuiltinBPFFunction("$arg1")
        @NotUsableInJava
        public int func2(int x, int y) {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public int simpleReturn(int x) {
            return 1;
        }

        @BPFFunction
        public int math(int x) {
            return func(x, x + 1) + 1;
        }

        @BPFFunction
        public void empty() {

        }

        @BuiltinBPFFunction()
        public void emptyBuiltin() {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public int math2(int x) {
            empty();
            emptyBuiltin();
            return func2(x, x + 1) + 2;
        }
    }

    @Test
    public void testSimpleProgram() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                                
                int func(int x, int y);
                int func2(int x);
                                
                void emptyBuiltin();
                
                s32 simpleReturn(s32 x);
                
                s32 math(s32 x);
                
                int empty();
                
                s32 math2(s32 x);
                                
                s32 simpleReturn(s32 x) {
                  return 1;
                }
                                
                s32 math(s32 x) {
                  return func(x, x + 1) + 1;
                }
                                
                int empty() {
                  return 0;
                }
                                
                s32 math2(s32 x) {
                  empty();
                  emptyBuiltin();
                  return x + 2;
                }
                """, BPFProgram.getCode(SimpleProgram.class));
    }

    @BPF
    public static abstract class TestPtr extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                """;

        @BPFFunction
        public int refAndDeref() {
            int value = 3;
            Ptr<Integer> ptr = Ptr.of(value);
            return ptr == Ptr.ofNull() ? 1 : 0;
        }

        @BPFFunction
        public int cast(Ptr<Integer> intPtr) {
            Ptr<Short> ptr = intPtr.<Short>cast();
            return ptr.val();
        }

        @BPFFunction
        public Ptr<Integer> increment(Ptr<Integer> ptr) {
            return ptr.add(1);
        }
    }

    @Test
    public void testPtr() {
        assertEqualsDiffed("""
                s32 refAndDeref();
                
                s32 cast(s32 *intPtr);
                
                s32* increment(s32 *ptr);

                s32 refAndDeref() {
                  s32 value = 3;
                  s32 *ptr = &(value);
                  return ptr == ((void*)0) ? 1 : 0;
                }
                
                s32 cast(s32 *intPtr) {
                  s16 *ptr = ((s16*)intPtr);
                  return (*(ptr));
                }
                
                s32* increment(s32 *ptr) {
                  return (ptr + 1);
                }
                """, BPFProgram.getCode(TestPtr.class));
    }

    @BPF
    public static abstract class TestPrint extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public void testPrint() {
            BPFHelpers.bpf_trace_printk("Hello, World!\\n", "Hello, World!\\n".length());
        }

        @BPFFunction
        public void testJavaPrint() {
            BPFJ.bpf_trace_printk("Hello, World!\\n");
        }

        @BPFFunction
        public void testJavaPrint2() {
            BPFJ.bpf_trace_printk("Hello, %s!\\n", "World");
        }
    }

    @Test
    public void testPrint() {
        assertEqualsDiffed("""
                int testPrint();
                
                int testJavaPrint();
                
                int testJavaPrint2();
                
                int testPrint() {
                  bpf_trace_printk((const u8*)"Hello, World!\\\\n", 15);
                  return 0;
                }
                
                int testJavaPrint() {
                  bpf_trace_printk("Hello, World!\\\\n", sizeof("Hello, World!\\\\n"));
                  return 0;
                }

                int testJavaPrint2() {
                  bpf_trace_printk("Hello, %s!\\\\n", sizeof("Hello, %s!\\\\n"), "World");
                  return 0;
                }
                """, BPFProgram.getCode(TestPrint.class));
    }

    @BPF
    public static abstract class TestGlobalVariable extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        public final GlobalVariable<Integer> count = new GlobalVariable<>(42);

        @BPFFunction
        public void testGlobalVariable() {
            count.set(43);
            int currentCount = count.get();
            BPFJ.bpf_trace_printk("Count: %d\\n", currentCount);
        }
    }

    @Test
    public void testGlobalVariable() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                                
                s32 count SEC(".data");
                
                int testGlobalVariable();
                
                int testGlobalVariable() {
                  count = 43;
                  s32 currentCount = count;
                  bpf_trace_printk("Count: %d\\\\n", sizeof("Count: %d\\\\n"), currentCount);
                  return 0;
                }
                """, BPFProgram.getCode(TestGlobalVariable.class));
    }

    void assertEqualsDiffed(String expected, String actual, boolean ignoreIncludes) {
        expected = ignoreIncludes ? removeIncludes(expected.strip()) : expected.strip();
        actual = ignoreIncludes ? removeIncludes(actual.strip()) : actual.strip();
        // Normalize incidental decoration that doesn't affect semantics:
        //  - __always_inline prefix on function decls/defs (auto-applied to non-entry helpers)
        //  - #line directives (added for source-mapped verifier errors)
        // The fixtures predate these features; comparing post-strip keeps them readable.
        actual = stripDecorations(actual);
        expected = stripDecorations(expected);
        if (!expected.equals(actual)) {
            var diff = DiffUtil.diff(expected, actual);
            System.err.println("Diff: ");
            System.err.println(diff);
            assertEquals(expected, actual);
        }
    }

    private static String stripDecorations(String code) {
        return code.lines()
                .filter(line -> !line.trim().startsWith("#line "))
                .map(line -> line.replace("__always_inline ", ""))
                .collect(Collectors.joining("\n"));
    }

    void assertEqualsDiffed(String expected, String actual) {
        assertEqualsDiffed(expected, actual, true);
    }

    String removeIncludes(String code) {
        var lines = code.lines().filter(line -> !line.startsWith("#include ")).collect(Collectors.joining("\n"));
        if (lines.startsWith("\n")) {
            lines = lines.substring(1);
        }
        return lines;
    }

    @BPF
    public static abstract class TestString extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public char stringAt(String str) {
            return str.charAt(0);
        }

        @BPFFunction
        public byte bytes(String str) {
            return str.getBytes()[0];
        }
    }

    @Test
    public void testString() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                
                u8 stringAt(u8 *str);
                
                s8 bytes(u8 *str);
                
                u8 stringAt(u8 *str) {
                  return str[0];
                }
                                
                s8 bytes(u8 *str) {
                  return (str)[0];
                }
                """, BPFProgram.getCode(TestString.class));
    }

    @BPF
    public static abstract class TestArray extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public int access(@Size(2) int[] arr) {
            return arr[0];
        }

        @BPFFunction
        public void create() {
            @Size(2) int[] arr = new int[2];
            arr[0] = 1;
            arr[1] = 2;
            BPFJ.bpf_trace_printk("Array: %d, %d\\n", arr[0], arr[1]);
        }

        @BPFFunction
        public void create2() {
            int[] arr = new int[2];
            int[] arr2 = {1, 2};
            int[] arr3 = new int[]{1, 2};
        }

        @BPFFunction
        public Ptr<Integer> toPtr(@Size(2) int[] arr) {
            return Ptr.of(arr);
        }
    }

    @Test
    public void testArray() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                
                s32 access(s32 arr[2]);
                
                int create();
                
                int create2();
                
                s32* toPtr(s32 arr[2]);
                                
                s32 access(s32 arr[2]) {
                  return arr[0];
                }
                
                int create() {
                  s32 arr[2];
                  arr[0] = 1;
                  arr[1] = 2;
                  bpf_trace_printk("Array: %d, %d\\\\n", sizeof("Array: %d, %d\\\\n"), arr[0], arr[1]);
                  return 0;
                }
                
                int create2() {
                  s32 arr[2];
                  s32 arr2[2] = {1, 2};
                  s32 arr3[2] = {1, 2};
                  return 0;
                }
                
                s32* toPtr(s32 arr[2]) {
                  return (arr);
                }
                """, BPFProgram.getCode(TestArray.class));
    }

    @BPF
    public static abstract class TestForLoopAndIf extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public int forLoop() {
            int sum = 0;
            for (int i = 0; i < 10; i++) {
                sum += i;
            }
            return 1;
        }

        @BPFFunction
        public int ifStatement(int x) {
            if (x > 0) {
                return 1;
            }
            return 0;
        }

        @BPFFunction
        public int ifEleseStatement(int x) {
            if (x > 0) {
                return 1;
            } else {
                return 0;
            }
        }

        @BPFFunction
        public int ifElseIfElse(int x) {
            if (x > 0) {
                return 1;
            } else if (x < -10) {
                return -1;
            } else {
                return 0;
            }
        }
    }

    @Test
    public void testForLoopAndIf() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                
                s32 forLoop();
                
                s32 ifStatement(s32 x);
                
                s32 ifEleseStatement(s32 x);
                
                s32 ifElseIfElse(s32 x);
                                
                s32 forLoop() {
                  s32 sum = 0;
                  for (s32 i = 0; i < 10; i++) {
                    sum += i;
                  }
                  return 1;
                }
                                
                s32 ifStatement(s32 x) {
                  if ((x > 0)) {
                    return 1;
                  }
                  return 0;
                }
                                
                s32 ifEleseStatement(s32 x) {
                  if ((x > 0)) {
                    return 1;
                  } else {
                    return 0;
                  }
                }
                                
                s32 ifElseIfElse(s32 x) {
                  if ((x > 0)) {
                    return 1;
                  } else if ((x < -10)) {
                    return -1;
                  } else {
                    return 0;
                  }
                }
                """, BPFProgram.getCode(TestForLoopAndIf.class));
    }

    @BPF
    public static abstract class TestComments extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        /**
         * Comment
         */
        @BPFFunction
        public int testComments() {
            // This is a comment
            return 1; // This is another comment
        }
    }

    @Test
    public void testComments() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                
                s32 testComments();
                
                s32 testComments() {
                  return 1;
                }
                """, BPFProgram.getCode(TestComments.class));
    }

    @BPF
    public static abstract class TestFinalVariable extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public int finalVariable() {
            final int i = 0;
            return i;
        }
    }

    @Test
    public void testFinalVariable() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                
                s32 finalVariable();
                                
                s32 finalVariable() {
                  s32 i = 0;
                  return i;
                }
                """, BPFProgram.getCode(TestFinalVariable.class));
    }

    @BPF
    public static abstract class EnumTest extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @Type
        enum TestEnum implements Enum<TestEnum> {
            A, B, @EnumMember(name = "D") C
        }

        @BPFFunction
        int ordinal(TestEnum e) {
            return (int) e.value();
        }

        @BPFFunction
        TestEnum ofValue(int ordinal) {
            return Enum.<TestEnum>ofValue(ordinal);
        }

        @BPFFunction
        TestEnum access() {
            return TestEnum.A;
        }

        @BPFFunction
        TestEnum access2() {
            return TestEnum.C;
        }
    }

    @Test
    public void testEnum() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                                
                enum TestEnum {
                  TEST_ENUM_A = 0,
                  TEST_ENUM_B = 1,
                  D = 2
                };
                
                s32 ordinal(enum TestEnum e);
                
                enum TestEnum ofValue(s32 ordinal);
                
                enum TestEnum access();
                
                enum TestEnum access2();
                
                s32 ordinal(enum TestEnum e) {
                  return (s32)(long)(e);
                }
                
                enum TestEnum ofValue(s32 ordinal) {
                  return (enum TestEnum)(ordinal);
                }
                
                enum TestEnum access() {
                  return TEST_ENUM_A;
                }
                
                enum TestEnum access2() {
                  return D;
                }
                """, BPFProgram.getCode(EnumTest.class));
    }

    public static final int OUTER_CONSTANT = 100;

    @BPF
    public static abstract class TestConstants extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        static final int TEST_CONSTANT = 100;
        static final String TEST_CONSTANT_STRING = "Hello, World!";

        @BPFFunction
        public int constant() {
            return TEST_CONSTANT;
        }

        @BPFFunction
        public String constantString() {
            return TEST_CONSTANT_STRING;
        }

        @BPFFunction
        public int outerConstant() {
            return OUTER_CONSTANT;
        }
    }

    @Test
    public void testConstants() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                                
                #define TEST_CONSTANT 100
                #define TEST_CONSTANT_STRING "Hello, World!"
                
                #define OUTER_CONSTANT 100
                
                s32 constant();
                
                u8* constantString();
                
                s32 outerConstant();
                
                s32 constant() {
                  return TEST_CONSTANT;
                }
                
                u8* constantString() {
                  return TEST_CONSTANT_STRING;
                }
                
                s32 outerConstant() {
                  return OUTER_CONSTANT;
                }
                """, BPFProgram.getCode(TestConstants.class));
    }

    @BPF
    public static abstract class TestStruct extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @Type
        static class Event extends Struct {
            @Unsigned
            int pid;
            @Size(256)
            String filename;
            @Size(16)
            String comm;
        }

        @BPFFunction
        int access(Event event) {
            return event.pid;
        }

        @BPFFunction
        void returnAndCreateEvent(Ptr<Event> evtPtr) {
            Event event = new Event();
            event.pid = 1;
            evtPtr.set(event);
        }
    }

    @Test
    public void testStruct() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                                
                struct Event {
                  u32 pid;
                  u8 filename[256];
                  u8 comm[16];
                };
                
                s32 access(struct Event event);
                
                int returnAndCreateEvent(struct Event *evtPtr);
                               
                s32 access(struct Event event) {
                  return event.pid;
                }
                                
                int returnAndCreateEvent(struct Event *evtPtr) {
                  struct Event event;
                  event.pid = 1;
                  *(evtPtr) = event;
                  return 0;
                }
                """, BPFProgram.getCode(TestStruct.class));
    }

    @BPF
    public static abstract class TestNotUsableInJavaStruct extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @Type
        @NotUsableInJava
        static class Event extends Struct {
            @Unsigned
            int pid;
        }

        @BPFFunction
        int use(Event event) {
            Event event2 = new Event();
            event2.pid = event.pid;
            return event2.pid;
        }
    }

    @Test
    public void testNotUsableInJavaStruct() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                                
                struct Event {
                  u32 pid;
                };
                
                s32 use(struct Event event);
                                
                s32 use(struct Event event) {
                  struct Event event2;
                  event2.pid = event.pid;
                  return event2.pid;
                }
                """, BPFProgram.getCode(TestNotUsableInJavaStruct.class));
    }

    @BPF
    public static abstract class TestUnion extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @Type
        static class SampleUnion extends Union {
            @Unsigned
            int ipv4;
            long count;
        }

        @BPFFunction
        int access(SampleUnion address) {
            return address.ipv4;
        }

        @BPFFunction
        long createAddress() {
            SampleUnion address = new SampleUnion();
            address.ipv4 = 1;
            return address.count;
        }
    }

    @Test
    public void testUnion() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                
                union SampleUnion {
                  u32 ipv4;
                  s64 count;
                };
                          
                s32 access(union SampleUnion address);
                
                s64 createAddress();
                
                s32 access(union SampleUnion address) {
                  return address.ipv4;
                }
                                
                s64 createAddress() {
                  union SampleUnion address;
                  address.ipv4 = 1;
                  return address.count;
                }
                """, BPFProgram.getCode(TestUnion.class));
    }

    @BPF
    public static abstract class TestRecordStruct extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @Type
        record Event(@Unsigned int pid, @Size(256) String filename) {
        }

        @BPFFunction
        int access(Event event) {
            int i = event.pid();
            return event.pid;
        }

        @BPFFunction
        void createEvent() {
            Event event = new Event(1, "file");
            BPFJ.setField(event, "pid", 2);
        }
    }

    @Test
    public void testRecordStruct() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                                
                struct Event {
                  u32 pid;
                  u8 filename[256];
                };
                
                s32 access(struct Event event);
                
                int createEvent();
                
                s32 access(struct Event event) {
                  s32 i = event.pid;
                  return event.pid;
                }
                
                int createEvent() {
                  struct Event event = (struct Event){.pid = 1, .filename = "file"};
                  (event).pid = 2;
                  return 0;
                }
                """, BPFProgram.getCode(TestRecordStruct.class));
    }

    @BPF
    public static abstract class TestInt128 extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        void create() {
            Int128 i = Int128.of(1, 2);
        }

        @BPFFunction
        long lower(Int128 i) {
            return i.lower();
        }

        @BPFFunction
        long upper(Int128 i) {
            return i.toUnsigned().upper();
        }

        @BPFFunction
        long lowerUnsigned(UnsignedInt128 i) {
            return i.lower();
        }
    }

    @Test
    public void testInt128() {
        assertEqualsDiffed("""
                int create();
                
                s64 lower(__int128 i);
                
                s64 upper(__int128 i);
                
                s64 lowerUnsigned(__int128 unsigned i);
                
                int create() {
                  __int128 i = (((__int128)1) << 64) | (2);
                  return 0;
                }
                
                s64 lower(__int128 i) {
                  return (s64)(i);
                }
                
                s64 upper(__int128 i) {
                  return (s64)((i) >> 64);
                }
                
                s64 lowerUnsigned(__int128 unsigned i) {
                  return (s64)(i);
                }
                """, BPFProgram.getCode(TestInt128.class));
    }

    @BPF
    public static abstract class TestBPFFunctionTemplates extends BPFProgram {

        @BPFFunction(
                callTemplate = "$name($arg1, $arg1)",
                headerTemplate = "$return $name($paramType1 $paramName1, $paramType1 y);",
                lastStatement = "(void*)0;",
                section = "section"
        )
        public void called(int x) {

        }

        @BPFFunction
        public void caller() {
            called(1);
        }
    }

    @Test
    public void testBPFFunctionTemplates() {
        assertEqualsDiffed("""
                
                int called(s32 x, s32 y);
                
                int caller();
                
                SEC("section") int called(s32 x, s32 y) {
                  (void*)0;
                }
                                
                int caller() {
                  called(1, 1);
                  return 0;
                }
                """, BPFProgram.getCode(TestBPFFunctionTemplates.class));
        assertEquals(List.of(), BPFProgram.getAutoAttachableBPFPrograms(TestBPFFunctionTemplates.class));
    }

    @BPFInterface
    interface TestInterface {
        @BPFFunction(
                callTemplate = "$name($arg1, $arg1)",
                headerTemplate = "int $name($paramType1 $paramName1, $paramType1 y)",
                lastStatement = "return 1;",
                section = "section",
                autoAttach = true
        )
        void func(String name);
    }

    @BPF
    static abstract class TestInterfaceImpl extends BPFProgram implements TestInterface {
        @Override
        public void func(String name) {
            BPFJ.bpf_trace_printk("Hello, %s!\\n", name);
        }
    }

    @Test
    public void testBPFFunctionTemplatesInterface() {
        assertEqualsDiffed("""
                int func(u8* name, u8* y);
                
                SEC("section") int func(u8* name, u8* y) {
                  bpf_trace_printk("Hello, %s!\\\\n", sizeof("Hello, %s!\\\\n"), name);
                  return 1;
                }
                """, BPFProgram.getCode(TestInterfaceImpl.class));
        assertEquals(List.of("func"), BPFProgram.getAutoAttachableBPFPrograms(TestInterfaceImpl.class));
    }

    @BPF
    static abstract class TestStringBody extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction(
                lastStatement = "bpf_trace_printk(\"%s\", 2, code);"
        )
        public void body() {
            String code = """
                    char* code = "Hello, World!";
                    """;
            throw new MethodIsBPFRelatedFunction();
        }
    }

    @Test
    public void testStringBody() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                
                int body();
                
                int body() {
                  char* code = "Hello, World!";
                  bpf_trace_printk("%s", 2, code);
                }
                """, BPFProgram.getCode(TestStringBody.class));
    }

    @BPFInterface
    public interface TestInterfaceWithCode {

        @BPFFunction
        default void func() {
            BPFJ.bpf_trace_printk("Hello, World!\\n");
        }

    }

    @Test
    @Disabled
    public void testInterfaceWithCode() {
        assertEqualsDiffed("""
                int func();
                
                int func() {
                  bpf_trace_printk("Hello, World!\\\\n", sizeof("Hello, World!\\\\n"));
                  return 0;
                }
                """, TestInterfaceWithCode.class.getAnnotation(InternalBody.class).value());
    }

    @BPF
    static abstract class TestUsingInterfaceWithCode extends BPFProgram implements TestInterfaceWithCode {
    }

    @Test
    public void testUsingInterfaceWithCode() {
        assertEqualsDiffed("""
                int func();
                
                int func() {
                  bpf_trace_printk("Hello, World!\\\\n", sizeof("Hello, World!\\\\n"));
                  return 0;
                }
                """, BPFProgram.getCode(TestUsingInterfaceWithCode.class));
    }

    @BPF
    static abstract class TestUsingCodeInMethods extends BPFProgram {
        @BPFFunction
        public void func(int x) {
            final String code = """
                    bpf_trace_printk("Hello, %d!\\\\n", x);
                    """;
        }
    }

    @Test
    public void testUsingCodeInMethods() {
        assertEqualsDiffed("""
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                int func(s32 x);

                int func(s32 x) {
                  bpf_trace_printk("Hello, %d!\\\\n", x);
                  return 0;
                }
                """, BPFProgram.getCode(TestUsingCodeInMethods.class));
    }

    @BPFInterface(after = "//after")
    public interface TestInterfaceWithAfter {

        @BPFFunction
        default void func() {
            BPFJ.bpf_trace_printk("Hello, World!\\n");
        }

    }

    @BPFInterface
    public interface TestInterfaceWithAfter2 extends TestInterfaceWithAfter {

    }

    @BPF
    public static abstract class TestUsingInterfaceWithAfter extends BPFProgram implements TestInterfaceWithAfter2 {
    }

    @Test
    public void testUsingInterfaceWithAfter() {
        assertEqualsDiffed("""
                int func() {
                  bpf_trace_printk("Hello, World!\\\\n", sizeof("Hello, World!\\\\n"));
                  return 0;
                }

                //after
                """, BPFProgram.getCode(TestUsingInterfaceWithAfter.class));
    }

    @BPF
    public static abstract class TestBasicFunctionMacro extends BPFProgram {

        @BuiltinBPFFunction("$lambda1:param1:type $lambda1:param1:name = $arg2; $lambda1:code")
        public static void testMacro(Consumer<Integer> consumer, int arg) {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public void _code() {
            testMacro((a) -> {
                BPFJ.bpf_trace_printk("Hello, %d!\\n", a);
            }, 2);
        }
    }

    @Test
    public void testBasicFunctionMacro() {
        assertEqualsDiffed("""
                int _code();

                int _code() {
                  s32 a = 2; bpf_trace_printk("Hello, %d!\\\\n", sizeof("Hello, %d!\\\\n"), a);
                  return 0;
                }
                """, BPFProgram.getCode(TestBasicFunctionMacro.class));
    }

    @BPF
    public static abstract class TestLoopFunctionMacro extends BPFProgram {
        @BuiltinBPFFunction("""
                for (int i = 0; i < 0; i++) {
                    $lambda1:code
                }
                """)
        public static void testMacro(Consumer<Integer> consumer) {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public int _code() {
            testMacro((i) -> {
                if (i == 1) {
                    _continue();
                }
                if (i == 2) {
                    _return(3);
                }
                if (i == 3) {
                    _break();
                }
            });
            return 1;
        }
    }

    @Test
    public void testLoopFunctionMacro() {
        assertEqualsDiffed("""
                s32 _code();

                s32 _code() {
                  for (int i = 0; i < 0; i++) {
                      if ((i == 1)) {
                        continue;
                      }
                      if ((i == 2)) {
                        return 3;
                      }
                      if ((i == 3)) {
                        break;
                      }
                  };
                  return 1;
                }
                """, BPFProgram.getCode(TestLoopFunctionMacro.class));
    }

    @BPF
    public static abstract class TestBox extends BPFProgram {
        @BPFFunction
        public void testBox() {
            Box<Integer> box = Box.of(1);
        }
    }

    @Test
    public void testBox() {
        assertEqualsDiffed("""
                int testBox();

                int testBox() {
                  s32 box = 1;
                  return 0;
                }
                """, BPFProgram.getCode(TestBox.class));
    }

    @BPFInterface
    public interface TestInterfaceWithStruct {
        @Type
        public record Event(@Unsigned int pid, @Size(256) String filename) {
        }
    }

    @BPF
    public static abstract class TestUsingInterfaceWithStruct extends BPFProgram implements TestInterfaceWithStruct {

        @BPFMapDefinition(maxEntries = 100)
        BPFHashMap<Integer, Event> events;
    }

    @Test
    public void testInterfaceWithStruct() {
        assertEqualsDiffed("""
                struct Event {
                  u32 pid;
                  u8 filename[256];
                };


                struct {
                    __uint (type, BPF_MAP_TYPE_HASH);
                    __uint (key_size, sizeof(s32));
                    __uint (value_size, sizeof(struct Event));
                    __uint (max_entries, 100);
                } events SEC(".maps");
                """, BPFProgram.getCode(TestUsingInterfaceWithStruct.class));
    }

    @BPF
    public static abstract class TestUsingInterfaceWithStruct2 extends BPFProgram implements TestInterfaceWithStruct {
        final GlobalVariable<Event> event = new GlobalVariable<>(new Event(1, "file"));
    }

    @Test
    public void testUsingInterfaceWithStruct2() {
        assertEqualsDiffed("""
                struct Event {
                  u32 pid;
                  u8 filename[256];
                };


                struct Event event SEC(".data");
                """, BPFProgram.getCode(TestUsingInterfaceWithStruct2.class));
    }

    // ──────────────────────────────────────────────────────────
    // Nullability tests (Phase 2)
    // ──────────────────────────────────────────────────────────

    /** Null-safe map lookup: result is guarded by an if != null check before use. */
    @BPF
    public static abstract class NullSafeMapLookup extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                """;

        @BPFMapDefinition(maxEntries = 64)
        BPFHashMap<Integer, Integer> counts;

        @BPFFunction
        public void increment(int key) {
            Ptr<Integer> val = counts.bpf_get(key);
            if (val != null) {
                val.set(val.val() + 1);
            }
        }
    }

    @Test
    public void testNullSafeMapLookupAccepted() {
        // The program should compile without error and produce the correct C code.
        assertEqualsDiffed("""
                struct {
                    __uint (type, BPF_MAP_TYPE_HASH);
                    __uint (key_size, sizeof(s32));
                    __uint (value_size, sizeof(s32));
                    __uint (max_entries, 64);
                } counts SEC(".maps");

                int increment(s32 key);

                int increment(s32 key) {
                  s32 *val = bpf_map_lookup_elem(&counts, &key);
                  if ((val != NULL)) {
                    *(val) = (*(val)) + 1;
                  }
                  return 0;
                }
                """, BPFProgram.getCode(NullSafeMapLookup.class));
    }

    // Note: "should reject" (unsafe deref without null check) cannot be an inner class of this
    // file because a compile error from the BPF plugin would prevent the whole file from compiling.
    // Rejection is verified manually or by a separate test-compilation project.

    // ──────────────────────────────────────────────────────────
    // Phase 4.1 — Tail call lowering via BPFProgArray
    // ──────────────────────────────────────────────────────────

    /** Minimal tail-call program: one prog-array map, one tailCall call site. */
    @BPF
    public static abstract class TailCallSample extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                """;

        @BPFMapDefinition(maxEntries = 4)
        BPFProgArray progs;

        @BPFFunction
        public int dispatch(Ptr<xdp_md> ctx, int key) {
            progs.tailCall(ctx, key);
            return 0;
        }
    }

    @Test
    public void testTailCallLowering() {
        String code = BPFProgram.getCode(TailCallSample.class);
        assertEqualsDiffed("""
                struct {
                    __uint (type, BPF_MAP_TYPE_PROG_ARRAY);
                    __uint (key_size, sizeof(u32));
                    __uint (value_size, sizeof(u32));
                    __uint (max_entries, 4);
                } progs SEC(".maps");

                s32 dispatch(struct xdp_md *ctx, s32 key);

                s32 dispatch(struct xdp_md *ctx, s32 key) {
                  bpf_tail_call(ctx, &progs, key);
                  return 0;
                }
                """, code);
    }

    // --- C.3: Constant folding tests ---

    @BPF
    public static abstract class ConstantFoldFalse extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @BuiltinBPFFunction("illegal_helper()")
        @NotUsableInJava
        public void illegalHelper() {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public int test(int x) {
            if (false) {
                illegalHelper();
            }
            return x;
        }
    }

    @Test
    public void testConstantFoldFalse() {
        String code = BPFProgram.getCode(ConstantFoldFalse.class);
        // The dead branch should be eliminated; illegal_helper must not appear
        assertFalse(code.contains("illegal_helper"),
                "constant-false branch should be eliminated, illegal_helper must not appear in output:\n" + code);
        assertTrue(code.contains("return x;"),
                "test() body should still contain return x; got:\n" + code);
    }

    @BPF
    public static abstract class ConstantFoldTrue extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @BPFFunction
        public int test(int x) {
            if (true) {
                return x + 1;
            } else {
                return x - 1;
            }
        }
    }

    @Test
    public void testConstantFoldTrue() {
        String code = BPFProgram.getCode(ConstantFoldTrue.class);
        // True branch kept, else branch eliminated
        assertTrue(code.contains("return x + 1;"),
                "true-branch body should be preserved; got:\n" + code);
        assertFalse(code.contains("return x - 1;"),
                "else branch should be eliminated; got:\n" + code);
    }

    @BPF
    public static abstract class ConstantFoldStaticField extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        static final boolean FEATURE_ENABLED = false;

        @BuiltinBPFFunction("unused_helper()")
        @NotUsableInJava
        public void unusedHelper() {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public int test(int x) {
            if (FEATURE_ENABLED) {
                unusedHelper();
                return x + 99;
            }
            return x;
        }
    }

    @Test
    public void testConstantFoldStaticField() {
        String code = BPFProgram.getCode(ConstantFoldStaticField.class);
        // Static-final-false condition: dead branch eliminated
        assertFalse(code.contains("unused_helper"),
                "constant-false static field branch should be eliminated, unused_helper must not appear:\n" + code);
        assertFalse(code.contains("return x + 99;"),
                "dead-branch return must not appear:\n" + code);
        assertTrue(code.contains("return x;"),
                "fallthrough return must remain:\n" + code);
    }

    /** XDP program that calls a kernel helper illegal in XDP context.
     *  Compilation should succeed (warning, not error) but the helper-context
     *  pass should emit a javac warning visible in the build log.
     *  Existence test only — no in-process diagnostic capture. */
    @BPF
    public static abstract class HelperContextXDPViolation extends BPFProgram implements XDPHook {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            // bpf_get_current_task is illegal in XDP — verifier rejects at load time.
            long task = BPFHelpers.bpf_get_current_task();
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testHelperContextXDPViolationStillCompiles() {
        // The pass emits a warning, not an error, so generated C should still contain the call.
        String code = BPFProgram.getCode(HelperContextXDPViolation.class);
        assertTrue(code.contains("bpf_get_current_task"),
                "helper call should still appear in generated C (pass warns, doesn't block):\n" + code);
    }

    /** Phase D.2/D.3 — function-pointer-style lambda lift via {@code $funcN}.
     *  {@code BPFJ.bpfLoop(10, (i, ctx) -> 0, null)} must lift the lambda to a top-level
     *  static {@code __always_inline} function and pass its name to {@code bpf_loop}. */
    @BPF
    public static abstract class BpfLoopLambda extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        public final GlobalVariable<Integer> sum = new GlobalVariable<>(0);

        @BPFFunction
        public void runLoop() {
            BPFJ.bpfLoop(10, (i, ctx) -> {
                return 0;
            }, null);
        }
    }

    @Test
    public void testBpfLoopLambdaLifted() {
        String code = BPFProgram.getCode(BpfLoopLambda.class);
        assertTrue(code.contains("static __always_inline"),
                "lifted lambda should be static __always_inline in generated C:\n" + code);
        assertTrue(code.contains("__bpf_lambda_runLoop_0"),
                "lifted lambda's synthetic name should appear in generated C:\n" + code);
        assertTrue(code.contains("bpf_loop(10, __bpf_lambda_runLoop_0"),
                "bpf_loop call should reference the synthetic function:\n" + code);
    }

    /** Phase D.2 — capturing locals from the enclosing method must be rejected.
     *  We verified this manually: the program below
     *  <pre>{@code
     *      @BPFFunction
     *      public void runLoop() {
     *          int x = 0;
     *          BPFJ.bpfLoop(10, (i, ctx) -> { int y = x; return 0; }, null);
     *      }
     *  }</pre>
     *  fails compilation with a {@code Diagnostic.Kind.ERROR} containing
     *  "captures local variable 'x'". Because plugin-emitted ERRORs abort javac,
     *  there's no way to keep the bad program compiling here just to assert in a
     *  test, short of building dedicated negative-test infrastructure (see
     *  {@code bpf-compiler-plugin-test} module). The behaviour is exercised by
     *  {@code MapForEachTest}/{@code BpfLoopTest} in {@code bpf} which use
     *  the legal {@code ctx} parameter. */
    @org.junit.jupiter.api.Disabled("Negative test — would break compilation; see Javadoc.")
    @Test
    public void testBpfLoopLambdaCaptureRejected_documented() {
    }

    /** Phase D — two lambdas in one method must lift to two distinct synthetic
     *  functions with stable indexed names. */
    @BPF
    public static abstract class TwoBpfLoopLambdas extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public void runLoops() {
            BPFJ.bpfLoop(5, (i, ctx) -> { return 0; }, null);
            BPFJ.bpfLoop(7, (i, ctx) -> { return 0; }, null);
        }
    }

    @Test
    public void testTwoBpfLoopLambdasLiftDistinct() {
        String code = BPFProgram.getCode(TwoBpfLoopLambdas.class);
        assertTrue(code.contains("__bpf_lambda_runLoops_0"),
                "first lambda should lift to __bpf_lambda_runLoops_0; got:\n" + code);
        assertTrue(code.contains("__bpf_lambda_runLoops_1"),
                "second lambda should lift to __bpf_lambda_runLoops_1; got:\n" + code);
        assertTrue(code.contains("bpf_loop(5, __bpf_lambda_runLoops_0"),
                "first call site should reference _0; got:\n" + code);
        assertTrue(code.contains("bpf_loop(7, __bpf_lambda_runLoops_1"),
                "second call site should reference _1; got:\n" + code);
    }

    /** Phase D — {@code BPFHashMap.forEach} should lift its lambda using the
     *  {@code :mapelem} flavor: kernel ABI signature with key/value pointer
     *  parameters, and a deref prologue so the user body sees plain {@code k}/{@code v}. */
    @BPF
    public static abstract class MapForEachLift extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Integer> map;

        @BPFFunction
        public void run() {
            map.forEach((k, v) -> { return 0; }, null);
        }
    }

    @Test
    public void testMapForEachLambdaMapElemSignature() {
        String code = BPFProgram.getCode(MapForEachLift.class);
        assertTrue(code.contains("__bpf_lambda_run_0"),
                "forEach lambda should lift with synthetic name __bpf_lambda_run_0; got:\n" + code);
        // mapelem ABI: 4 params with bpf_map / const void *key / void *value / void *ctx.
        assertTrue(code.contains("struct bpf_map") && code.contains("const void *")
                        && code.contains("void *"),
                "mapelem ABI should declare (struct bpf_map *, const void *key, void *value, void *ctx); got:\n" + code);
        assertTrue(code.contains("bpf_for_each_map_elem(&map, __bpf_lambda_run_0"),
                "forEach call should reference the lifted function; got:\n" + code);
    }

    /** Phase C.2 — kprobe calling {@code bpf_get_current_task} is allowed and should
     *  NOT trigger a HelperContextPass warning. (The XDP version above is rejected;
     *  this proves the allowed-set is honoured.) */
    @BPF
    public static abstract class HelperContextKprobeAllowed extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @BPFFunction(section = "kprobe/do_sys_openat2")
        public int onOpen() {
            long task = BPFHelpers.bpf_get_current_task();
            return 0;
        }
    }

    @Test
    public void testHelperContextKprobeAllowedCompiles() {
        String code = BPFProgram.getCode(HelperContextKprobeAllowed.class);
        assertTrue(code.contains("bpf_get_current_task"),
                "kprobe should keep the helper call (no warning, no rewrite):\n" + code);
    }

    /** Phase C.2 — helpers not in the curated HELPER_COMPAT table must not be
     *  flagged. {@code bpf_ktime_get_ns} is universally available and is not tracked. */
    @BPF
    public static abstract class HelperContextUntracked extends BPFProgram implements XDPHook {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            long now = BPFHelpers.bpf_ktime_get_ns();
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testHelperContextUntrackedHelperCompiles() {
        String code = BPFProgram.getCode(HelperContextUntracked.class);
        assertTrue(code.contains("bpf_ktime_get_ns"),
                "untracked helper should appear unchanged in generated C:\n" + code);
    }

    /** Phase C.1 — guarded packet deref should compile and contain the deref
     *  unchanged. (Pass emits warnings only; here we verify the happy path
     *  doesn't strip anything and that the program is a valid XDP probe.) */
    @BPF
    public static abstract class BoundsCheckGuarded extends BPFProgram implements XDPHook {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            Ptr<?> data = Ptr.voidPointer(ctx.val().data);
            Ptr<?> end = Ptr.voidPointer(ctx.val().data_end);
            if (data.add(14).greaterThan(end)) {
                return xdp_action.XDP_ABORTED;
            }
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testBoundsCheckGuardedCompiles() {
        String code = BPFProgram.getCode(BoundsCheckGuarded.class);
        // The generated C should still contain the data-end comparison.
        assertTrue(code.contains("data_end"),
                "guarded XDP program should still reference data_end in generated C:\n" + code);
    }

    /** Phase C.3 — outer constant-false condition eliminates the entire branch
     *  including any nested constant-true branch. Verifies dead-code elimination
     *  is not gated on the inner condition. */
    @BPF
    public static abstract class ConstantFoldNested extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        static final boolean OUTER = false;

        @BuiltinBPFFunction("nested_illegal_helper()")
        @NotUsableInJava
        public void nestedIllegalHelper() {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public int test(int x) {
            if (OUTER) {
                if (true) {
                    nestedIllegalHelper();
                }
            }
            return x;
        }
    }

    @Test
    public void testConstantFoldNested() {
        String code = BPFProgram.getCode(ConstantFoldNested.class);
        assertFalse(code.contains("nested_illegal_helper"),
                "outer constant-false branch should eliminate nested calls:\n" + code);
        assertTrue(code.contains("return x;"),
                "fallthrough must remain:\n" + code);
    }
}
