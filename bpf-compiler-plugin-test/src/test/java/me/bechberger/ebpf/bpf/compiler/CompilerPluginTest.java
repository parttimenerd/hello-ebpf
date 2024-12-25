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
        if (!expected.equals(actual)) {
            var diff = DiffUtil.diff(expected, actual);
            System.err.println("Diff: ");
            System.err.println(diff);
            assertEquals(expected, actual);
        }
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
}
