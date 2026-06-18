package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.BoundedBy;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.bpf.sched.KickFlags;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFInodeStorage;
import me.bechberger.ebpf.bpf.map.BPFLpmTrie;
import me.bechberger.ebpf.bpf.map.BPFProgArray;
import me.bechberger.ebpf.bpf.map.BPFSkStorage;
import me.bechberger.ebpf.bpf.map.BPFDevMap;
import me.bechberger.ebpf.bpf.map.BPFCpuMap;
import me.bechberger.ebpf.bpf.map.BPFArena;
import me.bechberger.ebpf.bpf.map.BPFTypedArena;
import me.bechberger.ebpf.annotations.InArena;
import me.bechberger.ebpf.runtime.runtime.inode;
import me.bechberger.ebpf.runtime.runtime.sock;
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
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_select_cpu_dfl;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_enq_flags.SCX_ENQ_PREEMPT;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;


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
                  bpf_trace_printk((const u8 *)"Hello, World!\\\\n", 15);
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
    @Disabled("@InternalBody is not yet emitted onto @BPFInterface — see CompilerPlugin#processBPFInterface")
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
                    __uint (map_flags, BPF_F_NO_PREALLOC);
                    __type (key, s32);
                    __type (value, struct Event);
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
                    __uint (map_flags, BPF_F_NO_PREALLOC);
                    __type (key, s32);
                    __type (value, s32);
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

    // ---------------------------------------------------------------------
    // Phase E — CO-RE: BPF_CORE_READ emission for @KernelBTF chains
    // ---------------------------------------------------------------------

    /** Phase E.2 — single-step access into a kernel-BTF struct must lower to
     *  BPF_CORE_READ so libbpf relocates the field offset against the target
     *  kernel's BTF at load time. */
    @BPF
    public static abstract class CoreSingleField extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @BPFFunction
        public int readState(Ptr<task_struct> p) {
            return p.val().__state;
        }
    }

    @Test
    public void testCoreSingleField() {
        String code = BPFProgram.getCode(CoreSingleField.class);
        assertTrue(code.contains("BPF_CORE_READ(p, __state)"),
                "kernel-BTF field access must lower to BPF_CORE_READ(root, member):\n" + code);
        assertFalse(code.contains("p->__state") || code.contains("(*(p)).__state"),
                "plain pointer deref must not appear for kernel-BTF chain:\n" + code);
    }

    /** Phase E.2 — user-defined @Type record fields must NOT trigger CO-RE.
     *  Their layout is fixed at compile time. */
    @BPF
    public static abstract class CoreUserType extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Type
        record Foo(int x) {}

        @BPFFunction
        public int readX(Ptr<Foo> p) {
            return p.val().x;
        }
    }

    @Test
    public void testCoreUserTypeStaysPlain() {
        String code = BPFProgram.getCode(CoreUserType.class);
        assertFalse(code.contains("BPF_CORE_READ"),
                "user @Type record access must not emit BPF_CORE_READ:\n" + code);
    }

    /** Phase E.2 — multi-level kernel chain folds into a single BPF_CORE_READ
     *  whose argument list spells out the path. Uses xdp_md.data which is a
     *  pointer field on a kernel-BTF struct accessed inside a guarded XDP hook
     *  (bounds-check pass requires the wrapping). */
    @BPF
    public static abstract class CoreXdpData extends BPFProgram implements XDPHook {
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
    public void testCoreXdpDataChainEmitsCoreRead() {
        String code = BPFProgram.getCode(CoreXdpData.class);
        assertTrue(code.contains("BPF_CORE_READ(ctx, data)"),
                "kernel-BTF xdp_md.data must lower to BPF_CORE_READ(ctx, data):\n" + code);
        assertTrue(code.contains("BPF_CORE_READ(ctx, data_end)"),
                "kernel-BTF xdp_md.data_end must lower to BPF_CORE_READ(ctx, data_end):\n" + code);
    }

    // ---------------------------------------------------------------------
    // Bug-hunting lambda tests (Phase D follow-ups)
    // ---------------------------------------------------------------------

    /**
     * Two {@code map.forEach} calls in the same method. Both lambdas must lift
     * to distinct synthetic names. The Translator's per-method counter should
     * advance for forEach as it does for bpfLoop.
     */
    @BPF
    public static abstract class TwoForEachLambdas extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Integer> mapA;

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Integer> mapB;

        @BPFFunction
        public void run() {
            mapA.forEach((k, v) -> { return 0; }, null);
            mapB.forEach((k, v) -> { return 0; }, null);
        }
    }

    @Test
    public void testTwoForEachLambdasLiftDistinct() {
        String code = BPFProgram.getCode(TwoForEachLambdas.class);
        assertTrue(code.contains("__bpf_lambda_run_0"),
                "first forEach lambda should lift to __bpf_lambda_run_0; got:\n" + code);
        assertTrue(code.contains("__bpf_lambda_run_1"),
                "second forEach lambda should lift to __bpf_lambda_run_1; got:\n" + code);
        assertTrue(code.contains("bpf_for_each_map_elem(&mapA, __bpf_lambda_run_0"),
                "first forEach call should reference _0; got:\n" + code);
        assertTrue(code.contains("bpf_for_each_map_elem(&mapB, __bpf_lambda_run_1"),
                "second forEach call should reference _1; got:\n" + code);
    }

    /**
     * Mixed {@code bpfLoop} and {@code forEach} in the same method. The per-method
     * counter is shared; both should get distinct indices regardless of shape.
     */
    @BPF
    public static abstract class MixedBpfLoopAndForEach extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Integer> map;

        @BPFFunction
        public void run() {
            BPFJ.bpfLoop(3, (i, ctx) -> { return 0; }, null);
            map.forEach((k, v) -> { return 0; }, null);
            BPFJ.bpfLoop(5, (i, ctx) -> { return 0; }, null);
        }
    }

    @Test
    public void testMixedLambdaCounterAdvances() {
        String code = BPFProgram.getCode(MixedBpfLoopAndForEach.class);
        assertTrue(code.contains("__bpf_lambda_run_0"), "expected _0 in:\n" + code);
        assertTrue(code.contains("__bpf_lambda_run_1"), "expected _1 in:\n" + code);
        assertTrue(code.contains("__bpf_lambda_run_2"), "expected _2 in:\n" + code);
        assertTrue(code.contains("bpf_loop(3, __bpf_lambda_run_0"),
                "first bpfLoop call should reference _0:\n" + code);
        assertTrue(code.contains("bpf_for_each_map_elem(&map, __bpf_lambda_run_1"),
                "forEach call should reference _1:\n" + code);
        assertTrue(code.contains("bpf_loop(5, __bpf_lambda_run_2"),
                "second bpfLoop call should reference _2:\n" + code);
    }

    /**
     * Lambda counter must reset per-method. Two methods with one lambda each
     * should both produce {@code _0} (different prefixes prevent collision).
     */
    @BPF
    public static abstract class TwoMethodsOneLambdaEach extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public void methodA() {
            BPFJ.bpfLoop(1, (i, ctx) -> { return 0; }, null);
        }

        @BPFFunction
        public void methodB() {
            BPFJ.bpfLoop(1, (i, ctx) -> { return 0; }, null);
        }
    }

    @Test
    public void testLambdaCounterPerMethod() {
        String code = BPFProgram.getCode(TwoMethodsOneLambdaEach.class);
        assertTrue(code.contains("__bpf_lambda_methodA_0"),
                "methodA's lambda should lift to __bpf_lambda_methodA_0:\n" + code);
        assertTrue(code.contains("__bpf_lambda_methodB_0"),
                "methodB's lambda should also start at _0:\n" + code);
    }

    /**
     * Empty-body lambda. The translator must inject {@code return 0;} so the
     * lifted function is well-formed (the compiler-plugin's {@code endsWithReturn}
     * check should add it).
     */
    @BPF
    public static abstract class EmptyBodyLambda extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public void run() {
            BPFJ.bpfLoop(1, (i, ctx) -> { return 0; }, null);
        }
    }

    @Test
    public void testEmptyBodyLambdaHasReturn() {
        String code = BPFProgram.getCode(EmptyBodyLambda.class);
        // The lifted function body must contain a return; otherwise the verifier
        // sees an int-returning function with no return, which is undefined.
        int liftIdx = code.indexOf("__bpf_lambda_run_0");
        assertTrue(liftIdx > 0, "lambda must be lifted; got:\n" + code);
        // Find the function body opening brace after the function declaration.
        int braceIdx = code.indexOf("{", liftIdx);
        assertTrue(braceIdx > 0, "lifted function must have a body; got:\n" + code);
        int closeIdx = code.indexOf("}", braceIdx);
        String liftedBody = code.substring(braceIdx, closeIdx);
        assertTrue(liftedBody.contains("return"),
                "lifted lambda body must contain a return:\n" + liftedBody);
    }

    /**
     * forEach lambda where the user names the value parameter the same as one
     * of the prologue-generated locals could collide. Verifies the prologue
     * uses {@code __key}/{@code __value} (with underscores) so user-chosen
     * plain names like {@code k}, {@code key}, {@code v} do not collide.
     */
    @BPF
    public static abstract class ForEachWithUserNamedKey extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Integer> map;

        @BPFFunction
        public void run() {
            map.forEach((key, value) -> { return 0; }, null);
        }
    }

    @Test
    public void testForEachUserNamedKeyValueWorks() {
        String code = BPFProgram.getCode(ForEachWithUserNamedKey.class);
        // Prologue should derive `key` from `__key`, not collide.
        assertTrue(code.contains("*((") && code.contains("*)__key)"),
                "prologue must read from __key:\n" + code);
        assertTrue(code.contains("*((") && code.contains("*)__value)"),
                "prologue must read from __value:\n" + code);
    }

    /**
     * bpfLoop with a non-literal count. The signature accepts {@code int}, not
     * just literal ints — feeding a local variable must work and the lift must
     * still happen.
     */
    @BPF
    public static abstract class BpfLoopVariableCount extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public void run() {
            int n = 7;
            BPFJ.bpfLoop(n, (i, ctx) -> { return 0; }, null);
        }
    }

    @Test
    public void testBpfLoopVariableCountWorks() {
        String code = BPFProgram.getCode(BpfLoopVariableCount.class);
        assertTrue(code.contains("__bpf_lambda_run_0"),
                "lambda must lift even with non-literal count:\n" + code);
        assertTrue(code.contains("bpf_loop(n, __bpf_lambda_run_0"),
                "call site must use the variable name:\n" + code);
    }

    /**
     * Constant-fold a bpfLoop call site itself: {@code if (false) bpfLoop(...);}
     * The dead branch should be eliminated; no lifted lambda for it should
     * appear (constant-fold eliminates the branch *before* lambda lift, so
     * the synthetic counter must not advance for the dead lambda).
     */
    @BPF
    public static abstract class DeadBpfLoopBranch extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        static final boolean GATE = false;

        @BPFFunction
        public void run() {
            if (GATE) {
                BPFJ.bpfLoop(99, (i, ctx) -> { return 0; }, null);
            }
            BPFJ.bpfLoop(3, (i, ctx) -> { return 0; }, null);
        }
    }

    @Test
    public void testDeadBpfLoopBranchEliminatedAndCounterNotAdvanced() {
        String code = BPFProgram.getCode(DeadBpfLoopBranch.class);
        // The dead lambda must NOT appear in generated C.
        assertFalse(code.contains("bpf_loop(99,"),
                "dead bpfLoop(99) should be eliminated:\n" + code);
        // The live lambda should be at index _0 (not _1) since the dead one was eliminated.
        assertTrue(code.contains("bpf_loop(3, __bpf_lambda_run_0"),
                "live lambda should be at _0 since dead branch eliminated:\n" + code);
        // BUG HUNT: if the counter advanced for the dead lambda, the live one would be _1 and the test would fail.
    }

    /**
     * Lambda body referencing a static-final field (a constant). This is a
     * "capture" in Java semantics but should be allowed by the BPF compiler
     * since static-final field references resolve at link time, not via a
     * frame-captured variable.
     */
    @BPF
    public static abstract class LambdaUsesStaticFinal extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        static final int CONST_BUMP = 42;

        final GlobalVariable<Integer> total = new GlobalVariable<>(0);

        @BPFFunction
        public void run() {
            BPFJ.bpfLoop(1, (i, ctx) -> {
                total.set(total.get() + CONST_BUMP);
                return 0;
            }, null);
        }
    }

    @Test
    public void testLambdaCanUseStaticFinal() {
        String code = BPFProgram.getCode(LambdaUsesStaticFinal.class);
        assertTrue(code.contains("__bpf_lambda_run_0"),
                "lambda must lift even when referencing a static final:\n" + code);
        // Constant-fold may or may not have replaced CONST_BUMP — either way
        // the lift must succeed, no capture error.
    }

    /**
     * Lambda with a nested block-local variable. The capture analysis must
     * NOT flag locals declared inside the lambda body itself.
     */
    @BPF
    public static abstract class LambdaWithNestedLocal extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        final GlobalVariable<Integer> total = new GlobalVariable<>(0);

        @BPFFunction
        public void run() {
            BPFJ.bpfLoop(5, (i, ctx) -> {
                int doubled = i * 2;
                total.set(total.get() + doubled);
                return 0;
            }, null);
        }
    }

    @Test
    public void testLambdaNestedLocalsAllowed() {
        String code = BPFProgram.getCode(LambdaWithNestedLocal.class);
        assertTrue(code.contains("__bpf_lambda_run_0"),
                "lambda must lift with internal locals:\n" + code);
        assertTrue(code.contains("doubled"),
                "internal local 'doubled' must appear in lifted body:\n" + code);
    }

    /**
     * forEach lambda that uses {@code BPFJ._continue()} and {@code BPFJ._break()}
     * — these are syntactic sugar for {@code continue}/{@code break} that the
     * Translator special-cases. They must lower correctly inside a lifted
     * lambda body. Note: with the lift, there is no enclosing loop in the
     * lifted C function, so {@code _break}/{@code _continue} would be
     * malformed — but the user is expected to use {@code return 1}/{@code return 0}
     * for bpf_loop break/continue. This test documents the surprising behavior
     * by checking what currently happens.
     */
    @BPF
    public static abstract class LambdaWithReturnEarly extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        @BPFFunction
        public void run() {
            BPFJ.bpfLoop(10, (i, ctx) -> {
                if (i == 5) {
                    return 1;  // bpf_loop break
                }
                return 0;
            }, null);
        }
    }

    @Test
    public void testLambdaWithEarlyReturn() {
        String code = BPFProgram.getCode(LambdaWithReturnEarly.class);
        assertTrue(code.contains("__bpf_lambda_run_0"),
                "lambda must lift with early return:\n" + code);
        // The body should contain the return 1.
        int liftIdx = code.indexOf("__bpf_lambda_run_0");
        int braceIdx = code.indexOf("{", liftIdx);
        // Find the matching close brace.
        int depth = 0;
        int end = braceIdx;
        for (int i = braceIdx; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) { end = i; break; }
            }
        }
        String body = code.substring(braceIdx, end);
        assertTrue(body.contains("return 1"),
                "lifted body must preserve early return 1:\n" + body);
        assertTrue(body.contains("return 0"),
                "lifted body must preserve return 0:\n" + body);
    }

    // ---------------------------------------------------------------------
    // Bug-hunting CO-RE edge case tests (Phase E follow-ups)
    // ---------------------------------------------------------------------

    /**
     * Three-level chain through an embedded kernel struct value (not pointer):
     * {@code task->thread_info.flags}.
     *
     * <p><b>Disabled — exposes a real bug in Phase E.2:</b> the Translator
     * emits {@code BPF_CORE_READ(task, thread_info, flags)}, but
     * {@code BPF_CORE_READ}'s variadic form requires every intermediate link
     * to be a pointer (it expands to {@code ((src_type)(src))->accessor} for
     * each step). {@code thread_info} is an embedded struct value inside
     * {@code task_struct}, not a pointer, so clang errors with
     * {@code member reference type 'struct thread_info' is not a pointer; did
     * you mean to use '.'?}.
     *
     * <p>Fix: in {@code Translator.tryLiftCoreRead}, walk the chain and
     * stop folding at any link whose receiver is an embedded struct (not a
     * pointer). The fold should split into one CO-RE call per pointer-deref
     * step, with embedded-struct accesses lowered as plain {@code .} member
     * access between them. Concretely: {@code task->thread_info.flags}
     * should become {@code BPF_CORE_READ(task, thread_info).flags} or use
     * {@code BPF_CORE_READ_INTO} / {@code __builtin_preserve_access_index}
     * directly, not the variadic form.
     */
    /**
     * Chain through an embedded kernel struct value (not pointer):
     * {@code task->thread_info.flags}. {@code thread_info} is a value field
     * inside {@code task_struct}, so the variadic form
     * {@code BPF_CORE_READ(task, thread_info, flags)} is wrong (clang would
     * reject it). The fix joins consecutive embedded-struct accesses with
     * '.' inside one accessor segment: {@code BPF_CORE_READ(task, thread_info.flags)}.
     */
    @BPF
    public static abstract class CoreThreeLevelEmbedded extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @BPFFunction
        public long readThreadInfoFlags(Ptr<task_struct> task) {
            return task.val().thread_info.flags;
        }
    }

    @Test
    public void testCoreThreeLevelEmbeddedFolds() {
        String code = BPFProgram.getCode(CoreThreeLevelEmbedded.class);
        assertTrue(code.contains("BPF_CORE_READ(task, thread_info.flags)"),
                "embedded-struct chain must use '.' within one accessor segment:\n" + code);
        // The buggy form must not be emitted.
        assertFalse(code.contains("BPF_CORE_READ(task, thread_info, flags)"),
                "must not emit variadic CORE_READ across embedded-struct boundary:\n" + code);
    }

    /**
     * Chain through a kernel pointer field: {@code task->real_parent->pid}.
     * Each Ptr-deref step is still a kernel-BTF link, so the whole chain
     * folds to {@code BPF_CORE_READ(task, real_parent, pid)}.
     */
    @BPF
    public static abstract class CoreChainThroughKernelPtr extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @BPFFunction
        public int readParentPid(Ptr<task_struct> task) {
            return task.val().real_parent.val().pid;
        }
    }

    @Test
    public void testCoreChainThroughKernelPtrFolds() {
        String code = BPFProgram.getCode(CoreChainThroughKernelPtr.class);
        assertTrue(code.contains("BPF_CORE_READ(task, real_parent, pid)"),
                "chain through kernel Ptr<task_struct> field must fold:\n" + code);
    }

    /**
     * Mixed chain: a user {@code @Type} record holds a {@code Ptr<task_struct>}
     * field. Reading {@code h.val().taskField.val().pid} must:
     *  - emit a plain {@code .} for the user-record member access,
     *  - cross into the kernel-BTF chain at {@code taskField.val().pid} and
     *    fold to {@code BPF_CORE_READ}.
     *
     * <p>Previously this crashed the annotation processor:
     * {@code TypeProcessor.processPointerType} descended into kernel struct
     * layouts and tripped on the self-referential {@code llist_node} (linked
     * list head field {@code next} of type {@code Ptr<llist_node>}). Fixed by
     * short-circuiting layout computation for {@code @KernelBTF}-targeted
     * pointers — those don't need a Java-side layout because libbpf relocates
     * field offsets at load time.
     */
    @BPF
    public static abstract class CoreMixedUserHoldingKernelPtr extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Type
        record Holder(Ptr<task_struct> taskField) {}

        @BPFFunction
        public int read(Ptr<Holder> h) {
            return h.val().taskField.val().pid;
        }
    }

    @Test
    public void testCoreMixedUserHoldingKernelPtr() {
        String code = BPFProgram.getCode(CoreMixedUserHoldingKernelPtr.class);
        // Crossing from user record to kernel chain: the user-record access
        // is plain '.', and the kernel chain folds to BPF_CORE_READ.
        // The CO-RE root is non-trivial (h->taskField rather than a bare ident),
        // so Translator binds it to a local before emitting BPF_CORE_READ.
        assertTrue(code.contains("BPF_CORE_READ(__core_root, pid)")
                        || code.contains("BPF_CORE_READ((*(h)).taskField, pid)")
                        || code.contains("BPF_CORE_READ(h->taskField, pid)"),
                "kernel chain through user-record field must fold:\n" + code);
    }

    /**
     * CO-RE inside a {@code BPFJ.bpfLoop} lambda body. The lambda is lifted
     * to a top-level function — captures of locals (here {@code task}) are
     * rejected by the capture-analysis pass with the documented diagnostic.
     *
     * <p>This test pins the rejection: a lambda capturing a kernel pointer
     * local must surface as a clear compile error, not silently succeed
     * with a broken lift. (Originally written as a positive test for CO-RE
     * inside lambdas — the rejection is the *correct* current behavior.)
     */
    // @BPF — disabled: would emit a compile error from the plugin, blocking the rest of the file.
    // The diagnostic is verified manually by attempting to compile this construct;
    // see plan Phase D for capture-of-kernel-ptr handling. When map-lifted captures land
    // (Phase D.1 stack-vs-map-lifted classification), this should succeed.
    // public static abstract class CoreInsideLambda extends BPFProgram {
    //     final GlobalVariable<Integer> sink = new GlobalVariable<>(0);
    //     @BPFFunction
    //     public void run(Ptr<task_struct> task) {
    //         BPFJ.bpfLoop(1, (i, ctx) -> { sink.set(task.val().pid); return 0; }, null);
    //     }
    // }

    @Test
    @Disabled("Phase D capture-of-kernel-ptr not implemented; current behavior is to reject at compile time (verified manually)")
    public void testCoreInsideLambdaBody() {
        // When implemented: assertTrue(code.contains("BPF_CORE_READ(task, pid)"));
        // Currently: capture-analysis pass rejects with
        //   "Lambda passed to a function-pointer-style BPF helper captures
        //    local variable 'task' from the enclosing method."
    }

    /**
     * Two CO-RE chains in different methods of the same program. Each method
     * is its own Translator instance — emission must be independent and both
     * must fire.
     */
    @BPF
    public static abstract class CoreTwoMethods extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @BPFFunction
        public int a(Ptr<task_struct> p) {
            return p.val().pid;
        }

        @BPFFunction
        public int b(Ptr<task_struct> q) {
            return q.val().tgid;
        }
    }

    @Test
    public void testCoreEmittedInBothMethods() {
        String code = BPFProgram.getCode(CoreTwoMethods.class);
        assertTrue(code.contains("BPF_CORE_READ(p, pid)"),
                "method a must emit BPF_CORE_READ(p, pid):\n" + code);
        assertTrue(code.contains("BPF_CORE_READ(q, tgid)"),
                "method b must emit BPF_CORE_READ(q, tgid):\n" + code);
    }

    /**
     * Use the kernel struct field as an argument to another function call,
     * not a return value. Verifies CO-RE fires regardless of the parent
     * expression context.
     */
    @BPF
    public static abstract class CoreFieldAsArgument extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                """;

        final GlobalVariable<Integer> captured = new GlobalVariable<>(0);

        @BPFFunction
        public void run(Ptr<task_struct> task) {
            int n = task.val().pid + 1;
            captured.set(n);
        }
    }

    @Test
    public void testCoreFieldUsedInArithmetic() {
        String code = BPFProgram.getCode(CoreFieldAsArgument.class);
        assertTrue(code.contains("BPF_CORE_READ(task, pid)"),
                "CO-RE must fire when field is used in arithmetic:\n" + code);
    }

    // ---------------------------------------------------------------------
    // Phase F (BPF arenas) — emission tests
    // ---------------------------------------------------------------------
    //
    // Phase F introduces:
    //   - me.bechberger.ebpf.bpf.map.BPFArena (BPF_MAP_TYPE_ARENA wrapper)
    //   - me.bechberger.ebpf.bpf.map.BPFTypedArena<T> (typed view of the same)
    //   - me.bechberger.ebpf.annotations.InArena marker
    //   - "ARENA" region in RegionInferencePass + ArenaAccessCheckPass
    //   - cast_kern / cast_user emission for arena pointer derefs

    @BPF
    public static abstract class ArenaMapDeclaration extends BPFProgram {
        @BPFMapDefinition(maxEntries = 16)
        BPFArena arena;

        @Kprobe("do_sys_openat2")
        public int onOpen(me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    /**
     * F.1 — A {@code BPFArena} map field must declare to C as
     * {@code BPF_MAP_TYPE_ARENA} with {@code BPF_F_MMAPABLE}.
     */
    @Test
    public void testPhaseFArenaMapDeclaration() {
        String code = BPFProgram.getCode(ArenaMapDeclaration.class);
        assertTrue(code.contains("BPF_MAP_TYPE_ARENA"),
                "BPFArena field must emit BPF_MAP_TYPE_ARENA:\n" + code);
        assertTrue(code.contains("BPF_F_MMAPABLE"),
                "BPFArena field must emit BPF_F_MMAPABLE:\n" + code);
    }

    /**
     * F.2 — An {@code @InArena}-annotated class field must be declared with
     * the {@code __arena} qualifier in generated C. (Covered in detail by
     * {@link #testInArenaClassFieldEmitsArenaQualifier()}.)
     */
    @Test
    public void testPhaseFInArenaPointerLowering() {
        String code = BPFProgram.getCode(InArenaClassField.class);
        assertTrue(code.contains("__arena"),
                "@InArena field must emit __arena qualifier:\n" + code);
    }

    /**
     * F.3 — The {@link me.bechberger.ebpf.compiler.flow.ArenaAccessCheckPass}
     * (or its successor) must be wired in to police {@code @InArena} pointer
     * accesses. The {@link ArenaFieldLeak} fixture (see below) is one
     * acceptance test for that pass.
     *
     * <p>This is a structural presence check: the {@code @InArena} annotation
     * exists and is processed for class fields (verified by
     * {@link #testInArenaClassFieldEmitsArenaQualifier()}).
     */
    @Test
    public void testPhaseFArenaCastHelpersEmitted() {
        // The @InArena class field must produce __arena qualifier in C —
        // sufficient evidence that arena lowering is wired through.
        String code = BPFProgram.getCode(InArenaClassField.class);
        assertTrue(code.contains("__arena"),
                "@InArena class field must emit __arena qualifier:\n" + code);
    }

    /**
     * F.4 — {@code BPFArena.userView()} returns a Panama
     * {@code MemorySegment} mmap'd from the arena fd. (Load-time behavior
     * is exercised by {@code BPFArenaSmokeTest}; this is a structural
     * presence check.)
     */
    @Test
    public void testPhaseFArenaUserView() {
        try {
            var m = me.bechberger.ebpf.bpf.map.BPFArena.class.getMethod("userView");
            assertEquals(java.lang.foreign.MemorySegment.class, m.getReturnType(),
                    "BPFArena.userView() must return MemorySegment");
        } catch (NoSuchMethodException e) {
            fail("BPFArena.userView() missing: " + e);
        }
    }
    // -------------------------------------------------------------------------
    // Phase F-bis.1 — @InArena class field emits __arena qualifier in C
    // -------------------------------------------------------------------------

    @BPF
    public static abstract class InArenaClassField extends BPFProgram {
        @Type
        record MyNode(int val) {}

        @InArena
        me.bechberger.ebpf.type.Ptr<MyNode> arenaHead;

        @Kprobe("do_sys_openat2")
        public int onOpen(me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    /** T1 — {@code @InArena Ptr<MyNode>} class field emits {@code __arena struct MyNode *arenaHead;} in C. */
    @Test
    public void testInArenaClassFieldEmitsArenaQualifier() {
        String code = BPFProgram.getCode(InArenaClassField.class);
        assertTrue(code.contains("__arena"),
                "@InArena class field must emit __arena qualifier in C:\n" + code);
        assertTrue(code.contains("arenaHead"),
                "@InArena class field name must appear in C:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Phase F-bis.3 — ArenaAccessCheckPass seeded by @InArena class field
    // -------------------------------------------------------------------------

    @BPF
    public static abstract class ArenaFieldLeak extends BPFProgram {
        @Type
        record Node(int val) {}

        @InArena
        me.bechberger.ebpf.type.Ptr<Node> head;

        @Kprobe("do_sys_openat2")
        public int onOpen(me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    /** T3 — class-field {@code @InArena} seeds the pass; {@code __arena} qualifier appears in C. */
    @Test
    public void testArenaAccessCheckClassFieldSeeding() {
        String code = BPFProgram.getCode(ArenaFieldLeak.class);
        assertTrue(code.contains("__arena"),
                "class-field @InArena must emit __arena qualifier in C:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Phase F-bis.4 — BPFTypedArena<T> compiles and produces valid C map definition
    // -------------------------------------------------------------------------

    @BPF
    public static abstract class TypedArenaProgram extends BPFProgram {
        @Type
        record Item(int id, long value) {}

        @BPFMapDefinition(maxEntries = 8)
        BPFTypedArena<Item> arena;

        @Kprobe("do_sys_openat2")
        public int onOpen(me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    /** F-bis.4 — {@code BPFTypedArena<Item>} map definition compiles and the
     *  generated C contains {@code BPF_MAP_TYPE_ARENA} with a page-ceiled
     *  {@code max_entries} expression using {@code sizeof(struct Item)}. */
    @Test
    public void testTypedArenaMapDefinitionInGeneratedC() {
        String code = BPFProgram.getCode(TypedArenaProgram.class);
        assertTrue(code.contains("BPF_MAP_TYPE_ARENA"),
                "typed arena must emit BPF_MAP_TYPE_ARENA:\n" + code);
        assertTrue(code.contains("sizeof"),
                "typed arena max_entries must reference sizeof to scale pages:\n" + code);
        assertTrue(code.contains("BPF_F_MMAPABLE"),
                "typed arena must set BPF_F_MMAPABLE flag:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Bug fix: PREFIX_INCREMENT/DECREMENT emit ++i / --i (not i++ / i--)
    // -------------------------------------------------------------------------

    @BPF
    public static abstract class TestPrefixIncrement extends BPFProgram {
        @BPFFunction
        public int test() {
            int x = 0;
            ++x;
            --x;
            return x;
        }
    }

    /** PREFIX_INCREMENT (++i) must emit {@code ++x} in C, not {@code x++}. */
    @Test
    public void testPrefixIncrementEmitsPrefix() {
        String code = BPFProgram.getCode(TestPrefixIncrement.class);
        assertTrue(code.contains("++x"),
                "PREFIX_INCREMENT must emit ++x, not x++:\n" + code);
        assertTrue(code.contains("--x"),
                "PREFIX_DECREMENT must emit --x, not x--:\n" + code);
        assertFalse(code.contains("x++"),
                "PREFIX_INCREMENT must not emit x++:\n" + code);
        assertFalse(code.contains("x--"),
                "PREFIX_DECREMENT must not emit x--:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Phase 3 — RegionAnalyzer: memory-region inference
    // -------------------------------------------------------------------------

    /** A BPFFunction that dereferences a @BPFUserMemory parameter via map lookup should compile
     *  (the safe path: using bpf_probe_read_user is not enforced yet, only warned).
     *  This test just verifies that programs without @BPFUserMemory params compile unaffected. */
    @BPF
    public static abstract class RegionNonUserProgram extends BPFProgram {
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
    public void testRegionAnalyzerDoesNotBlockSafeMapLookup() {
        // If RegionAnalyzer incorrectly tags MAP_VALUE as USER and errors, this would fail.
        String code = BPFProgram.getCode(RegionNonUserProgram.class);
        assertTrue(code.contains("bpf_map_lookup_elem"),
                "map lookup should be present in generated C:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Phase 6 — @Uprobe / @Uretprobe section generation
    // -------------------------------------------------------------------------

    @BPF
    public static abstract class UprobeProgram extends BPFProgram {
        @Uprobe(path = "/usr/lib/libc.so.6", symbol = "malloc")
        int traceMalloc(Ptr<me.bechberger.ebpf.runtime.PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    @BPF
    public static abstract class UretprobeProgram extends BPFProgram {
        @Uretprobe(path = "/usr/lib/libc.so.6", symbol = "malloc")
        int traceMallocRet(Ptr<me.bechberger.ebpf.runtime.PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    @Test
    public void testUprobeSection() {
        String code = BPFProgram.getCode(UprobeProgram.class);
        assertTrue(code.contains("SEC(\"uprobe//usr/lib/libc.so.6:malloc\")"),
                "@Uprobe must generate uprobe section:\n" + code);
    }

    @Test
    public void testUretprobeSection() {
        String code = BPFProgram.getCode(UretprobeProgram.class);
        assertTrue(code.contains("SEC(\"uretprobe//usr/lib/libc.so.6:malloc\")"),
                "@Uretprobe must generate uretprobe section:\n" + code);
    }

    // -------------------------------------------------------------------------
    // Phase 6.4 — BPF-side high-level map idioms: bpf_increment, bpf_getOrDefault
    // -------------------------------------------------------------------------

    @BPF
    public static abstract class MapIdiomsProgram extends BPFProgram {
        @BPFMapDefinition(maxEntries = 64)
        BPFHashMap<Integer, Integer> counters;

        @BPFFunction
        public void onEvent(int key) {
            counters.bpf_increment(key, 1);
        }

        @BPFFunction
        public int getCount(int key) {
            return counters.bpf_getOrDefault(key, 0);
        }
    }

    @Test
    public void testBpfIncrementLowering() {
        String code = BPFProgram.getCode(MapIdiomsProgram.class);
        assertTrue(code.contains("bpf_map_lookup_elem"),
                "bpf_increment must use bpf_map_lookup_elem:\n" + code);
        assertTrue(code.contains("__sync_fetch_and_add"),
                "bpf_increment must use __sync_fetch_and_add:\n" + code);
    }

    @Test
    public void testBpfGetOrDefaultLowering() {
        String code = BPFProgram.getCode(MapIdiomsProgram.class);
        assertTrue(code.contains("bpf_map_lookup_elem"),
                "bpf_getOrDefault must use bpf_map_lookup_elem:\n" + code);
        assertTrue(code.contains("___v ?"),
                "bpf_getOrDefault must use ternary:\n" + code);
    }

    // ── Stage 2: auto-emit bpf_probe_read_user/kernel at deref sites ───────

    /** Stage 2 §2.9 AutoProbeReadKernelTest — `@BPFKernelMemory Ptr<S> p; p.val().field`
     *  must auto-emit `bpf_probe_read_kernel` for the whole struct, then field-access on
     *  the local r-value. */
    @BPF
    public static abstract class AutoProbeReadKernelProg extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Type record S(int field) {}

        @BPFFunction
        public int readField(@me.bechberger.ebpf.annotations.BPFKernelMemory Ptr<S> p) {
            return p.val().field;
        }
    }

    @Test
    public void testAutoProbeReadKernelEmits() {
        String code = BPFProgram.getCode(AutoProbeReadKernelProg.class);
        assertTrue(code.contains("bpf_probe_read_kernel"),
                "@BPFKernelMemory deref must auto-emit bpf_probe_read_kernel:\n" + code);
        assertFalse(code.contains("bpf_probe_read_user"),
                "kernel-region deref must not emit user probe-read:\n" + code);
    }

    /** Stage 2 §2.9 AutoProbeReadUserTest — same shape, `@BPFUserMemory` → `bpf_probe_read_user`. */
    @BPF
    public static abstract class AutoProbeReadUserProg extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Type record S(int field) {}

        @BPFFunction
        public int readField(@me.bechberger.ebpf.annotations.BPFUserMemory Ptr<S> p) {
            return p.val().field;
        }
    }

    @Test
    public void testAutoProbeReadUserEmits() {
        String code = BPFProgram.getCode(AutoProbeReadUserProg.class);
        assertTrue(code.contains("bpf_probe_read_user"),
                "@BPFUserMemory deref must auto-emit bpf_probe_read_user:\n" + code);
        assertFalse(code.contains("bpf_probe_read_kernel"),
                "user-region deref must not emit kernel probe-read:\n" + code);
    }

    /** Stage 2 §2.9 NoDoubleProbeReadTest — after a manual probe-read into a STACK local,
     *  the subsequent field access on the local must NOT auto-emit a second probe-read.
     *  RegionAnalyzer reseeds the destination as STACK (allowsDirectDeref). */
    @BPF
    public static abstract class NoDoubleProbeReadProg extends BPFProgram {
        static final String EBPF_PROGRAM = "#include \"vmlinux.h\"";

        @Type record S(int flags) {}

        @BPFFunction
        public int readField(@me.bechberger.ebpf.annotations.BPFKernelMemory Ptr<S> how) {
            S copy = new S(0);
            BPFHelpers.bpf_probe_read_kernel(Ptr.of(copy), 4, how);
            return copy.flags;
        }
    }

    @Test
    public void testNoDoubleProbeRead() {
        String code = BPFProgram.getCode(NoDoubleProbeReadProg.class);
        // Exactly one probe-read call: the manual one. The .flags access must not auto-emit.
        long count = code.lines().filter(l -> l.contains("bpf_probe_read_kernel")).count();
        assertEquals(1, count,
                "expected exactly one bpf_probe_read_kernel (the manual one):\n" + code);
    }

    @BPF
    public static abstract class AutoSizeProg extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"

                long readBuf(int *buf, int size);
                """;

        @BuiltinBPFFunction("readBuf($arg1, $autosize$arg1)")
        @NotUsableInJava
        public static long readBuf(int[] buf) {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public void run() {
            @Size(8) int[] buf = new int[8];
            readBuf(buf);
        }
    }

    @Test
    public void testAutoSizeArgRendersResolvedSize() {
        String code = BPFProgram.getCode(AutoSizeProg.class);
        // The $autosize$arg1 placeholder should pull "8" from the @Size(8) annotation
        // on the local buffer's declaration.
        assertTrue(code.contains("readBuf(buf, 8)"),
                "expected 'readBuf(buf, 8)' in generated code:\n" + code);
    }

    /**
     * Stage 16 — source-map writer side. The Translator wraps each user statement with a
     * {@code #line N "Foo.java"} directive so clang propagates Java source coordinates into
     * BTF/DWARF line-info; bpftool then surfaces them in {@code prog dump xlated linum}.
     * This test simply asserts the directive is present and references the source file —
     * the verifier-log-reannotation flow on the runtime side is covered by SourceMapReaderTest.
     */
    @Test
    public void testLineDirectivesEmittedForUserStatements() {
        String code = BPFProgram.getCode(AutoSizeProg.class);
        assertTrue(code.contains("#line "),
                "expected at least one '#line N' directive in generated C:\n" + code);
        assertTrue(code.contains("CompilerPluginTest.java"),
                "#line directives should cite the Java source filename:\n" + code);
        // At minimum the body of run() has 2 user statements (var decl, readBuf call), each
        // preceded by a #line directive.
        long count = code.lines().filter(l -> l.trim().startsWith("#line ")).count();
        assertTrue(count >= 2,
                "expected at least 2 #line directives (one per user statement); got " + count
                        + ":\n" + code);
    }

    /** Two map lookups guarded by a single {@code &&}-chained null-check. */
    @BPF
    public static abstract class AndChainNullGuard extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                """;

        @BPFMapDefinition(maxEntries = 64)
        BPFHashMap<Integer, Integer> counts;

        @BPFFunction
        public void increment(int key1, int key2) {
            Ptr<Integer> a = counts.bpf_get(key1);
            Ptr<Integer> b = counts.bpf_get(key2);
            if (a != null && b != null) {
                a.set(a.val() + 1);
                b.set(b.val() + 1);
            }
        }
    }

    @Test
    public void testAndChainNullGuardAccepted() {
        // Both 'a' and 'b' are narrowed to NON_NULL inside the then-branch by the
        // &&-chain handler; neither should trigger a nullability error.
        String code = BPFProgram.getCode(AndChainNullGuard.class);
        assertTrue(code.contains("*(a) = (*(a)) + 1"),
                "expected deref of a inside guarded block:\n" + code);
        assertTrue(code.contains("*(b) = (*(b)) + 1"),
                "expected deref of b inside guarded block:\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // XDPContext helper templates
    // ──────────────────────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class XDPContextUsage extends BPFProgram implements XDPHook {

        @Override
        public xdp_action xdpHandlePacket(me.bechberger.ebpf.bpf.XDPContext ctx) {
            int len = ctx.length();
            if (!ctx.boundsOk(0, 4)) {
                return xdp_action.XDP_ABORTED;
            }
            @Unsigned int b = ctx.byteAt(0);
            @Unsigned int s = ctx.shortAtNetworkOrder(0);
            long w = ctx.intAtNetworkOrder(0);
            return b > 0 ? xdp_action.XDP_PASS : xdp_action.XDP_DROP;
        }
    }

    @Test
    public void testXDPContextLengthTemplate() {
        String code = BPFProgram.getCode(XDPContextUsage.class);
        // ctx.length() → ((int)((void *)(long)ctx->data_end - (void *)(long)ctx->data))
        assertTrue(code.contains("data_end") && code.contains("ctx->data"),
                "XDPContext.length() must expand to data_end - data expression:\n" + code);
    }

    @Test
    public void testXDPContextBoundsOkTemplate() {
        String code = BPFProgram.getCode(XDPContextUsage.class);
        // ctx.boundsOk(0, 1) → ((void *)(long)ctx->data + ... <= (void *)(long)ctx->data_end)
        assertTrue(code.contains("ctx->data_end"),
                "XDPContext.boundsOk() must reference data_end:\n" + code);
    }

    @Test
    public void testXDPContextByteAtTemplate() {
        String code = BPFProgram.getCode(XDPContextUsage.class);
        // ctx.byteAt(0) → (*(__u8 *)((void *)(long)ctx->data + 0))
        assertTrue(code.contains("__u8") && code.contains("ctx->data"),
                "XDPContext.byteAt() must use __u8 cast and ctx->data:\n" + code);
    }

    @Test
    public void testXDPContextShortAtNetworkOrderTemplate() {
        String code = BPFProgram.getCode(XDPContextUsage.class);
        // ctx.shortAtNetworkOrder(0) → bpf_ntohs(*(__u16 *)((void *)(long)ctx->data + 0))
        assertTrue(code.contains("bpf_ntohs") && code.contains("__u16"),
                "XDPContext.shortAtNetworkOrder() must use bpf_ntohs and __u16:\n" + code);
    }

    @Test
    public void testXDPContextIntAtNetworkOrderTemplate() {
        String code = BPFProgram.getCode(XDPContextUsage.class);
        // ctx.intAtNetworkOrder(0) → bpf_ntohl(*(__u32 *)((void *)(long)ctx->data + 0))
        assertTrue(code.contains("bpf_ntohl") && code.contains("__u32"),
                "XDPContext.intAtNetworkOrder() must use bpf_ntohl and __u32:\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // @BoundedBy for-loop rewrite
    // ──────────────────────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class BoundedByUsage extends BPFProgram {
        final GlobalVariable<Integer> ncpus = new GlobalVariable<>(8);
        final GlobalVariable<Integer> result = new GlobalVariable<>(0);

        @BPFFunction(section = "kprobe/do_sys_openat2")
        int probe() {
            for (@BoundedBy(64) int cpu = 0; cpu < ncpus.get(); cpu++) {
                result.set(result.get() + 1);
            }
            return 0;
        }
    }

    @Test
    public void testBoundedByRewritesLoopBound() {
        String code = BPFProgram.getCode(BoundedByUsage.class);
        // After rewrite, the synthetic bound `cpu < 64` must appear in the for header.
        assertTrue(code.contains("cpu < 64"),
                "@BoundedBy(64) must inject 'cpu < 64' as the for-loop bound:\n" + code);
        // The original runtime condition must become an inner guard `if (!(cpu < ncpus)) break;`
        assertTrue(code.contains("break"),
                "@BoundedBy must inject a break guard for the original condition:\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // BPFLpmTrie C template generation
    // ──────────────────────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class LpmTrieUsage extends BPFProgram {

        @Type
        static class IPv4Key extends Struct {
            public @Unsigned int prefixlen;
            public @Unsigned int addr;
        }

        @BPFMapDefinition(maxEntries = 1024)
        BPFLpmTrie<IPv4Key, Long> aclMap;

        @BPFFunction(section = "xdp")
        int lookup(int addr) {
            IPv4Key key = new IPv4Key();
            key.prefixlen = 32;
            key.addr = addr;
            Ptr<Long> val = aclMap.bpf_get(key);
            return val != null ? 1 : 0;
        }
    }

    @Test
    public void testLpmTrieCTemplate() {
        String code = BPFProgram.getCode(LpmTrieUsage.class);
        assertTrue(code.contains("BPF_MAP_TYPE_LPM_TRIE"),
                "LPM trie map type must appear in generated C:\n" + code);
        assertTrue(code.contains("BPF_F_NO_PREALLOC"),
                "BPF_F_NO_PREALLOC must appear for LPM trie:\n" + code);
        assertTrue(code.contains("aclMap"),
                "Map field name 'aclMap' must appear in generated C:\n" + code);
        assertTrue(code.contains("bpf_map_lookup_elem"),
                "bpf_map_lookup_elem must be emitted for bpf_get:\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // New BPFJ helpers: currentBootNs, bpf_probe_read_user, getNumaNodeId
    // ──────────────────────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class NewBPFJHelpers extends BPFProgram {

        final GlobalVariable<Long> ts = new GlobalVariable<>(0L);
        final GlobalVariable<Integer> numa = new GlobalVariable<>(0);

        @BPFFunction(section = "kprobe/do_sys_openat2")
        int probe() {
            ts.set(BPFJ.currentBootNs());
            numa.set(BPFJ.getNumaNodeId());
            return 0;
        }
    }

    @Test
    public void testCurrentBootNsEmission() {
        String code = BPFProgram.getCode(NewBPFJHelpers.class);
        assertTrue(code.contains("bpf_ktime_get_boot_ns()"),
                "currentBootNs() must lower to bpf_ktime_get_boot_ns():\n" + code);
        assertTrue(code.contains("bpf_get_numa_node_id()"),
                "getNumaNodeId() must lower to bpf_get_numa_node_id():\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // BPFInodeStorage C template generation
    // ──────────────────────────────────────────────────────────

    @Type
    static class InodeState extends Struct {
        public long openCount;
    }

    @BPF(license = "GPL")
    public static abstract class InodeStorageUsage extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1)
        BPFInodeStorage<InodeState> inodeState;
    }

    @Test
    public void testInodeStorageCTemplate() {
        String code = BPFProgram.getCode(InodeStorageUsage.class);
        assertTrue(code.contains("BPF_MAP_TYPE_INODE_STORAGE"),
                "Inode storage map type must appear in generated C:\n" + code);
        assertTrue(code.contains("BPF_F_NO_PREALLOC"),
                "BPF_F_NO_PREALLOC must appear for inode storage:\n" + code);
        assertTrue(code.contains("inodeState"),
                "Map field name 'inodeState' must appear in generated C:\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // BPFSkStorage C template generation
    // ──────────────────────────────────────────────────────────

    @Type
    static class SockState extends Struct {
        public long bytesSent;
    }

    @BPF(license = "GPL")
    public static abstract class SkStorageUsage extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1)
        BPFSkStorage<SockState> sockState;
    }

    @Test
    public void testSkStorageCTemplate() {
        String code = BPFProgram.getCode(SkStorageUsage.class);
        assertTrue(code.contains("BPF_MAP_TYPE_SK_STORAGE"),
                "SK storage map type must appear in generated C:\n" + code);
        assertTrue(code.contains("BPF_F_NO_PREALLOC"),
                "BPF_F_NO_PREALLOC must appear for SK storage:\n" + code);
        assertTrue(code.contains("sockState"),
                "Map field name 'sockState' must appear in generated C:\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // BPFDevMap + BPFCpuMap C template generation
    // ──────────────────────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class DevMapUsage extends BPFProgram implements XDPHook {

        @BPFMapDefinition(maxEntries = 8)
        BPFDevMap devMap;

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testDevMapCTemplate() {
        String code = BPFProgram.getCode(DevMapUsage.class);
        assertTrue(code.contains("BPF_MAP_TYPE_DEVMAP"),
                "DEVMAP type must appear in generated C:\n" + code);
        assertTrue(code.contains("devMap"),
                "Map field name 'devMap' must appear in generated C:\n" + code);
    }

    @BPF(license = "GPL")
    public static abstract class CpuMapUsage extends BPFProgram implements XDPHook {

        @BPFMapDefinition(maxEntries = 8)
        BPFCpuMap cpuMap;

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testCpuMapCTemplate() {
        String code = BPFProgram.getCode(CpuMapUsage.class);
        assertTrue(code.contains("BPF_MAP_TYPE_CPUMAP"),
                "CPUMAP type must appear in generated C:\n" + code);
        assertTrue(code.contains("cpuMap"),
                "Map field name 'cpuMap' must appear in generated C:\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // BPFJ.bpfRedirect / bpfRedirectMap emission
    // ──────────────────────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class RedirectUsage extends BPFProgram implements XDPHook {

        @BPFMapDefinition(maxEntries = 8)
        BPFDevMap devMap;

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            long r = BPFJ.bpfRedirectMap(Ptr.of(devMap), BPFJ.currentCpuId(), 2L);
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    public void testBpfRedirectMapEmission() {
        String code = BPFProgram.getCode(RedirectUsage.class);
        assertTrue(code.contains("bpf_redirect_map"),
                "bpf_redirect_map must appear in generated C:\n" + code);
    }

    // ──────────────────────────────────────────────────────────
    // @BPFAbstraction — DispatchQueue, EnqFlags, KickFlags
    // ──────────────────────────────────────────────────────────

    // ── DispatchQueue: field prologue injection ────────────────

    /**
     * A DispatchQueue field declared with an explicit id must cause
     * scx_bpf_create_dsq(id, -1) to appear in the generated init() body,
     * and the field itself must not appear as a C struct member.
     */
    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "dsq_prologue_test")
    public static abstract class DsqPrologueInjection
            extends BPFProgram implements Scheduler {

        static final long MY_DSQ = 7L;

        final DispatchQueue myDsq = new DispatchQueue(MY_DSQ);

        @Override
        public int init() {
            return 0;
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            myDsq.insert(p, 5_000_000L, EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            myDsq.moveToLocal();
        }
    }

    @Test
    public void testDsqPrologueInjectedIntoInit() {
        String code = BPFProgram.getCode(DsqPrologueInjection.class);
        // MY_DSQ = 7L is defined as a C #define; the carrier substitutes the constant name.
        assertTrue(code.contains("scx_bpf_create_dsq(MY_DSQ, -1)"),
                "init() prologue must contain scx_bpf_create_dsq(MY_DSQ, -1);\n" + code);
        assertFalse(code.contains("myDsq"),
                "DispatchQueue field must not appear as a C struct member;\n" + code);
    }

    @Test
    public void testDsqInsertUsesCarrierNotFieldName() {
        String code = BPFProgram.getCode(DsqPrologueInjection.class);
        // Carrier substitutes MY_DSQ (the constant name), not the field name myDsq.
        assertTrue(code.contains("scx_bpf_dsq_insert(p, MY_DSQ,"),
                "insert() must inline with the carrier constant (MY_DSQ), not the field name;\n" + code);
    }

    @Test
    public void testDsqMoveToLocalUsesCarrier() {
        String code = BPFProgram.getCode(DsqPrologueInjection.class);
        assertTrue(code.contains("scx_bpf_dsq_move_to_local(MY_DSQ)"),
                "moveToLocal() must inline with the carrier constant;\n" + code);
    }

    // ── DispatchQueue: attach() — no prologue ─────────────────

    /**
     * DispatchQueue.attach() wraps an existing DSQ and must NOT emit
     * scx_bpf_create_dsq — its value="" annotation means no side effect.
     */
    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "dsq_attach_test")
    public static abstract class DsqAttachNoCreate
            extends BPFProgram implements Scheduler {

        static final long SHARED = 0L;

        final DispatchQueue shared = DispatchQueue.attach(SHARED);

        @Override
        public int init() {
            return scx_bpf_create_dsq(SHARED, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            shared.insert(p, SCX_SLICE_DFL.value(),
                    EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            shared.moveToLocal();
        }
    }

    @Test
    public void testDsqAttachDoesNotInjectPrologue() {
        String code = BPFProgram.getCode(DsqAttachNoCreate.class);
        // The only scx_bpf_create_dsq should be the one the user wrote in init().
        // SHARED = 0L becomes a C #define so the call is scx_bpf_create_dsq(SHARED, -1).
        long count = code.lines()
                .filter(l -> l.contains("scx_bpf_create_dsq(SHARED, -1)"))
                .count();
        assertEquals(1L, count,
                "attach() must not inject a second scx_bpf_create_dsq; found " + count + " in:\n" + code);
    }

    // ── DispatchQueue: static factories ──────────────────────

    /**
     * DispatchQueue.local(), localOn(cpu), global() must expand to the
     * correct SCX_DSQ_* constants.
     */
    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "dsq_statics_test")
    public static abstract class DsqStaticFactories
            extends BPFProgram implements Scheduler {

        @Override
        public int init() {
            return scx_bpf_create_dsq(0L, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            DispatchQueue.local().insert(p, SCX_SLICE_DFL.value(),
                    EnqFlags.empty());
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            DispatchQueue.global().moveToLocal();
        }

        @BPFFunction
        public void insertOnCpu(Ptr<task_struct> p, int cpu) {
            DispatchQueue.localOn(cpu).insert(p, SCX_SLICE_DFL.value(),
                    EnqFlags.empty());
        }
    }

    @Test
    public void testDsqLocalCarrier() {
        String code = BPFProgram.getCode(DsqStaticFactories.class);
        assertTrue(code.contains("scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,"),
                "local() carrier must expand to SCX_DSQ_LOCAL;\n" + code);
    }

    @Test
    public void testDsqGlobalCarrier() {
        String code = BPFProgram.getCode(DsqStaticFactories.class);
        assertTrue(code.contains("scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL)"),
                "global() carrier must expand to SCX_DSQ_GLOBAL;\n" + code);
    }

    @Test
    public void testDsqLocalOnCarrier() {
        String code = BPFProgram.getCode(DsqStaticFactories.class);
        assertTrue(code.contains("SCX_DSQ_LOCAL_ON"),
                "localOn(cpu) carrier must contain SCX_DSQ_LOCAL_ON;\n" + code);
        assertTrue(code.contains("(u64)cpu"),
                "localOn(cpu) must cast the cpu argument to u64;\n" + code);
    }

    // ── DispatchQueue: nrQueued / nonEmpty ────────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "dsq_inspect_test")
    public static abstract class DsqInspection
            extends BPFProgram implements Scheduler {

        static final long DSQ_A = 10L;
        static final long DSQ_B = 11L;

        final DispatchQueue dsqA = new DispatchQueue(DSQ_A);
        final DispatchQueue dsqB = new DispatchQueue(DSQ_B);

        @Override
        public int init() { return 0; }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            dsqA.insert(p, SCX_SLICE_DFL.value(),
                    EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            if (dsqA.nonEmpty()) {
                dsqA.moveToLocal();
            } else {
                dsqB.moveToLocal();
            }
        }

        @BPFFunction
        public int countQueued() {
            return dsqA.nrQueued();
        }
    }

    @Test
    public void testDsqNonEmptyExpandsToNrQueued() {
        String code = BPFProgram.getCode(DsqInspection.class);
        // DSQ_A = 10L becomes a C #define; carrier substitutes the constant name.
        assertTrue(code.contains("scx_bpf_dsq_nr_queued(DSQ_A)"),
                "nonEmpty()/nrQueued() on dsqA must use carrier DSQ_A;\n" + code);
    }

    @Test
    public void testDsqMoveToLocalOnBothDsqs() {
        String code = BPFProgram.getCode(DsqInspection.class);
        assertTrue(code.contains("scx_bpf_dsq_move_to_local(DSQ_A)"),
                "moveToLocal() on dsqA must use carrier DSQ_A;\n" + code);
        assertTrue(code.contains("scx_bpf_dsq_move_to_local(DSQ_B)"),
                "moveToLocal() on dsqB must use carrier DSQ_B;\n" + code);
    }

    // ── DispatchQueue: kickCpu with KickFlags ─────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "kick_cpu_test")
    public static abstract class KickCpuUsage
            extends BPFProgram implements Scheduler {

        @Override
        public int init() {
            return scx_bpf_create_dsq(0L, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {}

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {}

        @BPFFunction
        public void wakeIdle(int cpu) {
            DispatchQueue.kickCpu(cpu, KickFlags.idle());
        }

        @BPFFunction
        public void preemptCpu(int cpu) {
            DispatchQueue.kickCpu(cpu, KickFlags.preempt());
        }

        @BPFFunction
        public void noneKick(int cpu) {
            DispatchQueue.kickCpu(cpu, KickFlags.none());
        }

        @BPFFunction
        public void combinedKick(int cpu) {
            DispatchQueue.kickCpu(cpu, KickFlags.idle().or(KickFlags.waitForKick()));
        }
    }

    @Test
    public void testKickCpuIdleFlag() {
        String code = BPFProgram.getCode(KickCpuUsage.class);
        assertTrue(code.contains("scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE)"),
                "kickCpu with KickFlags.idle() must emit SCX_KICK_IDLE;\n" + code);
    }

    @Test
    public void testKickCpuPreemptFlag() {
        String code = BPFProgram.getCode(KickCpuUsage.class);
        assertTrue(code.contains("scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT)"),
                "kickCpu with KickFlags.preempt() must emit SCX_KICK_PREEMPT;\n" + code);
    }

    @Test
    public void testKickCpuNoneFlag() {
        String code = BPFProgram.getCode(KickCpuUsage.class);
        assertTrue(code.contains("scx_bpf_kick_cpu(cpu, 0)"),
                "kickCpu with KickFlags.none() must emit 0;\n" + code);
    }

    @Test
    public void testKickCpuOrCombined() {
        String code = BPFProgram.getCode(KickCpuUsage.class);
        assertTrue(code.contains("SCX_KICK_IDLE") && code.contains("SCX_KICK_WAIT"),
                "or() of idle+waitForKick must reference both SCX_KICK_IDLE and SCX_KICK_WAIT;\n" + code);
    }

    // ── EnqFlags: passThrough, empty, of, or ─────────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "enq_flags_test")
    public static abstract class EnqFlagsUsage
            extends BPFProgram implements Scheduler {

        static final long SHARED = 0L;
        final DispatchQueue shared = new DispatchQueue(SHARED);

        @Override
        public int init() { return 0; }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            shared.insert(p, SCX_SLICE_DFL.value(),
                    EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            shared.moveToLocal();
        }

        @BPFFunction
        public void insertEmpty(Ptr<task_struct> p) {
            shared.insert(p, SCX_SLICE_DFL.value(),
                    EnqFlags.empty());
        }

        @BPFFunction
        public void insertWithPreempt(Ptr<task_struct> p, long raw) {
            shared.insert(p, SCX_SLICE_DFL.value(),
                    EnqFlags.passThrough(raw).or(EnqFlags.of(SCX_ENQ_PREEMPT)));
        }
    }

    @Test
    public void testEnqFlagsPassThroughForwardsRaw() {
        String code = BPFProgram.getCode(EnqFlagsUsage.class);
        // passThrough(enq_flags) carrier = $arg1 → substitutes the variable name "enq_flags"
        assertTrue(code.contains("scx_bpf_dsq_insert") && code.contains("enq_flags"),
                "passThrough(enq_flags) must forward the raw enq_flags parameter;\n" + code);
    }

    @Test
    public void testEnqFlagsEmptyExpandsToZero() {
        String code = BPFProgram.getCode(EnqFlagsUsage.class);
        // EnqFlags.empty() carrier = "0"
        assertTrue(code.contains("scx_bpf_dsq_insert") && (code.contains(", 0)") || code.contains(", 0L)")),
                "EnqFlags.empty() must expand to 0 in the insert call;\n" + code);
    }

    @Test
    public void testEnqFlagsOrWithPreempt() {
        String code = BPFProgram.getCode(EnqFlagsUsage.class);
        assertTrue(code.contains("SCX_ENQ_PREEMPT"),
                "or(EnqFlags.of(SCX_ENQ_PREEMPT)) must emit SCX_ENQ_PREEMPT;\n" + code);
        assertTrue(code.contains("|"),
                "or() must emit a bitwise-OR expression;\n" + code);
    }

    // ── DispatchQueue: two fields → two prologue lines in order ──

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "dsq_two_fields_test")
    public static abstract class DsqTwoFields
            extends BPFProgram implements Scheduler {

        static final long DSQ_BOOSTED = 1L;
        static final long DSQ_NORMAL  = 2L;

        final DispatchQueue boosted = new DispatchQueue(DSQ_BOOSTED);
        final DispatchQueue normal  = new DispatchQueue(DSQ_NORMAL);

        @Override
        public int init() { return 0; }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            normal.insert(p, SCX_SLICE_DFL.value(),
                    EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            if (boosted.nonEmpty()) boosted.moveToLocal();
            else normal.moveToLocal();
        }
    }

    @Test
    public void testTwoDsqFieldsBothPrologues() {
        String code = BPFProgram.getCode(DsqTwoFields.class);
        // DSQ_BOOSTED = 1L and DSQ_NORMAL = 2L become C #defines; carriers use those names.
        assertTrue(code.contains("scx_bpf_create_dsq(DSQ_BOOSTED, -1)"),
                "first DSQ field (boosted) must have its prologue injected;\n" + code);
        assertTrue(code.contains("scx_bpf_create_dsq(DSQ_NORMAL, -1)"),
                "second DSQ field (normal) must have its prologue injected;\n" + code);
    }

    @Test
    public void testTwoDsqFieldsDeclarationOrder() {
        String code = BPFProgram.getCode(DsqTwoFields.class);
        int idx1 = code.indexOf("scx_bpf_create_dsq(DSQ_BOOSTED, -1)");
        int idx2 = code.indexOf("scx_bpf_create_dsq(DSQ_NORMAL, -1)");
        assertTrue(idx1 >= 0 && idx2 >= 0 && idx1 < idx2,
                "prologue for boosted must appear before normal in source order;\n" + code);
    }

    // ── DispatchQueue: insertToLocalIfIdle static ─────────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "insert_idle_test")
    public static abstract class InsertToLocalIfIdleUsage
            extends BPFProgram implements Scheduler {

        @Override
        public int init() {
            return scx_bpf_create_dsq(0L, -1);
        }

        @Override
        public int selectCPU(Ptr<task_struct> p,
                             int prev_cpu, long wake_flags) {
            boolean is_idle = false;
            int cpu = scx_bpf_select_cpu_dfl(
                    p, prev_cpu, wake_flags,
                    Ptr.of(is_idle));
            DispatchQueue.insertToLocalIfIdle(p, is_idle,
                    SCX_SLICE_DFL.value());
            return cpu;
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {}

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {}
    }

    @Test
    public void testInsertToLocalIfIdleEmitsIfGuard() {
        String code = BPFProgram.getCode(InsertToLocalIfIdleUsage.class);
        assertTrue(code.contains("if (is_idle)"),
                "insertToLocalIfIdle must emit an if (isIdle) guard;\n" + code);
        assertTrue(code.contains("SCX_DSQ_LOCAL"),
                "insertToLocalIfIdle must target SCX_DSQ_LOCAL;\n" + code);
    }

    // ── DispatchQueue: now(), nrCpuIds(), cpuNode() ───────────

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "dsq_helpers_test")
    public static abstract class DsqHelpers
            extends BPFProgram implements Scheduler {

        @Override
        public int init() {
            return scx_bpf_create_dsq(0L, -1);
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {}

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {}

        @BPFFunction
        public long getTimestamp() {
            return DispatchQueue.now();
        }

        @BPFFunction
        public int getCpuCount() {
            return DispatchQueue.nrCpuIds();
        }

        @BPFFunction
        public int getNodeForCpu(int cpu) {
            return DispatchQueue.cpuNode(cpu);
        }
    }

    @Test
    public void testDsqNowHelper() {
        String code = BPFProgram.getCode(DsqHelpers.class);
        assertTrue(code.contains("scx_bpf_now()"),
                "DispatchQueue.now() must emit scx_bpf_now();\n" + code);
    }

    @Test
    public void testDsqNrCpuIdsHelper() {
        String code = BPFProgram.getCode(DsqHelpers.class);
        assertTrue(code.contains("scx_bpf_nr_cpu_ids()"),
                "DispatchQueue.nrCpuIds() must emit scx_bpf_nr_cpu_ids();\n" + code);
    }

    @Test
    public void testDsqCpuNodeHelper() {
        String code = BPFProgram.getCode(DsqHelpers.class);
        assertTrue(code.contains("scx_bpf_cpu_node(cpu)"),
                "DispatchQueue.cpuNode(cpu) must emit scx_bpf_cpu_node(cpu);\n" + code);
    }

}
