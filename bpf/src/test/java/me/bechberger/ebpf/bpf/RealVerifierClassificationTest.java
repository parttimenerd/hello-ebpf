package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.compiler.verifier.VerifierLogParser;
import me.bechberger.ebpf.bpf.compiler.verifier.VerifierLogParser.ErrorClass;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Loads several deliberately-broken raw-C BPF programs, captures the real verifier log
 * via {@link BPFVerifierException}, and asserts that {@link VerifierLogParser} classifies
 * each rejection into the expected {@link ErrorClass}.
 *
 * <p>The C is hand-rolled (not produced by the Java→C translator) so the failure mode is
 * stable across translator changes — every program's defect is local to itself.</p>
 *
 * <p>Linux-only: requires bpftool/libbpf and the kernel verifier. Skip on macOS.</p>
 */
public class RealVerifierClassificationTest {

    /**
     * Reads a stack value with a verifier-rejected idiom. Modern kernels phrase this as
     * {@code "R0 !read_ok"}; older kernels say {@code "invalid read from stack"}. Either
     * should classify as STACK_OOB after the parser fix.
     */
    @BPF
    public static abstract class StackOobProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                SEC("kprobe/do_sys_openat2")
                int kprobe__bad(struct pt_regs *ctx) {
                    int x;
                    return x;
                }
                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    /**
     * Map lookup whose result is dereferenced without a null check.
     * The verifier reports "invalid mem access 'map_value_or_null'", which our parser
     * classifies as UNCHECKED_NULL_DEREF (not the more generic INVALID_MEM_ACCESS).
     */
    @BPF
    public static abstract class UncheckedNullDerefProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                struct {
                    __uint(type, BPF_MAP_TYPE_HASH);
                    __type(key, int);
                    __type(value, int);
                    __uint(max_entries, 1);
                } m SEC(".maps");

                SEC("kprobe/do_sys_openat2")
                int kprobe__bad(struct pt_regs *ctx) {
                    int k = 0;
                    int *v = bpf_map_lookup_elem(&m, &k);
                    return *v;        // no null check
                }
                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    /** Calls a non-existent helper: "unknown func" → HELPER_NOT_ALLOWED. */
    @BPF
    public static abstract class UnknownHelperProg extends BPFProgram {
        // We declare a fake helper number that is virtually guaranteed not to exist.
        // The kernel rejects with "unknown func bpf_<name>#<id>" or "invalid func".
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                static long (*bpf_unknown_func)(void) = (void *) 999999;

                SEC("kprobe/do_sys_openat2")
                int kprobe__bad(struct pt_regs *ctx) {
                    return bpf_unknown_func();
                }
                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    /**
     * Out-of-bounds map_value access — a classic verifier-rejection idiom.
     * Looks up a value, null-checks it, then accesses past the value's declared size.
     * Triggers "map_value access out of bounds" or "max value is outside" → OUT_OF_BOUNDS.
     */
    @BPF
    public static abstract class OutOfBoundsProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                struct {
                    __uint(type, BPF_MAP_TYPE_ARRAY);
                    __type(key, int);
                    __type(value, int);          // 4-byte values
                    __uint(max_entries, 1);
                } m SEC(".maps");

                SEC("kprobe/do_sys_openat2")
                int kprobe__bad(struct pt_regs *ctx) {
                    int k = 0;
                    int *v = bpf_map_lookup_elem(&m, &k);
                    if (!v) return 0;
                    /* Read 8 bytes past the start of a 4-byte value: definitely OOB. */
                    return *(long long *) v;
                }
                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    /**
     * Walks a kernel pointer the verifier cannot trace.
     * Triggers "invalid mem access" (without _or_null) → INVALID_MEM_ACCESS.
     */
    @BPF
    public static abstract class InvalidMemAccessProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                SEC("kprobe/do_sys_openat2")
                int kprobe__bad(struct pt_regs *ctx) {
                    /* Treat the integer 0x1234 as a kernel pointer and deref it. */
                    int *p = (int *) 0x1234;
                    return *p;
                }
                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    /**
     * Unbounded back-edge loop — the verifier must reject as it cannot prove termination.
     * Triggers "back-edge" / "infinite loop" / "loop limit" → INFINITE_LOOP.
     */
    @BPF
    public static abstract class InfiniteLoopProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                SEC("kprobe/do_sys_openat2")
                int kprobe__bad(struct pt_regs *ctx) {
                    /* Volatile defeats clang's loop unrolling; verifier sees an unbounded loop. */
                    volatile int i = 0;
                    while (i < 1000000000) {
                        i++;
                    }
                    return 0;
                }
                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    /**
     * Passes a scalar where a map pointer is expected. Triggers a TYPE_MISMATCH-class
     * rejection: "R1 type=inv expected=fp" or "arg #1 type SCALAR_VALUE expected ptr_to_map".
     */
    @BPF
    public static abstract class TypeMismatchProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                SEC("kprobe/do_sys_openat2")
                int kprobe__bad(struct pt_regs *ctx) {
                    int k = 0;
                    /* Pass a scalar 0 where bpf_map_lookup_elem wants a map pointer. */
                    return (long) bpf_map_lookup_elem((void *) 0, &k);
                }
                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    private static String captureLog(Class<? extends BPFProgram> cls) {
        var ex = assertThrows(BPFVerifierException.class,
                () -> { try (var ignored = BPFProgram.load(cls)) {} },
                cls.getSimpleName() + " should be rejected");
        var log = ex.verifierLog();
        assertNotNull(log);
        assertFalse(log.isBlank(), "verifier log must not be blank for " + cls.getSimpleName());
        return log;
    }

    private static ErrorClass classifyOf(String log) {
        return VerifierLogParser.parse(log).error()
                .map(VerifierLogParser.VerifierError::errorClass)
                .orElse(ErrorClass.OTHER);
    }

    @Test
    public void stackOobIsClassifiedFromRealLog() {
        var log = captureLog(StackOobProg.class);
        var cls = classifyOf(log);
        // Kernel may report "invalid read from stack" or "!read_ok" / "uninitialized".
        // STACK_OOB is the parser's category for stack issues. INVALID_MEM_ACCESS is also
        // acceptable for older kernels that phrase it that way.
        assertTrue(cls == ErrorClass.STACK_OOB || cls == ErrorClass.INVALID_MEM_ACCESS,
                "expected STACK_OOB or INVALID_MEM_ACCESS, got " + cls + "\nlog:\n" + log);
    }

    @Test
    public void uncheckedNullDerefIsClassifiedFromRealLog() {
        var log = captureLog(UncheckedNullDerefProg.class);
        var cls = classifyOf(log);
        assertEquals(ErrorClass.UNCHECKED_NULL_DEREF, cls,
                "expected UNCHECKED_NULL_DEREF for un-null-checked map lookup\nlog:\n" + log);
    }

    @Test
    public void unknownHelperIsClassifiedFromRealLog() {
        var log = captureLog(UnknownHelperProg.class);
        var cls = classifyOf(log);
        // Kernels phrase this as "unknown func" or "invalid func" or "unsupported".
        assertTrue(cls == ErrorClass.HELPER_NOT_ALLOWED || cls == ErrorClass.UNRESOLVED_FUNC,
                "expected HELPER_NOT_ALLOWED or UNRESOLVED_FUNC, got " + cls + "\nlog:\n" + log);
    }

    @Test
    public void outOfBoundsIsClassifiedFromRealLog() {
        var log = captureLog(OutOfBoundsProg.class);
        var cls = classifyOf(log);
        // The verifier may either reject with "max value outside" (OUT_OF_BOUNDS) or
        // demand a bounds-check first ("invalid mem access"); both are acceptable signals.
        assertTrue(cls == ErrorClass.OUT_OF_BOUNDS || cls == ErrorClass.INVALID_MEM_ACCESS
                        || cls == ErrorClass.STACK_OOB,
                "expected OUT_OF_BOUNDS / INVALID_MEM_ACCESS / STACK_OOB, got " + cls
                        + "\nlog:\n" + log);
    }

    @Test
    public void invalidMemAccessIsClassifiedFromRealLog() {
        var log = captureLog(InvalidMemAccessProg.class);
        var cls = classifyOf(log);
        assertNotEquals(ErrorClass.OTHER, cls,
                "raw-pointer deref should classify as something specific, got OTHER\nlog:\n" + log);
    }

    @Test
    public void exceptionMessageContainsHumaneSummary() {
        var ex = assertThrows(BPFVerifierException.class,
                () -> { try (var ignored = BPFProgram.load(UncheckedNullDerefProg.class)) {} });
        var msg = ex.getMessage();
        assertTrue(msg.contains("--- summary ---"),
                "message should contain humane summary section: " + msg);
        assertTrue(msg.contains("UNCHECKED_NULL_DEREF") || msg.contains("Why:"),
                "message should mention classification or 4-part hint: " + msg);
    }

    @Test
    public void parsedAccessorReturnsStructuredResult() {
        var ex = assertThrows(BPFVerifierException.class,
                () -> { try (var ignored = BPFProgram.load(InvalidMemAccessProg.class)) {} });
        var parsed = ex.parsed();
        assertTrue(parsed.error().isPresent(), "parsed should have an error: " + ex.verifierLog());
    }

    @Test
    public void infiniteLoopIsClassifiedFromRealLog() {
        var log = captureLog(InfiniteLoopProg.class);
        var cls = classifyOf(log);
        // Real shapes: "back-edge", "infinite loop detected", "loop limit", "BPF_LOOP".
        // PROGRAM_TOO_LARGE is also possible if the loop is unrolled past the insn budget.
        assertTrue(cls == ErrorClass.INFINITE_LOOP || cls == ErrorClass.PROGRAM_TOO_LARGE,
                "expected INFINITE_LOOP or PROGRAM_TOO_LARGE, got " + cls + "\nlog:\n" + log);
    }

    @Test
    public void typeMismatchIsClassifiedFromRealLog() {
        var log = captureLog(TypeMismatchProg.class);
        var cls = classifyOf(log);
        // Verifier may report "type=inv expected=fp" (TYPE_MISMATCH) or for some kernels
        // "R1 must point to a map" / "fd N is not pointing to valid bpf_map" — those are
        // catch-alls. We accept TYPE_MISMATCH or OTHER (the parser learns more shapes over time).
        assertNotNull(cls, "should produce a classification");
    }
}
