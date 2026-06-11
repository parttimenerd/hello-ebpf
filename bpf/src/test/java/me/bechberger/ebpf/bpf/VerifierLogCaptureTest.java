package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@link VerifierLogCapture} captures the kernel verifier's log when
 * {@code bpf_object__load} fails, and that {@link BPFProgram#loadProgram()} surfaces
 * the captured text via {@link BPFVerifierException}.
 *
 * <p>The test program below is intentionally hand-rolled raw C with a deliberate
 * verifier violation (uninitialised stack read returned to userspace), bypassing the
 * Java→C translator so the failure mode is stable across translator changes. The
 * captured log is asserted to mention a verifier marker like a register name; this
 * proves the libbpf print callback is wired correctly and {@code vsnprintf} renders
 * the {@code va_list} payload.</p>
 */
public class VerifierLogCaptureTest {

    /** Raw C program that the verifier reliably rejects: returns an uninitialised
     *  stack value. The verifier reports something like "invalid read from stack". */
    @BPF
    public static abstract class BadProgram extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                SEC("kprobe/do_sys_openat2")
                int kprobe__bad(struct pt_regs *ctx) {
                    int x;            // uninitialised
                    return x;         // verifier: invalid read from stack
                }

                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    @Test
    public void testVerifierLogIsCaptured() {
        BPFVerifierException ex = assertThrows(BPFVerifierException.class,
                () -> { try (var ignored = BPFProgram.load(BadProgram.class)) {} });

        String log = ex.verifierLog();
        assertNotNull(log, "verifier log must be non-null");
        assertFalse(log.isEmpty(), "verifier log must be non-empty");

        // Some marker proving we actually parsed real verifier output, not just an
        // errno string. The verifier consistently mentions register names, opcodes,
        // or the literal word "verifier" / "invalid".
        boolean hasMarker = log.contains("R0") || log.contains("R1")
                || log.contains("R10") || log.toLowerCase().contains("verifier")
                || log.toLowerCase().contains("invalid");
        assertTrue(hasMarker,
                "verifier log should mention a register or contain 'verifier'/'invalid'; got:\n" + log);
    }
}
