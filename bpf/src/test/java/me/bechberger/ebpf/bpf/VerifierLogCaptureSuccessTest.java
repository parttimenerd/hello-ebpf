package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Phase A.3 — verifies that a successful program load does NOT throw
 * {@link BPFVerifierException}. Earlier the load path was extended to
 * surface verifier output via {@code VerifierLogCapture}; this is a
 * regression guard ensuring informational libbpf output captured during
 * a successful load doesn't trigger a false-positive exception.
 */
public class VerifierLogCaptureSuccessTest {

    @BPF
    public static abstract class GoodProgram extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>

                SEC("kprobe/do_sys_openat2")
                int kprobe__noop(struct pt_regs *ctx) {
                    return 0;
                }

                char LICENSE[] SEC("license") = "GPL";
                """;
    }

    @Test
    public void testSuccessfulLoadDoesNotThrow() {
        assertDoesNotThrow(() -> {
            try (var ignored = BPFProgram.load(GoodProgram.class)) {
                // Loaded fine; close immediately.
            }
        }, "valid program should load without BPFVerifierException");
    }
}
