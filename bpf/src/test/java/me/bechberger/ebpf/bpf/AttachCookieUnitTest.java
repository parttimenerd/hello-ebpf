package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Asserts the byte size of the internal libbpf attach opts layouts we mirror
 * in {@link BPFProgram}. Guards against silent drift in the Panama structs.
 * These sizes are for libbpf 1.4+ on x86-64 / LP64 (kernel floor 6.14+).
 */
class AttachCookieUnitTest {

    @Test
    void kprobeOptsLayoutIs32Bytes() {
        // struct bpf_kprobe_opts { size_t sz; u64 bpf_cookie; size_t offset;
        //                          bool retprobe; size_t :0; } -> aligned to 32.
        assertEquals(32L, BPFProgram.internalKprobeOptsSize());
    }

    @Test
    void kprobeMultiOptsLayoutIs56Bytes() {
        // struct bpf_kprobe_multi_opts { size_t sz; const char **syms;
        //  const unsigned long *addrs; const u64 *cookies; size_t cnt;
        //  bool retprobe; bool session; bool unique_match; size_t :0; }
        assertEquals(56L, BPFProgram.internalKprobeMultiOptsSize());
    }

    @Test
    void uprobeMultiOptsLayoutIs64Bytes() {
        // struct bpf_uprobe_multi_opts { size_t sz; const char **syms;
        //  const unsigned long *offsets; const unsigned long *ref_ctr_offsets;
        //  const u64 *cookies; size_t cnt; unsigned int flags; pid_t pid;
        //  const char *path; size_t :0; }
        assertEquals(64L, BPFProgram.internalUprobeMultiOptsSize());
    }
}
