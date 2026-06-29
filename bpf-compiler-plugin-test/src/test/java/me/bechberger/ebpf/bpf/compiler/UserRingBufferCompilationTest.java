package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFUserRingBuffer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Compiler-plugin unit test: verifies that a {@code BPFUserRingBuffer<E>} field
 * is lowered to a {@code BPF_MAP_TYPE_USER_RINGBUF} struct in generated C.
 *
 * <p>This test must FAIL before {@link BPFUserRingBuffer} and
 * {@link me.bechberger.ebpf.bpf.map.MapTypeId#USER_RINGBUF} are wired in,
 * and PASS afterwards (TDD gate for Task 0b).
 */
public class UserRingBufferCompilationTest {

    @BPF(license = "GPL")
    public static abstract class UserRingBufferSample extends BPFProgram {

        @Type
        record Msg(@Unsigned int pid) {}

        @BPFMapDefinition(maxEntries = 4096)
        BPFUserRingBuffer<Msg> outbox;

        @Kprobe("do_sys_openat2")
        public int onOpen(me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    /**
     * A {@code BPFUserRingBuffer} field must emit {@code BPF_MAP_TYPE_USER_RINGBUF}
     * and the correct {@code max_entries} value in the generated C.
     */
    @Test
    public void testUserRingBufferEmitsCorrectMapDefinition() {
        String code = BPFProgram.getCode(UserRingBufferSample.class);
        assertTrue(code.contains("BPF_MAP_TYPE_USER_RINGBUF"),
                "Emitted C must contain BPF_MAP_TYPE_USER_RINGBUF; got:\n" + code);
        assertTrue(code.contains("__uint(max_entries, 4096)"),
                "max_entries propagation broken; got:\n" + code);
    }
}
