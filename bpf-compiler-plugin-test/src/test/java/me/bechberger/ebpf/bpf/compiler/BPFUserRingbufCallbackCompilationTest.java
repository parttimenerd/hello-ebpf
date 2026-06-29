package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFUserRingBuffer;
import me.bechberger.ebpf.bpf.map.BPFUserRingbufCallback;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Compiler-plugin unit test: verifies that {@link BPFUserRingbufCallback} lambdas
 * are lowered to a C thunk that uses {@code bpf_dynptr_read} to deserialize the
 * record from the dynptr, and that the surrounding call emits {@code bpf_user_ringbuf_drain}.
 */
public class BPFUserRingbufCallbackCompilationTest {

    @BPF(license = "GPL")
    public static abstract class Sample extends BPFProgram {

        @Type
        record Msg(@Unsigned int pid, @Unsigned long ts) {}

        @BPFMapDefinition(maxEntries = 4096)
        BPFUserRingBuffer<Msg> rb;

        @BPFFunction
        int drainAll(Ptr<Integer> budget) {
            return rb.drain((m, ctx) -> {
                int p = m.val().pid;
                return p == 0 ? 1 : 0;
            }, budget);
        }
    }

    /**
     * The generated C must:
     * <ol>
     *   <li>declare the map as {@code BPF_MAP_TYPE_USER_RINGBUF};</li>
     *   <li>call {@code bpf_user_ringbuf_drain} with the thunk as callback;</li>
     *   <li>contain {@code bpf_dynptr_read} inside the thunk.</li>
     * </ol>
     */
    @Test
    public void testTypedCallbackLowersToDynptrRead() {
        String code = BPFProgram.getCode(Sample.class);
        assertTrue(code.contains("BPF_MAP_TYPE_USER_RINGBUF"),
                "Emitted C must contain BPF_MAP_TYPE_USER_RINGBUF; got:\n" + code);
        assertTrue(code.contains("bpf_user_ringbuf_drain"),
                "drain kfunc missing from emitted C; got:\n" + code);
        assertTrue(code.contains("bpf_dynptr_read"),
                "dynptr read thunk missing from emitted C; got:\n" + code);
    }
}
