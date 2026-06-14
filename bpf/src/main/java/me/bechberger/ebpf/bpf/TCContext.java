package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.SkDefinitions.__sk_buff;

/**
 * Ergonomic helper for TC (Traffic Control) classifier programs.
 *
 * <p>All methods are {@code @BuiltinBPFFunction}-annotated — they lower to
 * bounds-checked C idioms that the kernel verifier accepts.  Call them from
 * inside a {@link TCHook#tcHandleIngress} or {@link TCHook#tcHandleEgress} body:
 *
 * <pre>{@code
 * @Override
 * public __sk_action tcHandleIngress(Ptr<__sk_buff> skb) {
 *     if (!TCContext.boundsOk(skb, 0, 1)) return __sk_action.__SK_DROP;
 *     int firstByte = TCContext.byteAt(skb, 0);
 *     ...
 * }
 * }</pre>
 *
 * <p>None of the methods here are callable from Java user-space; they exist
 * only for the BPF compiler plugin to lower to C.
 */
public final class TCContext {

    private TCContext() {}

    /**
     * Returns the packet length in bytes (from {@code __sk_buff.len}).
     *
     * <p>Lowers to: {@code (int)($arg1->len)}
     */
    @BuiltinBPFFunction("((int)($arg1->len))")
    @NotUsableInJava
    public static int length(Ptr<__sk_buff> skb) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns {@code true} if the byte range {@code [offset, offset+size)} is within
     * the packet bounds, {@code false} otherwise.
     *
     * <p>Lowers to: {@code ((void *)(long)skb->data + offset + size <= (void *)(long)skb->data_end)}
     */
    @BuiltinBPFFunction("((void *)(long)$arg1->data + ($arg2) + ($arg3) <= (void *)(long)$arg1->data_end)")
    @NotUsableInJava
    public static boolean boundsOk(Ptr<__sk_buff> skb, int offset, int size) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads one byte at {@code offset} from the packet start.
     *
     * <p>No bounds check is performed — callers must call {@link #boundsOk} first.
     * Lowers to: {@code (*(__u8 *)((void *)(long)skb->data + offset))}
     */
    @BuiltinBPFFunction("(*((__u8 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static @Unsigned int byteAt(Ptr<__sk_buff> skb, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads a big-endian 16-bit value at {@code offset} (network byte order → host).
     *
     * <p>No bounds check — callers must guard first. Lowers to:
     * {@code bpf_ntohs(*(__u16 *)((void *)(long)skb->data + offset))}
     */
    @BuiltinBPFFunction("bpf_ntohs(*((__u16 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static @Unsigned int shortAtNetworkOrder(Ptr<__sk_buff> skb, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads a big-endian 32-bit value at {@code offset} (network byte order → host).
     *
     * <p>No bounds check — callers must guard first. Lowers to:
     * {@code bpf_ntohl(*(__u32 *)((void *)(long)skb->data + offset))}
     */
    @BuiltinBPFFunction("bpf_ntohl(*((__u32 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static long intAtNetworkOrder(Ptr<__sk_buff> skb, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }
}
