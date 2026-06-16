package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.SkDefinitions.__sk_buff;

/**
 * Ergonomic context object for TC (Traffic Control) classifier programs.
 *
 * <p>Use as the parameter type of {@link TCHook#tcHandleIngress(TCContext)} or
 * {@link TCHook#tcHandleEgress(TCContext)}:
 *
 * <pre>{@code
 * @Override
 * public __sk_action tcHandleIngress(TCContext skb) {
 *     if (!skb.boundsOk(0, 1)) return __sk_action.__SK_DROP;
 *     int firstByte = skb.byteAt(0);
 *     int len = skb.length();
 *     ...
 * }
 * }</pre>
 *
 * <p>The compiler plugin lowers {@code TCContext} parameters to {@code struct __sk_buff *} in
 * the generated C, so all instance methods use {@code $this->data} / {@code $this->data_end}
 * and {@code $this->len} directly.
 *
 * <p>Instance methods are not callable from Java user-space.
 */
public final class TCContext {

    private final Ptr<__sk_buff> skb;

    public TCContext(Ptr<__sk_buff> skb) {
        this.skb = skb;
    }

    /** Returns the underlying {@code Ptr<__sk_buff>} for use with legacy APIs. */
    public Ptr<__sk_buff> raw() {
        return skb;
    }

    /**
     * Returns the raw {@code data} offset (uint32, as in {@code __sk_buff.data}).
     *
     * <p>Lowers to: {@code ($this->data)}
     */
    @BuiltinBPFFunction("($this->data)")
    @NotUsableInJava
    public @Unsigned int data() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the raw {@code data_end} offset (uint32, as in {@code __sk_buff.data_end}).
     *
     * <p>Lowers to: {@code ($this->data_end)}
     */
    @BuiltinBPFFunction("($this->data_end)")
    @NotUsableInJava
    public @Unsigned int dataEnd() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the packet length in bytes (from {@code __sk_buff.len}).
     *
     * <p>Lowers to: {@code ((int)($this->len))}
     */
    @BuiltinBPFFunction("((int)($this->len))")
    @NotUsableInJava
    public int length() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns {@code true} if the byte range {@code [offset, offset+size)} is within packet bounds.
     *
     * <p>Lowers to:
     * {@code ((void *)(long)$this->data + ($arg1) + ($arg2) <= (void *)(long)$this->data_end)}
     *
     * <p><b>Verifier limitation:</b> Re-loads {@code skb->data} into a fresh BPF register.
     * Subsequent calls to {@link #byteAt}, {@link #shortAtNetworkOrder}, or
     * {@link #intAtNetworkOrder} also reload {@code skb->data} independently, so the verifier
     * cannot link their access register back to this bounds check — the program will be rejected.
     * Use {@link #data()}/{@link #dataEnd()} once, then do all accesses via typed
     * {@link me.bechberger.ebpf.type.Ptr} arithmetic (as in {@link BasePacketParser}).
     */
    @BuiltinBPFFunction("((void *)(long)$this->data + ($arg1) + ($arg2) <= (void *)(long)$this->data_end)")
    @NotUsableInJava
    public boolean boundsOk(int offset, int size) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads one byte at {@code offset} from the packet start.
     *
     * <p>No bounds check — call {@link #boundsOk} first.
     * Lowers to: {@code (*(__u8 *)((void *)(long)$this->data + ($arg1)))}
     */
    @BuiltinBPFFunction("(*((__u8 *)((void *)(long)$this->data + ($arg1))))")
    @NotUsableInJava
    public @Unsigned int byteAt(int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads a big-endian 16-bit value at {@code offset} (network byte order → host).
     *
     * <p>No bounds check — call {@link #boundsOk} first.
     * Lowers to: {@code bpf_ntohs(*(__u16 *)((void *)(long)$this->data + ($arg1)))}
     */
    @BuiltinBPFFunction("bpf_ntohs(*((__u16 *)((void *)(long)$this->data + ($arg1))))")
    @NotUsableInJava
    public @Unsigned int shortAtNetworkOrder(int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads a big-endian 32-bit value at {@code offset} (network byte order → host).
     *
     * <p>No bounds check — call {@link #boundsOk} first.
     * Lowers to: {@code bpf_ntohl(*(__u32 *)((void *)(long)$this->data + ($arg1)))}
     */
    @BuiltinBPFFunction("bpf_ntohl(*((__u32 *)((void *)(long)$this->data + ($arg1))))")
    @NotUsableInJava
    public long intAtNetworkOrder(int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    // --- Static helpers (kept for backwards compatibility) ---

    /** @deprecated Use {@code skb.length()} instead. */
    @Deprecated
    @BuiltinBPFFunction("((int)($arg1->len))")
    @NotUsableInJava
    public static int length(Ptr<__sk_buff> skb) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** @deprecated Use {@code skb.boundsOk(offset, size)} instead. */
    @Deprecated
    @BuiltinBPFFunction("((void *)(long)$arg1->data + ($arg2) + ($arg3) <= (void *)(long)$arg1->data_end)")
    @NotUsableInJava
    public static boolean boundsOk(Ptr<__sk_buff> skb, int offset, int size) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** @deprecated Use {@code skb.byteAt(offset)} instead. */
    @Deprecated
    @BuiltinBPFFunction("(*((__u8 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static @Unsigned int byteAt(Ptr<__sk_buff> skb, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** @deprecated Use {@code skb.shortAtNetworkOrder(offset)} instead. */
    @Deprecated
    @BuiltinBPFFunction("bpf_ntohs(*((__u16 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static @Unsigned int shortAtNetworkOrder(Ptr<__sk_buff> skb, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** @deprecated Use {@code skb.intAtNetworkOrder(offset)} instead. */
    @Deprecated
    @BuiltinBPFFunction("bpf_ntohl(*((__u32 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static long intAtNetworkOrder(Ptr<__sk_buff> skb, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }
}
