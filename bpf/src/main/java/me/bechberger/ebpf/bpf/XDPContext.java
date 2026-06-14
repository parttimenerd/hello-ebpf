package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

/**
 * Ergonomic context object for XDP programs.
 *
 * <p>Use as the parameter type of {@link XDPHook#xdpHandlePacket(XDPContext)}:
 *
 * <pre>{@code
 * @Override
 * public xdp_action xdpHandlePacket(XDPContext ctx) {
 *     if (!ctx.boundsOk(0, 1)) return xdp_action.XDP_ABORTED;
 *     int firstByte = ctx.byteAt(0);
 *     int len       = ctx.length();
 *     ...
 * }
 * }</pre>
 *
 * <p>The compiler plugin lowers {@code XDPContext} parameters to {@code struct xdp_md *} in the
 * generated C, so all instance methods use {@code $this->data} / {@code $this->data_end} directly.
 *
 * <p>Instance methods are not callable from Java user-space.
 */
public final class XDPContext {

    private final Ptr<xdp_md> ctx;

    public XDPContext(Ptr<xdp_md> ctx) {
        this.ctx = ctx;
    }

    /** Returns the underlying {@code Ptr<xdp_md>} for use with legacy APIs. */
    public Ptr<xdp_md> raw() {
        return ctx;
    }

    /**
     * Returns the raw {@code data} offset (uint32, as in {@code xdp_md.data}).
     *
     * <p>Lowers to: {@code ($this->data)}
     */
    @BuiltinBPFFunction("($this->data)")
    @NotUsableInJava
    public @Unsigned int data() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the raw {@code data_end} offset (uint32, as in {@code xdp_md.data_end}).
     *
     * <p>Lowers to: {@code ($this->data_end)}
     */
    @BuiltinBPFFunction("($this->data_end)")
    @NotUsableInJava
    public @Unsigned int dataEnd() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the packet length in bytes.
     *
     * <p>Lowers to: {@code (int)((void *)(long)$this->data_end - (void *)(long)$this->data)}
     */
    @BuiltinBPFFunction("((int)((void *)(long)$this->data_end - (void *)(long)$this->data))")
    @NotUsableInJava
    public int length() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns {@code true} if the byte range {@code [offset, offset+size)} is within packet bounds.
     *
     * <p>Lowers to:
     * {@code ((void *)(long)$this->data + ($arg1) + ($arg2) <= (void *)(long)$this->data_end)}
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

    /** @deprecated Use {@code ctx.length()} instead. */
    @Deprecated
    @BuiltinBPFFunction("((int)((void *)(long)$arg1->data_end - (void *)(long)$arg1->data))")
    @NotUsableInJava
    public static int length(Ptr<xdp_md> ctx) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** @deprecated Use {@code ctx.boundsOk(offset, size)} instead. */
    @Deprecated
    @BuiltinBPFFunction("((void *)(long)$arg1->data + ($arg2) + ($arg3) <= (void *)(long)$arg1->data_end)")
    @NotUsableInJava
    public static boolean boundsOk(Ptr<xdp_md> ctx, int offset, int size) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** @deprecated Use {@code ctx.byteAt(offset)} instead. */
    @Deprecated
    @BuiltinBPFFunction("(*((__u8 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static @Unsigned int byteAt(Ptr<xdp_md> ctx, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** @deprecated Use {@code ctx.shortAtNetworkOrder(offset)} instead. */
    @Deprecated
    @BuiltinBPFFunction("bpf_ntohs(*((__u16 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static @Unsigned int shortAtNetworkOrder(Ptr<xdp_md> ctx, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** @deprecated Use {@code ctx.intAtNetworkOrder(offset)} instead. */
    @Deprecated
    @BuiltinBPFFunction("bpf_ntohl(*((__u32 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static long intAtNetworkOrder(Ptr<xdp_md> ctx, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }
}
