package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

/**
 * Ergonomic helper for XDP programs.
 *
 * <p>All methods are {@code @BuiltinBPFFunction}-annotated — they lower to
 * bounds-checked C idioms that the kernel verifier accepts.  Call them from
 * inside a {@link XDPHook#xdpHandlePacket} body:
 *
 * <pre>{@code
 * @Override
 * public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
 *     if (!XDPContext.boundsOk(ctx, 0, 1)) return xdp_action.XDP_ABORTED;
 *     int firstByte = XDPContext.byteAt(ctx, 0);
 *     int len       = XDPContext.length(ctx);
 *     ...
 * }
 * }</pre>
 *
 * <p>None of the methods here are callable from Java user-space; they exist
 * only for the BPF compiler plugin to lower to C.
 */
public final class XDPContext {

    private XDPContext() {}

    /**
     * Returns the packet length in bytes.
     *
     * <p>Lowers to: {@code (int)((void *)(long)$arg1->data_end - (void *)(long)$arg1->data)}
     */
    @BuiltinBPFFunction("((int)((void *)(long)$arg1->data_end - (void *)(long)$arg1->data))")
    @NotUsableInJava
    public static int length(Ptr<xdp_md> ctx) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns {@code true} if the byte range {@code [offset, offset+size)} is within
     * the packet bounds, {@code false} otherwise.
     *
     * <p>Lowers to a bounds check the verifier understands:
     * {@code ((void *)(long)ctx->data + offset + size <= (void *)(long)ctx->data_end)}
     */
    @BuiltinBPFFunction("((void *)(long)$arg1->data + ($arg2) + ($arg3) <= (void *)(long)$arg1->data_end)")
    @NotUsableInJava
    public static boolean boundsOk(Ptr<xdp_md> ctx, int offset, int size) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads one byte at {@code offset} from the packet start.
     *
     * <p>No bounds check is performed — callers must call {@link #boundsOk} first
     * or arrange their own guard. Lowers to:
     * {@code (*(__u8 *)((void *)(long)ctx->data + offset))}
     */
    @BuiltinBPFFunction("(*((__u8 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static @Unsigned int byteAt(Ptr<xdp_md> ctx, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads a big-endian 16-bit value at {@code offset} (network byte order → host).
     *
     * <p>No bounds check — callers must guard first. Lowers to:
     * {@code bpf_ntohs(*(__u16 *)((void *)(long)ctx->data + offset))}
     */
    @BuiltinBPFFunction("bpf_ntohs(*((__u16 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static @Unsigned int shortAtNetworkOrder(Ptr<xdp_md> ctx, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads a big-endian 32-bit value at {@code offset} (network byte order → host).
     *
     * <p>No bounds check — callers must guard first. Lowers to:
     * {@code bpf_ntohl(*(__u32 *)((void *)(long)ctx->data + offset))}
     */
    @BuiltinBPFFunction("bpf_ntohl(*((__u32 *)((void *)(long)$arg1->data + ($arg2))))")
    @NotUsableInJava
    public static long intAtNetworkOrder(Ptr<xdp_md> ctx, int offset) {
        throw new MethodIsBPFRelatedFunction();
    }
}
