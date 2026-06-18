package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.runtime.sock;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

/**
 * BPF socket-local storage map ({@code BPF_MAP_TYPE_SK_STORAGE}) — a per-socket
 * key-value store keyed implicitly by {@code sock *}.
 *
 * <p>Entries are created on demand and freed automatically when the socket is
 * destroyed, eliminating leaks.  Typical uses: per-socket latency tracking,
 * per-socket connection metadata, per-socket rate limiting state.
 *
 * <p>Requires Linux ≥ 5.2 and a GPL license.
 *
 * <h2>BPF-side usage</h2>
 * <pre>{@code
 * @Type
 * static class SockCtx extends Struct {
 *     long connectTime;
 *     long bytesSent;
 * }
 *
 * @BPFMapDefinition(maxEntries = 1)
 * BPFSkStorage<SockCtx> sockCtx;
 *
 * // In a socket-filter or cgroup BPF program:
 * Ptr<SockCtx> ctx = sockCtx.bpf_getOrCreate(sk);
 * if (ctx != null) ctx.val().bytesSent += packetLen;
 * }</pre>
 *
 * @param <V> the per-socket value type (must be a {@code @Type}-annotated struct)
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_SK_STORAGE);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(key, int);
            __type(value, $c1);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFSkStorage<V> extends BPFMap {

    private final BPFType<V> valueType;

    public BPFSkStorage(FileDescriptor fd, BPFType<V> valueType) {
        super(MapTypeId.SK_STORAGE, fd);
        this.valueType = valueType;
    }

    public BPFType<V> getValueType() {
        return valueType;
    }

    /**
     * BPF-side: look up the storage entry for {@code sk}, returning
     * {@code null} if no entry exists.
     *
     * <p>Lowers to {@code bpf_sk_storage_get(&map, sk, NULL, 0)}.
     */
    @BuiltinBPFFunction("bpf_sk_storage_get(&$this, $arg1, NULL, 0)")
    @NotUsableInJava
    public Ptr<V> bpf_get(Ptr<sock> sk) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * BPF-side: look up the storage entry for {@code sk}, creating a
     * zero-initialized entry if none exists.
     *
     * <p>Lowers to {@code bpf_sk_storage_get(&map, sk, NULL,
     * BPF_LOCAL_STORAGE_GET_F_CREATE)}.
     */
    @BuiltinBPFFunction("bpf_sk_storage_get(&$this, $arg1, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)")
    @NotUsableInJava
    public Ptr<V> bpf_getOrCreate(Ptr<sock> sk) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * BPF-side: delete the storage entry for {@code sk}.
     *
     * <p>Lowers to {@code bpf_sk_storage_delete(&map, sk)}.
     */
    @BuiltinBPFFunction("bpf_sk_storage_delete(&$this, $arg1)")
    @NotUsableInJava
    public long bpf_delete(Ptr<sock> sk) {
        throw new MethodIsBPFRelatedFunction();
    }
}
