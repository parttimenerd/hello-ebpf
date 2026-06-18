package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.runtime.inode;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

/**
 * BPF inode-local storage map ({@code BPF_MAP_TYPE_INODE_STORAGE}) — a per-inode
 * key-value store keyed implicitly by {@code inode *}.
 *
 * <p>Entries are created on demand and freed automatically when the inode is
 * evicted, eliminating leaks.  Typical uses: per-file access counters, per-inode
 * security labels, per-inode tracing state in LSM hooks.
 *
 * <p>Requires Linux ≥ 5.10 and a GPL license.
 *
 * <h2>BPF-side usage</h2>
 * <pre>{@code
 * @Type
 * static class FileCtx extends Struct {
 *     long openCount;
 * }
 *
 * @BPFMapDefinition(maxEntries = 1)
 * BPFInodeStorage<FileCtx> fileCtx;
 *
 * // In an LSM hook (e.g. file_open):
 * Ptr<FileCtx> ctx = fileCtx.bpf_getOrCreate(inode);
 * if (ctx != null) ctx.val().openCount++;
 * }</pre>
 *
 * @param <V> the per-inode value type (must be a {@code @Type}-annotated struct)
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_INODE_STORAGE);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(key, int);
            __type(value, $c1);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFInodeStorage<V> extends BPFMap {

    private final BPFType<V> valueType;

    public BPFInodeStorage(FileDescriptor fd, BPFType<V> valueType) {
        super(MapTypeId.INODE_STORAGE, fd);
        this.valueType = valueType;
    }

    public BPFType<V> getValueType() {
        return valueType;
    }

    /**
     * BPF-side: look up the storage entry for {@code inode}, returning
     * {@code null} if no entry exists.
     *
     * <p>Lowers to {@code bpf_inode_storage_get(&map, inode, NULL, 0)}.
     */
    @BuiltinBPFFunction("bpf_inode_storage_get(&$this, $arg1, NULL, 0)")
    @NotUsableInJava
    public Ptr<V> bpf_get(Ptr<inode> inodePtr) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * BPF-side: look up the storage entry for {@code inode}, creating a
     * zero-initialized entry if none exists.
     *
     * <p>Lowers to {@code bpf_inode_storage_get(&map, inode, NULL,
     * BPF_LOCAL_STORAGE_GET_F_CREATE)}.
     */
    @BuiltinBPFFunction("bpf_inode_storage_get(&$this, $arg1, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)")
    @NotUsableInJava
    public Ptr<V> bpf_getOrCreate(Ptr<inode> inodePtr) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * BPF-side: delete the storage entry for {@code inode}.
     *
     * <p>Lowers to {@code bpf_inode_storage_delete(&map, inode)}.
     */
    @BuiltinBPFFunction("bpf_inode_storage_delete(&$this, $arg1)")
    @NotUsableInJava
    public long bpf_delete(Ptr<inode> inodePtr) {
        throw new MethodIsBPFRelatedFunction();
    }
}
