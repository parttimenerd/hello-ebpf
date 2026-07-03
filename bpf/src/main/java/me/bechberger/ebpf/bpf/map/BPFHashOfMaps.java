package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Objects;

/**
 * eBPF hash-of-maps: an outer hash whose values are BPF map fds.
 * All inner maps share the same template (type/key_size/value_size/max_entries/flags),
 * enforced by the kernel at {@code bpf_map_update_elem} time.
 *
 * <p>The outer map's inner-map layout is supplied at load time via the BTF
 * {@code __array(values, innerTemplate)} idiom in the generated C struct.
 * libbpf resolves the inner-map fd automatically during {@code bpf_object__load};
 * see {@code @InnerMap} for the companion annotation.
 *
 * <p>Java API:
 * <ul>
 *   <li>{@link #register(Object, BPFMap)} - write the inner map's fd at key.</li>
 *   <li>{@link #unregister(Object)} - drop the outer's reference.</li>
 *   <li>{@link #get(Object)} - read back a fresh handle to the inner map (or {@code null}).</li>
 * </ul>
 *
 * <p>BPF-side:
 * <pre>{@code
 *   Ptr<InnerMap> inner = outer.lookup(key);
 *   if (inner != null) { ... }
 * }</pre>
 *
 * @param <K>        outer key type
 * @param <InnerMap> inner-map wrapper class (e.g. {@code BPFHashMap<Long, Long>})
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_HASH_OF_MAPS);
            __type (key, $c1);
            __type (value, __u32);
            __uint (max_entries, $maxEntries);
            __array (values, $innerName);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFHashOfMaps<K, InnerMap extends BPFMap> extends BPFMap {

    private final BPFType<K> keyType;

    public BPFHashOfMaps(FileDescriptor fd, BPFType<K> keyType) {
        super(MapTypeId.HASH_OF_MAPS, Objects.requireNonNull(fd, "fd"));
        this.keyType = Objects.requireNonNull(keyType, "keyType");
    }

    public BPFType<K> getKeyType() { return keyType; }

    /**
     * Register {@code inner}'s file descriptor at {@code key}.
     *
     * <p>If a different inner map was already registered at this key, the
     * kernel drops the old inner's reference and takes a new one on
     * {@code inner}. Template mismatch (different inner-map type / key /
     * value / max_entries / flags) is rejected by the kernel with EINVAL.
     */
    public void register(K key, BPFMap inner) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(inner, "inner");
        try (var arena = Arena.ofConfined()) {
            var keyMem = keyType.allocate(arena, key);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            valMem.set(ValueLayout.JAVA_INT, 0, inner.getFd().fd());
            int ret = Lib.bpf_map_update_elem(fd.fd(), keyMem, valMem, Lib.BPF_ANY());
            if (ret != 0) {
                throw new BPFError("bpf_map_update_elem on HASH_OF_MAPS failed for key "
                        + key + " (errno " + (-ret) + ")", ret);
            }
        }
    }

    /** Drop the outer's reference at {@code key}. Does not close the inner map. */
    public void unregister(K key) {
        Objects.requireNonNull(key, "key");
        try (var arena = Arena.ofConfined()) {
            var keyMem = keyType.allocate(arena, key);
            Lib.bpf_map_delete_elem(fd.fd(), keyMem);
        }
    }

    /**
     * Look up the inner map registered at {@code key}. Returns {@code null}
     * if no inner map is registered. The returned handle owns a fresh fd
     * obtained via {@code bpf_map_get_fd_by_id}; call {@link BPFMap#close()}
     * on it when done to avoid leaking the descriptor.
     *
     * <p>Note: kernel returns the inner map's <em>id</em>, not its fd, to
     * user space (see {@code map_lookup_elem} in {@code kernel/bpf/syscall.c}).
     * We convert id -&gt; fd via {@link Lib#bpf_map_get_fd_by_id(int)}.
     */
    public BPFMap get(K key) {
        Objects.requireNonNull(key, "key");
        try (var arena = Arena.ofConfined()) {
            var keyMem = keyType.allocate(arena, key);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            int ret = Lib.bpf_map_lookup_elem(fd.fd(), keyMem, valMem);
            if (ret != 0) return null;
            int innerId = valMem.get(ValueLayout.JAVA_INT, 0);
            int innerFd = Lib.bpf_map_get_fd_by_id(innerId);
            if (innerFd < 0) return null;
            return new BPFMap(null,
                    new FileDescriptor("<inner:" + key + ">", MemorySegment.NULL, innerFd));
        }
    }

    /**
     * BPF-side: return a pointer to the inner map registered at {@code key},
     * or {@code null} if none. Lowers to {@code bpf_map_lookup_elem(&outer, &key)}.
     */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, &$arg1)")
    @NotUsableInJava
    public Ptr<InnerMap> lookup(K key) {
        throw new MethodIsBPFRelatedFunction();
    }
}
