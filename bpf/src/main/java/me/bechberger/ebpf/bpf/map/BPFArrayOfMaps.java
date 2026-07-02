package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Objects;

/**
 * eBPF array-of-maps: an outer array (u32 keys) whose values are BPF map fds.
 * See {@link BPFHashOfMaps} for the sibling type and the {@code @InnerMap}
 * annotation used to supply the inner-map template.
 *
 * <p>The kernel enforces that every inner map registered under this outer
 * shares the same template (type, key_size, value_size, max_entries, flags).
 *
 * @param <InnerMap> inner-map wrapper class (e.g. {@code BPFHashMap<Long, Long>})
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
            __type (key, u32);
            __type (value, __u32);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $maxEntries)
        """)
public class BPFArrayOfMaps<InnerMap extends BPFMap> extends BPFMap {

    private final int size;

    public BPFArrayOfMaps(FileDescriptor fd, int size) {
        super(MapTypeId.ARRAY_OF_MAPS, Objects.requireNonNull(fd, "fd"));
        this.size = size;
    }

    public int size() { return size; }

    /**
     * Register {@code inner}'s fd at {@code slot}. Template mismatch (different
     * inner-map type / key / value / max_entries / flags) is rejected by the
     * kernel with EINVAL.
     */
    public void register(@Unsigned int slot, BPFMap inner) {
        if (slot < 0 || slot >= size) {
            throw new IndexOutOfBoundsException("slot " + slot + " out of [0," + size + ")");
        }
        Objects.requireNonNull(inner, "inner");
        try (var arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, slot);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            valMem.set(ValueLayout.JAVA_INT, 0, inner.getFd().fd());
            int ret = Lib.bpf_map_update_elem(fd.fd(), keyMem, valMem, Lib.BPF_ANY());
            if (ret != 0) {
                throw new BPFError("bpf_map_update_elem on ARRAY_OF_MAPS failed for slot "
                        + slot + " (errno " + (-ret) + ")", ret);
            }
        }
    }

    /**
     * ARRAY_OF_MAPS supports delete since kernel 4.12; drops the outer's
     * reference at {@code slot}. Does not close the inner map.
     */
    public void unregister(@Unsigned int slot) {
        if (slot < 0 || slot >= size) {
            throw new IndexOutOfBoundsException("slot " + slot + " out of [0," + size + ")");
        }
        try (var arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, slot);
            Lib.bpf_map_delete_elem(fd.fd(), keyMem);
        }
    }

    /**
     * Look up the inner map registered at {@code slot}. Returns {@code null}
     * if no inner map is registered or {@code slot} is out of range.
     *
     * <p>The returned handle owns a fresh fd obtained via
     * {@code bpf_map_get_fd_by_id}; call {@link BPFMap#close()} on it when done
     * to avoid leaking the descriptor. The kernel returns the inner map's
     * <em>id</em>, not its fd, to user space; we convert id -&gt; fd via
     * {@link Lib#bpf_map_get_fd_by_id(int)}.
     */
    public BPFMap get(@Unsigned int slot) {
        if (slot < 0 || slot >= size) return null;
        try (var arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, slot);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            int ret = Lib.bpf_map_lookup_elem(fd.fd(), keyMem, valMem);
            if (ret != 0) return null;
            int innerId = valMem.get(ValueLayout.JAVA_INT, 0);
            int innerFd = Lib.bpf_map_get_fd_by_id(innerId);
            if (innerFd < 0) return null;
            return new BPFMap(null,
                    new FileDescriptor("<inner:" + slot + ">", MemorySegment.NULL, innerFd));
        }
    }

    /**
     * BPF-side: return a pointer to the inner map registered at {@code slot},
     * or {@code null} if none. Lowers to {@code bpf_map_lookup_elem(&outer, &slot)}.
     */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, &$arg1)")
    @NotUsableInJava
    public Ptr<InnerMap> lookup(@Unsigned int slot) {
        throw new MethodIsBPFRelatedFunction();
    }
}
