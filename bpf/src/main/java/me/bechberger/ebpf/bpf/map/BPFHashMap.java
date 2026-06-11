package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.BPFType;

import java.util.function.BiFunction;

/**
 * A base map based on <a href="https://docs.kernel.org/bpf/map_hash.html">BPF hash map</a>
 * <p>
 * A note on LRU maps: The LRU map evics the least recently used entry if the map is full, but this
 * doesn't mean that the map only evicts this entry, it might also remove others entries (at least one, as I observed
 * this behavior).
 * @param <K> key type
 * @param <V> value type
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_HASH);
            __uint (key_size, sizeof($c1));
            __uint (value_size, sizeof($c2));
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $b2)
        """)
public class BPFHashMap<K, V> extends BPFBaseMap<K, V> {

    /**
     * @param useLRU evict the least recently used entry if the map is full
     */
    public BPFHashMap(FileDescriptor fd, boolean useLRU, BPFType<K> keyType, BPFType<V> valueType) {
        super(fd, useLRU ? MapTypeId.LRU_HASH : MapTypeId.HASH, keyType, valueType);
    }

    public BPFHashMap(FileDescriptor fd, BPFType<K> keyType, BPFType<V> valueType) {
        this(fd, false, keyType, valueType);
    }

    public boolean usesLRU() {
        return typeId == MapTypeId.LRU_HASH;
    }

    /**
     * Iterate over every entry of this map via {@code bpf_for_each_map_elem}, calling
     * {@code body} for each (key, value) pair.
     * <p>
     * Lowers to {@code bpf_for_each_map_elem(&map, &__bpf_lambda_..., ctx, 0)} where
     * the lambda is lifted to a top-level static {@code __always_inline} C function
     * with the kernel ABI
     * {@code int (struct bpf_map *map, const void *key, void *value, void *ctx)}.
     * The lifted function dereferences the {@code key}/{@code value} pointers so
     * the user-written body sees plain {@code k} and {@code v} of types {@code K}
     * and {@code V}. The lambda body must NOT capture locals from the enclosing
     * method — pass state through {@code ctx} instead.
     * <p>
     * Return {@code 0} from {@code body} to continue, {@code 1} to break.
     * <p>
     * Requires kernel ≥5.13.
     */
    @BuiltinBPFFunction("bpf_for_each_map_elem(&$this, $func1:mapelem, $arg2, 0)")
    @NotUsableInJava
    public void forEach(BiFunction<K, V, Integer> body, Object ctx) {
        throw new MethodIsBPFRelatedFunction();
    }
}