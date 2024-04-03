package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.type.BPFType;

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
}