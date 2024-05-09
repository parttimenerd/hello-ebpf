package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.type.BPFType;

@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_LRU_HASH);
            __uint (key_size, sizeof($c1));
            __uint (value_size, sizeof($c2));
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $b2)
        """)
public class BPFLRUHashMap<K, V> extends BPFHashMap<K, V> {
    public BPFLRUHashMap(FileDescriptor fd, BPFType<K> keyType, BPFType<V> valueType) {
        super(fd, true, keyType, valueType);
    }
}
