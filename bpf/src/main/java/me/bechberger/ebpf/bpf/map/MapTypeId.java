package me.bechberger.ebpf.bpf.map;

import org.jetbrains.annotations.Nullable;

/**
 * The type of map, used to identify the map type
 */
public enum MapTypeId {
    HASH(1), ARRAY(2), PROG_ARRAY(3), PERF_EVENT_ARRAY(4), PERCPU_HASH(5), PERCPU_ARRAY(6), STACK_TRACE(7),
    CGROUP_ARRAY(8), LRU_HASH(9), LRU_PERCPU_HASH(10), LPM_TRIE(11), ARRAY_OF_MAPS(12), HASH_OF_MAPS(13), DEVMAP(14),
    SOCKMAP(15), CPUMAP(16), XSKMAP(17), SOCKHASH(18), CGROUP_STORAGE(19), REUSEPORT_SOCKARRAY(20),
    PERCPU_CGROUP_STORAGE(21), QUEUE(22), STACK(23), SK_STORAGE(24), DEVMAP_HASH(25), STRUCT_OPS(26),
    /** Ring buffer map type, see {@link BPFRingBuffer} */
    RINGBUF(27),
    INODE_STORAGE(28), TASK_STORAGE(29), BLOOM_FILTER(30);
    private final int id;

    MapTypeId(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    private static MapTypeId[] _values;

    private static MapTypeId[] getValues() {
        if (_values == null) {
            _values = new MapTypeId[256];
            for (MapTypeId type : MapTypeId.values()) {
                _values[type.id] = type;
            }
        }
        return _values;
    }

    public static @Nullable MapTypeId fromId(int id) {
        return id < 0 || id >= 256 ? null : getValues()[id];
    }
}
