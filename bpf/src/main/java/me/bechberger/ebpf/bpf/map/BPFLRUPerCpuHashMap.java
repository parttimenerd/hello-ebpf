package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.util.ArrayList;
import java.util.List;

/**
 * LRU per-CPU hash map ({@code BPF_MAP_TYPE_LRU_PERCPU_HASH}).
 *
 * <p>Combines LRU eviction with per-CPU storage: each CPU gets an independent
 * copy of every value, and the map automatically evicts the least-recently-used
 * entries when full — no pre-allocation required.  Useful for high-throughput
 * per-CPU counters that track a bounded working set (e.g., per-source-IP metrics
 * in XDP programs).
 *
 * <h2>BPF-side usage</h2>
 * <pre>{@code
 * @BPFMapDefinition(maxEntries = 4096)
 * BPFLRUPerCpuHashMap<Integer, Long> ipStats;
 *
 * Ptr<Long> count = ipStats.bpf_get(srcIp);
 * if (count != null) count.val()++;
 * }</pre>
 *
 * <h2>Java-side aggregation</h2>
 * <pre>{@code
 * long total = program.ipStats.sumAll(ip);
 * }</pre>
 *
 * @param <K> key type
 * @param <V> value type
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
            __type (key, $c1);
            __type (value, $c2);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $b2)
        """)
public class BPFLRUPerCpuHashMap<K, V> extends BPFMap {

    private final BPFType<K> keyType;
    private final BPFType<V> valueType;

    public BPFLRUPerCpuHashMap(FileDescriptor fd, BPFType<K> keyType, BPFType<V> valueType) {
        super(MapTypeId.LRU_PERCPU_HASH, fd);
        this.keyType = keyType;
        this.valueType = valueType.alignTo(8);
    }

    public BPFType<K> getKeyType() { return keyType; }
    public BPFType<V> getValueType() { return valueType; }

    private int numCpus() {
        return Lib_2.libbpf_num_possible_cpus();
    }

    private long stride() {
        long vs = valueType.size();
        return (vs + 7) & ~7L;
    }

    /**
     * Returns per-CPU values for the given key (one per possible CPU),
     * or an empty list if the key is not present.
     */
    public List<V> getAll(K key) {
        int cpus = numCpus();
        long stride = stride();
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, key);
            var valueSegment = arena.allocate(stride * cpus);
            if (Lib.bpf_map_lookup_elem(fd.fd(), keySegment, valueSegment) != 0) {
                return List.of();
            }
            List<V> result = new ArrayList<>(cpus);
            for (int cpu = 0; cpu < cpus; cpu++) {
                result.add(valueType.parseMemory(valueSegment.asSlice(cpu * stride, stride)));
            }
            return result;
        }
    }

    /** Returns the value for {@code key} on the given CPU, or {@code null} if not present. */
    public V getCpu(K key, int cpu) {
        List<V> all = getAll(key);
        return all.isEmpty() ? null : all.get(cpu);
    }

    /**
     * Stores values for the given key across all CPUs.
     * {@code values} must have exactly {@code libbpf_num_possible_cpus()} elements.
     */
    public boolean putAll(K key, List<V> values) {
        int cpus = numCpus();
        if (values.size() != cpus) {
            throw new IllegalArgumentException(
                    "values.size()=" + values.size() + " != num_possible_cpus=" + cpus);
        }
        long stride = stride();
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, key);
            var valueSegment = arena.allocate(stride * cpus);
            for (int cpu = 0; cpu < cpus; cpu++) {
                valueType.setMemory(valueSegment.asSlice(cpu * stride, stride), values.get(cpu));
            }
            return Lib.bpf_map_update_elem(fd.fd(), keySegment, valueSegment, 0) == 0;
        }
    }

    /** Removes the entry for the given key. Returns {@code true} if it existed. */
    public boolean delete(K key) {
        try (var arena = Arena.ofConfined()) {
            return Lib.bpf_map_delete_elem(fd.fd(), keyType.allocate(arena, key)) == 0;
        }
    }

    /**
     * Sums values across all CPUs for the given key.
     * Only valid when {@code V} is a numeric type.
     */
    @SuppressWarnings("unchecked")
    public long sumAll(K key) {
        return getAll(key).stream()
                .mapToLong(v -> ((Number) v).longValue())
                .sum();
    }

    /** In BPF programs: per-CPU lookup, returns pointer to current CPU's value or null. */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, $pointery$arg1)")
    @NotUsableInJava
    public Ptr<V> bpf_get(K key) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** In BPF programs: inserts or updates the per-CPU value for the given key. */
    @BuiltinBPFFunction("!bpf_map_update_elem(&$this, $pointery$arg1, $pointery$arg2, BPF_ANY)")
    @NotUsableInJava
    public boolean bpf_put(K key, V value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /** In BPF programs: deletes the entry for the given key. */
    @BuiltinBPFFunction("!bpf_map_delete_elem(&$this, $pointery$arg1)")
    @NotUsableInJava
    public boolean bpf_delete(K key) {
        throw new MethodIsBPFRelatedFunction();
    }
}
