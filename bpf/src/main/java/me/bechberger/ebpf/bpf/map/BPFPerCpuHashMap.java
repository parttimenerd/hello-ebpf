package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.util.ArrayList;
import java.util.List;

/**
 * Per-CPU hash map ({@code BPF_MAP_TYPE_PERCPU_HASH}).
 *
 * <p>Like {@link BPFHashMap} but each CPU holds an independent copy of every
 * value.  This eliminates lock contention when many CPUs update the same key
 * concurrently — each CPU writes to its own slot and the Java side aggregates
 * across CPUs.
 *
 * <h2>BPF-side usage</h2>
 * <pre>{@code
 * @BPFMapDefinition(maxEntries = 256)
 * BPFPerCpuHashMap<Integer, Long> bytesByPort;
 *
 * // in xdpHandlePacket:
 * Ptr<Long> counter = bytesByPort.bpf_get(port);
 * if (counter != null) counter.val()++;
 * }</pre>
 *
 * <h2>Java-side aggregation</h2>
 * <pre>{@code
 * long total = program.bytesByPort.sumAll(80);
 * List<Long> perCpu = program.bytesByPort.getAll(80);
 * }</pre>
 *
 * @param <K> key type
 * @param <V> value type (must be a numeric or struct type)
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_PERCPU_HASH);
            __uint (map_flags, BPF_F_NO_PREALLOC);
            __type (key, $c1);
            __type (value, $c2);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $b2)
        """)
public class BPFPerCpuHashMap<K, V> extends BPFMap {

    private final BPFType<K> keyType;
    private final BPFType<V> valueType;

    public BPFPerCpuHashMap(FileDescriptor fd, BPFType<K> keyType, BPFType<V> valueType) {
        super(MapTypeId.PERCPU_HASH, fd);
        this.keyType = keyType;
        this.valueType = valueType.alignTo(8);
    }

    public BPFType<K> getKeyType() { return keyType; }
    public BPFType<V> getValueType() { return valueType; }

    private int numCpus() {
        return Lib_2.libbpf_num_possible_cpus();
    }

    /** Aligned per-CPU value stride (rounded up to 8 bytes as required by the kernel). */
    private long stride() {
        long vs = valueType.size();
        return (vs + 7) & ~7L;
    }

    /**
     * Returns the per-CPU values for the given key, one entry per possible CPU.
     * Returns an empty list if the key is not present.
     */
    public List<V> getAll(K key) {
        int cpus = numCpus();
        long stride = stride();
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, key);
            var valueSegment = arena.allocate(stride * cpus);
            var ret = Lib.bpf_map_lookup_elem(fd.fd(), keySegment, valueSegment);
            if (ret != 0) {
                return List.of();
            }
            List<V> result = new ArrayList<>(cpus);
            for (int cpu = 0; cpu < cpus; cpu++) {
                result.add(valueType.parseMemory(valueSegment.asSlice(cpu * stride, stride)));
            }
            return result;
        }
    }

    /**
     * Returns the value for the given key on the specified CPU, or {@code null} if not found.
     */
    public V getCpu(K key, int cpu) {
        List<V> all = getAll(key);
        return all.isEmpty() ? null : all.get(cpu);
    }

    /**
     * Stores the values for the given key across all CPUs.
     * {@code values} must have exactly {@code libbpf_num_possible_cpus()} elements.
     */
    public boolean putAll(K key, List<V> values) {
        int cpus = numCpus();
        if (values.size() != cpus) {
            throw new IllegalArgumentException(
                    "values.size()=" + values.size() + " but num_possible_cpus=" + cpus);
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

    /**
     * Removes the entry for the given key from the map.
     * @return {@code true} if the key was present
     */
    public boolean delete(K key) {
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, key);
            return Lib.bpf_map_delete_elem(fd.fd(), keySegment) == 0;
        }
    }

    /**
     * Returns the sum of the given key's values across all CPUs.
     * Only valid when {@code V} is a numeric type (Integer, Long, etc.).
     */
    @SuppressWarnings("unchecked")
    public long sumAll(K key) {
        return getAll(key).stream()
                .mapToLong(v -> ((Number) v).longValue())
                .sum();
    }

    /**
     * In BPF programs: looks up and returns a pointer to the per-CPU value for the
     * given key (on the current CPU), or {@code null} if the key is not present.
     */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, $pointery$arg1)")
    @NotUsableInJava
    public Ptr<V> bpf_get(K key) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * In BPF programs: inserts or updates the per-CPU value for the given key.
     */
    @BuiltinBPFFunction("!bpf_map_update_elem(&$this, $pointery$arg1, $pointery$arg2, BPF_ANY)")
    @NotUsableInJava
    public boolean bpf_put(K key, V value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * In BPF programs: deletes the entry for the given key.
     */
    @BuiltinBPFFunction("!bpf_map_delete_elem(&$this, $pointery$arg1)")
    @NotUsableInJava
    public boolean bpf_delete(K key) {
        throw new MethodIsBPFRelatedFunction();
    }
}
