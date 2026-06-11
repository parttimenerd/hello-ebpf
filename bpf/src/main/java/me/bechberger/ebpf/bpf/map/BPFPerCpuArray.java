package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;

/**
 * Per-CPU array map ({@code BPF_MAP_TYPE_PERCPU_ARRAY}).
 *
 * <p>Each CPU gets its own independent copy of every value.  On the Java side
 * {@link #getAll(int)} and {@link #setAll(int, List)} transfer all CPU copies at
 * once; {@link #getCpu(int, int)} and {@link #setCpu(int, int, Object)} target a
 * single CPU.
 *
 * <p>Usage as a "thread-local" counter (one entry, one CPU-local value):
 * <pre>{@code
 * @BPFMapDefinition(maxEntries = 1)
 * BPFPerCpuArray<Integer> myCounter;
 * }</pre>
 *
 * @param <V> value type
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_PERCPU_ARRAY);
            __type (key, u32);
            __type (value, $c1);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $maxEntries)
        """)
public class BPFPerCpuArray<V> extends BPFMap {

    private final BPFType<V> valueType;
    private final int size;

    public BPFPerCpuArray(FileDescriptor fd, BPFType<V> valueType, int size) {
        super(MapTypeId.PERCPU_ARRAY, fd);
        this.valueType = valueType.alignTo(8);
        this.size = size;
    }

    public int size() {
        return size;
    }

    private int numCpus() {
        return Lib_2.libbpf_num_possible_cpus();
    }

    /** Aligned per-CPU value stride (rounded up to 8 bytes as required by the kernel). */
    private long stride() {
        long vs = valueType.size();
        return (vs + 7) & ~7L;
    }

    /**
     * Returns the values of the given map index across all CPUs.
     * The returned list has one entry per possible CPU.
     */
    public List<V> getAll(@Unsigned int index) {
        int cpus = numCpus();
        long stride = stride();
        try (var arena = Arena.ofConfined()) {
            var keySegment = arena.allocate(4);
            keySegment.set(java.lang.foreign.ValueLayout.JAVA_INT, 0, index);
            var valueSegment = arena.allocate(stride * cpus);
            var ret = Lib.bpf_map_lookup_elem(fd.fd(), keySegment, valueSegment);
            if (ret != 0) {
                throw new BPFError("Failed to read per-CPU array at index " + index, ret);
            }
            List<V> result = new ArrayList<>(cpus);
            for (int cpu = 0; cpu < cpus; cpu++) {
                result.add(valueType.parseMemory(valueSegment.asSlice(cpu * stride, stride)));
            }
            return result;
        }
    }

    /**
     * Returns the value for the given map index on the specified CPU.
     */
    public V getCpu(@Unsigned int index, int cpu) {
        return getAll(index).get(cpu);
    }

    /**
     * Overwrites the values for the given map index on all CPUs.
     * {@code values} must have exactly {@link #numCpus()} elements.
     */
    public void setAll(@Unsigned int index, List<V> values) {
        int cpus = numCpus();
        if (values.size() != cpus) {
            throw new IllegalArgumentException("values.size()=" + values.size() + " but num_possible_cpus=" + cpus);
        }
        long stride = stride();
        try (var arena = Arena.ofConfined()) {
            var keySegment = arena.allocate(4);
            keySegment.set(java.lang.foreign.ValueLayout.JAVA_INT, 0, index);
            var valueSegment = arena.allocate(stride * cpus);
            for (int cpu = 0; cpu < cpus; cpu++) {
                valueType.setMemory(valueSegment.asSlice(cpu * stride, stride), values.get(cpu));
            }
            var ret = Lib.bpf_map_update_elem(fd.fd(), keySegment, valueSegment, 0);
            if (ret != 0) {
                throw new BPFError("Failed to write per-CPU array at index " + index, ret);
            }
        }
    }

    /**
     * Sets the value for the given map index on the specified CPU, leaving other CPUs unchanged.
     */
    public void setCpu(@Unsigned int index, int cpu, V value) {
        List<V> all = new ArrayList<>(getAll(index));
        all.set(cpu, value);
        setAll(index, all);
    }

    /**
     * Returns the sum of the given index's values across all CPUs.
     * Only valid when V is a numeric type.
     */
    @SuppressWarnings("unchecked")
    public long sumAll(@Unsigned int index) {
        return getAll(index).stream()
                .mapToLong(v -> ((Number) v).longValue())
                .sum();
    }

    /**
     * In BPF programs: looks up and returns a pointer to the per-CPU value at {@code index}
     * for the current CPU, or null if not found.
     */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, $pointery$arg1)")
    @NotUsableInJava
    public Ptr<V> bpf_get(@Unsigned int index) {
        throw new me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction();
    }
}
