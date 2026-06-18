package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

/**
 * Per-CPU single-variable map ({@code BPF_MAP_TYPE_PERCPU_ARRAY} with {@code max_entries = 1}).
 *
 * <p>This is the idiomatic "thread-local variable in BPF" pattern — each CPU gets its own
 * independent copy of the value at index 0, so no locking or atomic operations are needed for
 * per-CPU counters and accumulators.
 *
 * <p>Equivalent to {@link BPFPerCpuArray}{@code <V>} with {@code maxEntries = 1}, but exposes
 * simpler single-slot accessors ({@link #get()}, {@link #set(Object)}, {@link #sumAll()}) and
 * a BPF-side {@link #bpf_get()} that returns a pointer directly.
 *
 * <p>Typical usage (BPF side — counter increment):
 * <pre>{@code
 *   @BPFMapDefinition(maxEntries = 1)
 *   BPFPerCpuVar<Long> pktCount;
 *
 *   @BPFFunction
 *   int xdp_count(Ptr<xdp_md> ctx) {
 *       Ptr<Long> cnt = pktCount.bpf_get();
 *       if (cnt != null) BPFJ.sync_fetch_and_add(cnt, 1L);
 *       return XDP_PASS;
 *   }
 * }</pre>
 *
 * <p>Typical usage (Java/user side — read total):
 * <pre>{@code
 *   long total = program.pktCount.sumAll();
 * }</pre>
 *
 * @param <V> value type; must be a numeric type for {@link #sumAll()}
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
        javaTemplate = "new $class<>($fd, $b1, $maxEntries)")
public class BPFPerCpuVar<V> extends BPFMap {

    private final BPFType<V> valueType;

    public BPFPerCpuVar(FileDescriptor fd, BPFType<V> valueType, int maxEntries) {
        super(MapTypeId.PERCPU_ARRAY, fd);
        this.valueType = valueType.alignTo(8);
    }

    private int numCpus() {
        return Lib_2.libbpf_num_possible_cpus();
    }

    private long stride() {
        long vs = valueType.size();
        return (vs + 7) & ~7L;
    }

    /**
     * Returns all per-CPU copies of the single variable.
     * The returned list has one element per possible CPU.
     */
    public List<V> getAll() {
        int cpus = numCpus();
        long stride = stride();
        try (var arena = Arena.ofConfined()) {
            var keySegment = arena.allocate(ValueLayout.JAVA_INT);
            keySegment.set(ValueLayout.JAVA_INT, 0, 0);
            var valueSegment = arena.allocate(stride * cpus);
            int ret = Lib.bpf_map_lookup_elem(fd.fd(), keySegment, valueSegment);
            if (ret != 0) {
                throw new BPFError("Failed to read BPFPerCpuVar", ret);
            }
            List<V> result = new ArrayList<>(cpus);
            for (int cpu = 0; cpu < cpus; cpu++) {
                result.add(valueType.parseMemory(valueSegment.asSlice(cpu * stride, stride)));
            }
            return result;
        }
    }

    /**
     * Returns the value for the specified CPU.
     */
    public V getCpu(int cpu) {
        return getAll().get(cpu);
    }

    /**
     * Returns the value from CPU 0 (useful when only one CPU is relevant, or as a default).
     * For aggregated results prefer {@link #sumAll()}.
     */
    public V get() {
        return getCpu(0);
    }

    /**
     * Overwrites the value on all CPUs simultaneously.
     * {@code values} must have exactly {@link Lib_2#libbpf_num_possible_cpus()} elements.
     */
    public void setAll(List<V> values) {
        int cpus = numCpus();
        if (values.size() != cpus) {
            throw new IllegalArgumentException("values.size()=" + values.size()
                    + " but num_possible_cpus=" + cpus);
        }
        long stride = stride();
        try (var arena = Arena.ofConfined()) {
            var keySegment = arena.allocate(ValueLayout.JAVA_INT);
            keySegment.set(ValueLayout.JAVA_INT, 0, 0);
            var valueSegment = arena.allocate(stride * cpus);
            for (int cpu = 0; cpu < cpus; cpu++) {
                valueType.setMemory(valueSegment.asSlice(cpu * stride, stride), values.get(cpu));
            }
            int ret = Lib.bpf_map_update_elem(fd.fd(), keySegment, valueSegment, 0);
            if (ret != 0) {
                throw new BPFError("Failed to write BPFPerCpuVar", ret);
            }
        }
    }

    /**
     * Sets the value for a single CPU, leaving other CPUs unchanged.
     */
    public void setCpu(int cpu, V value) {
        List<V> all = new ArrayList<>(getAll());
        all.set(cpu, value);
        setAll(all);
    }

    /**
     * Writes the same {@code value} to all CPUs.
     * Equivalent to {@link #setAll(List)} with all elements equal to {@code value}.
     */
    public void set(V value) {
        int cpus = numCpus();
        List<V> all = new ArrayList<>(cpus);
        for (int i = 0; i < cpus; i++) all.add(value);
        setAll(all);
    }

    /**
     * Returns the sum of this variable's value across all CPUs.
     * Only valid when {@code V} is a numeric type.
     *
     * @throws ClassCastException if {@code V} is not a {@link Number} subtype
     */
    @SuppressWarnings("unchecked")
    public long sumAll() {
        return getAll().stream()
                .mapToLong(v -> ((Number) v).longValue())
                .sum();
    }

    /**
     * BPF-side: looks up and returns a pointer to the per-CPU value for the current CPU.
     * Returns {@code null} if the lookup fails (which cannot happen for a valid array map,
     * but the verifier requires a null-check before the deref).
     *
     * <p>Lowers to {@code bpf_map_lookup_elem(&$this, &(u32){0})}.
     */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, &(u32){0})")
    @NotUsableInJava
    public Ptr<V> bpf_get() {
        throw new MethodIsBPFRelatedFunction();
    }

}
