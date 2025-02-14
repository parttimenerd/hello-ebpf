package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Objects;

/**
 * "{@code BPF_MAP_TYPE_BLOOM_FILTER} provides a BPF bloom filter map.
 * Bloom filters are a space-efficient probabilistic data structure
 * used to quickly test whether an element exists in a set.
 * In a bloom filter, false positives are possible whereas false negatives are not."
 * <a href="https://docs.kernel.org/next/bpf/map_bloom_filter.html">docs.kernel.org</a>
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_BLOOM_FILTER);
            __type (value, $c1);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $maxEntries)
        """)
public class BPFBloomFilter<V> extends BPFMap {

    private final BPFType<V> valueType;

    public BPFBloomFilter(FileDescriptor fd, MapTypeId mapType, BPFType<V> valueType) {
        super(mapType, fd);
        if (mapType != MapTypeId.BLOOM_FILTER) {
            throw new BPFError("Map type must be BLOOM_FILTER, but got " + mapType);
        }
        this.valueType = valueType;
    }

    /**
     * Insert a value into the bloom filter
     * @param value value
     * @return success?
     * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_map_update_elem(Ptr, Ptr, Ptr, long)
     */
    @BuiltinBPFFunction("!bpf_map_push_elem(&$this, $pointery$arg1, BPF_ANY)")
    public boolean push(V value) {
        try (var arena = Arena.ofConfined()) {
            var valueSegment = valueType.allocate(arena, Objects.requireNonNull(value));
            var ret = Lib.bpf_map_update_elem(fd.fd(), MemorySegment.NULL, valueSegment, Lib_2.BPF_ANY());
            return ret == 0;
        }
    }

    /**
     * Check if the value is probably present in the map
     */
    @BuiltinBPFFunction("!bpf_map_peek_elem(&$this, $pointery$arg1)")
    public boolean peek(V value) {
        try (var arena = Arena.ofConfined()) {
            var valueSegment = valueType.allocate(arena, Objects.requireNonNull(value));
            var ret = Lib.bpf_map_lookup_elem(fd.fd(), MemorySegment.NULL, valueSegment);
            return ret == 0;
        }
    }
}
