package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;

/**
 * Longest-prefix-match trie ({@code BPF_MAP_TYPE_LPM_TRIE}).
 *
 * <p>Used for CIDR-based packet classification.  The kernel finds the entry
 * whose key has the longest prefix (highest {@code prefixlen}) that is a
 * prefix of the lookup key.  Typical use: IPv4 / IPv6 routing tables and
 * access-control lists.
 *
 * <h2>Key format</h2>
 * <p>The key type {@code K} must be a {@code @Type}-annotated struct whose
 * first field is {@code @Unsigned int prefixlen} (number of significant
 * bits).  The remaining fields hold the address data.  The framework
 * passes the struct directly to the kernel — no wrapper is added.
 *
 * <p>Example key struct for IPv4:
 * <pre>{@code
 * @Type
 * static class IPv4Key extends Struct {
 *     @Unsigned int prefixlen;   // e.g. 24 for /24
 *     @Unsigned int addr;        // network-byte-order IPv4 address
 * }
 * }</pre>
 *
 * <h2>BPF-side usage</h2>
 * <pre>{@code
 * @BPFMapDefinition(maxEntries = 1024)
 * BPFLpmTrie<IPv4Key, Long> aclMap;
 *
 * // In XDP handler:
 * Ptr<Long> action = aclMap.bpf_get(lookupKey);
 * if (action != null) { ... }
 * }</pre>
 *
 * <h2>Java-side usage</h2>
 * <pre>{@code
 * var key = new IPv4Key();
 * key.prefixlen = 24;
 * key.addr = 0xC0A80100; // 192.168.1.0
 * program.aclMap.put(key, 1L);
 *
 * Long val = program.aclMap.get(lookupKey);
 * }</pre>
 *
 * @param <K> key type — must start with {@code @Unsigned int prefixlen}
 * @param <V> value type
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_LPM_TRIE);
            __uint (map_flags, BPF_F_NO_PREALLOC);
            __type (key, $c1);
            __type (value, $c2);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $b2)
        """)
public class BPFLpmTrie<K, V> extends BPFMap {

    private final BPFType<K> keyType;
    private final BPFType<V> valueType;

    public BPFLpmTrie(FileDescriptor fd, BPFType<K> keyType, BPFType<V> valueType) {
        super(MapTypeId.LPM_TRIE, fd);
        this.keyType = keyType;
        this.valueType = valueType;
    }

    public BPFType<K> getKeyType() { return keyType; }
    public BPFType<V> getValueType() { return valueType; }

    /**
     * Looks up the longest-prefix-match for the given key.
     * Returns the associated value, or {@code null} if no prefix matches.
     */
    public V get(K key) {
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, key);
            var valueSegment = valueType.allocate(arena);
            int ret = Lib.bpf_map_lookup_elem(fd.fd(), keySegment, valueSegment);
            return ret == 0 ? valueType.parseMemory(valueSegment) : null;
        }
    }

    /**
     * Inserts or updates the entry for the given key.
     * Returns {@code true} on success.
     */
    public boolean put(K key, V value) {
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, key);
            var valueSegment = valueType.allocate(arena, value);
            return Lib.bpf_map_update_elem(fd.fd(), keySegment, valueSegment, 0) == 0;
        }
    }

    /**
     * Removes the entry for the given key (exact match on prefixlen + data).
     * Returns {@code true} if the entry existed.
     */
    public boolean delete(K key) {
        try (var arena = Arena.ofConfined()) {
            return Lib.bpf_map_delete_elem(fd.fd(), keyType.allocate(arena, key)) == 0;
        }
    }

    /**
     * In BPF programs: looks up the longest-prefix-match for the given key
     * and returns a pointer to the associated value, or {@code null} if no
     * prefix matches.
     */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, $pointery$arg1)")
    @NotUsableInJava
    public Ptr<V> bpf_get(K key) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * In BPF programs: inserts or updates the entry for the given key.
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
