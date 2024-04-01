package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.shared.PanamaUtil;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.*;

/**
 * A base map based on <a href="https://docs.kernel.org/bpf/map_hash.html">BPF hash map</a>
 * <p>
 * We don't implement the full {@link Map} interface because it libbpf only supports a subset of the operations
 * and emulating the missing operations would hide the time complexity of the operations
 * @param <K> key type
 * @param <V> value type
 */
public class BPFBaseMap<K, V> extends BPFMap implements Iterable<Map.Entry<K, V>> {

    private final BPFType<K> keyType;
    private final BPFType<V> valueType;

    public BPFBaseMap(FileDescriptor fd, MapTypeId mapType, BPFType<K> keyType, BPFType<V> valueType) {
        super(mapType, fd);
        this.keyType = keyType;
        this.valueType = valueType;
    }

    public BPFType<K> getKeyType() {
        return keyType;
    }

    public BPFType<V> getValueType() {
        return valueType;
    }

    public static class BPFHashMapError extends BPFError {
        public BPFHashMapError(String message, int errorCode) {
            super(message, errorCode);
        }
    }

    /** Modes of putting a value into the map */
    public enum PutMode {
        /** Create a new entry or update an existing entry */
        BPF_ANY(Lib.BPF_ANY()),
        /** Create a new entry only if there is no existing entry */
        BPF_NOEXIST(Lib.BPF_NOEXIST()),
        /** Update an existing entry only */
        BPF_EXIST(Lib.BPF_EXIST());

        private final int mode;

        PutMode(int mode) {
            this.mode = mode;
        }
    }

    /**
     * Put a value into the map, updates it if its already there
     * @param key key
     * @param value value
     * @return false on error
     */
    public boolean put(K key, V value, PutMode mode) {
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, Objects.requireNonNull(key));
            var valueSegment = valueType.allocate(arena, Objects.requireNonNull(value));
            var ret = Lib.bpf_map_update_elem(fd.fd(), keySegment, valueSegment, mode.mode);
            return ret == 0;
        }
    }

    /** Put value into the map, updates it if it's already there */
    public boolean put(K key, V value) {
        return put(key, value, PutMode.BPF_ANY);
    }

    /**
     * Get a value from the map
     * @param key key
     * @return value or null if not found
     */
    public V get(K key) {
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, Objects.requireNonNull(key));
            var valueSegment = valueType.allocate(arena);
            var ret = Lib.bpf_map_lookup_elem(fd.fd(), keySegment, valueSegment);
            if (ret != 0) {
                return null;
            }
            return valueType.parseMemory(valueSegment);
        }
    }

    public boolean containsKey(K key) {
        return get(key) != null;
    }

    /**
     * Delete a value from the map
     * @param key key
     * @return false on error
     */
    public boolean delete(K key) {
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena, Objects.requireNonNull(key));
            var ret = Lib.bpf_map_delete_elem(fd.fd(), keySegment);
            return ret == 0;
        }
    }

    /**
     * Iterate over all keys in the map
     */
    public Iterator<K> keyIterator() {
        return new Iterator<K>() {

            record MemAndKey<K>(MemorySegment mem, K key) {}

            final Arena arena = Arena.ofConfined();
            @Nullable MemAndKey<K> next = obtainNext(null);
            MemorySegment nextKeyMem;

            boolean ended = false;
            @Override
            public boolean hasNext() {
                return !ended && next != null;
            }

            @Override
            public K next() {
                var res = next;
                if (ended) {
                    if (res != null) {
                        return res.key;
                    }
                    throw new NoSuchElementException();
                }
                next = obtainNext(next);
                return res.key;
            }

            @Nullable MemAndKey<K> obtainNext(@Nullable MemAndKey<K> prev) {
                if (ended) {
                    return null;
                }
                if (nextKeyMem == null) {
                    nextKeyMem = keyType.allocate(arena);
                }
                int res = Lib.bpf_map_get_next_key(fd.fd(), prev == null ? MemorySegment.NULL : prev.mem, nextKeyMem);
                if (res != 0) {
                    ended = true;
                    if (res == -PanamaUtil.ERRNO_ENOENT) {
                        return null;
                    }
                    throw new BPFHashMapError("Failed to get next key", res);
                }
                var ret = new MemAndKey<>(nextKeyMem, keyType.parseMemory(nextKeyMem));
                nextKeyMem = prev == null ? keyType.allocate(arena) : prev.mem;
                return ret;
            }
        };
    }

    public Set<K> keySet() {
        Set<K> keys = new HashSet<>();
        for (Iterator<K> it = keyIterator(); it.hasNext(); ) {
            K key = it.next();
            keys.add(key);
        }
        return keys;
    }

    /**
     * Iterate over all entries in the map
     */
    @Override
    public Iterator<Map.Entry<K, V>> iterator() {
        return new Iterator<Map.Entry<K, V>>() {

            final Iterator<K> keyIterator = keyIterator();

            @Override
            public boolean hasNext() {
                return keyIterator.hasNext();
            }

            @Override
            public Map.Entry<K, V> next() {
                var key = keyIterator.next();
                return new AbstractMap.SimpleEntry<>(key, get(key));
            }
        };
    }


    /**
     * Get all values in the map
     * @return set of values
     */
    public Set<V> values() {
        Set<V> values = new HashSet<>();
        for (K key : keySet()) {
            values.add(get(key));
        }
        return values;
    }

    /**
     * Get all entries in the map
     * @return set of entries
     */
    public Set<Map.Entry<K, V>> entrySet() {
        Set<Map.Entry<K, V>> entries = new HashSet<>();
        for (K key : keySet()) {
            entries.add(new AbstractMap.SimpleEntry<>(key, get(key)));
        }
        return entries;
    }

    public boolean isEmpty() {
        return !keyIterator().hasNext();
    }

    /** Obtains the number of entries by iterating over all keys */
    public int slowSize() {
        try (var arena = Arena.ofConfined()) {
            var keySegment = keyType.allocate(arena);
            int size = 0;
            while (Lib.bpf_map_get_next_key(fd.fd(), keySegment, keySegment) == 0) {
                size++;
            }
            return size;
        }
    }
}