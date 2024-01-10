package me.bechberger.ebpf.bcc;

import static me.bechberger.ebpf.bcc.PanamaUtil.*;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.*;
import java.util.function.UnaryOperator;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.raw.Lib;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Implementation of BPF maps.
 *
 * <p>"BPF 'maps' provide generic storage of different types for sharing data between kernel and
 * user space." – <a href="https://www.kernel.org/doc/html/latest/bpf/maps.html">Linux
 * documentation</a>
 *
 * <p>Translation of BCC's <code>class BPFTable</code>.
 */
public class BPFTable<K, V> {
    private final BPF bpf;
    private final long mapId;
    private final int mapFd;
    private final BPFType keyType;
    private final BPFType leafType;

    private final String name;
    private final int maxEntries;
    private final int ttype;
    private final int flags;

    public BPFTable(
            BPF bpf, long mapId, int mapFd, BPFType keyType, BPFType leafType, String name) {
        this.bpf = bpf;
        this.mapId = mapId;
        this.mapFd = mapFd;
        this.keyType = keyType;
        this.leafType = leafType;
        this.name = name;
        this.ttype = Lib.bpf_table_type_id(bpf.getModule(), mapId);
        this.flags = Lib.bpf_table_flags_id(bpf.getModule(), mapId);
        this.maxEntries = (int) Lib.bpf_table_max_entries_id(bpf.getModule(), mapId);
    }

    public int get_fd() {
        return mapFd;
    }

    public V get(Object key) {
        try (var arena = Arena.ofConfined()) {
            var keyInC = arena.allocate(keyType.layout());
            keyType.setMemory(keyInC, key);
            var leaf = arena.allocate(leafType.layout());
            var res = Lib.bpf_lookup_elem(mapFd, keyInC, leaf);
            if (res < 0) {
                return null;
            }
            return leafType.parseMemory(leaf);
        }
    }

    private static final HandlerWithErrno<Integer> BPF_UPDATE_ELEM =
            new HandlerWithErrno<>(
                    "bpf_update_elem",
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER));

    private ResultAndErr<Integer> bpf_update_elem(
            Arena arena, int map_fd, MemorySegment key, MemorySegment value, int flags) {
        return BPF_UPDATE_ELEM.call(arena, map_fd, key, value, flags);
    }

    public V put(K key, V value) {
        try (var arena = Arena.ofConfined()) {
            var keyInC = arena.allocate(keyType.layout());
            keyType.setMemory(keyInC, key);
            var leaf = arena.allocate(leafType.layout());
            leafType.setMemory(leaf, value);
            var res = bpf_update_elem(arena, mapFd, keyInC, leaf, 0);
            if (res.result() < 0) {
                throw new BPFCallException("Failed to update element", res.err());
            }
            return value;
        }
    }

    public V removeEntry(Object key) {
        try (var arena = Arena.ofConfined()) {
            var keyInC = arena.allocate(keyType.layout());
            keyType.setMemory(keyInC, key);
            var leaf = arena.allocate(leafType.layout());
            var res = Lib.bpf_lookup_elem(mapFd, keyInC, leaf);
            if (res < 0) {
                return null;
            }
            rawRemove(key);
            return leafType.parseMemory(leaf);
        }
    }

    private static final HandlerWithErrno<Integer> BPF_DELETE_ELEM =
            new HandlerWithErrno<>(
                    "bpf_delete_elem",
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER));

    private ResultAndErr<Integer> bpf_delete_elem(Arena arena, int map_fd, MemorySegment key) {
        return BPF_DELETE_ELEM.call(arena, map_fd, key);
    }

    public void rawRemove(Object key) {
        try (var arena = Arena.ofConfined()) {
            var keyInC = arena.allocate(keyType.layout());
            keyType.setMemory(keyInC, key);
            var res = bpf_delete_elem(arena, mapFd, keyInC);
            if (res.result() < 0) {
                throw new BPFCallException("Failed to delete element", res.err());
            }
        }
    }

    @NotNull
    public Set<K> keySet() {
        return items_lookup_batch().stream()
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toSet());
    }

    @NotNull
    public Collection<V> values() {
        return items_lookup_batch().stream()
                .map(Map.Entry::getValue)
                .collect(java.util.stream.Collectors.toList());
    }

    @NotNull
    public Set<Map.Entry<K, V>> entrySet() {
        return new HashSet<>(items_lookup_batch());
    }

    /** very inefficient */
    public int size() {
        var iter = keyIterator();
        var size = 0;
        while (iter.hasNext()) {
            iter.next();
            size++;
        }
        return size;
    }

    public boolean isEmpty() {
        return keyIterator().hasNext();
    }

    public boolean containsKey(Object key) {
        return get(key) != null;
    }

    @SuppressWarnings("unchecked")
    public boolean containsValue(Object value) {
        return values().contains((V) value);
    }

    private record AllocatedKeyAndLeafs(
            int count, @Nullable MemorySegment keySegment, @Nullable MemorySegment leafSegment) {}

    private AllocatedKeyAndLeafs alloc_key_values(
            Arena arena, boolean allocateKeys, boolean allocateValues) {
        return alloc_key_values(arena, allocateKeys, allocateValues, -1);
    }

    /**
     * Allocates keys and values, useful for bulk operations.
     *
     * @param arena arena to allocate memory in
     * @param allocateKeys whether to allocate keys
     * @param allocateValues whether to allocate values
     * @param count number of elements to allocate, or -1 to allocate all (@link
     *     BPFTable#max_entries)
     * @return allocated keys and values
     * @throws AssertionError if count is not -1 and smaller than 1 or larger than max_entries
     */
    private AllocatedKeyAndLeafs alloc_key_values(
            Arena arena, boolean allocateKeys, boolean allocateValues, int count) {
        if (count == -1) {
            count = maxEntries;
        }
        if (count < 1 || count > maxEntries) {
            throw new AssertionError("Invalid count");
        }
        return new AllocatedKeyAndLeafs(
                count,
                allocateKeys ? arena.allocateArray(keyType.layout(), count) : null,
                allocateValues ? arena.allocateArray(leafType.layout(), count) : null);
    }

    /**
     * Check if the given keys and values the right type and length.
     *
     * @return size of the array
     */
    private int sanity_check_keys_values(
            @Nullable MemorySegment keys, @Nullable MemorySegment values) {
        var arr_len = 0;
        if (keys != null) {
            if (keys.byteSize() != keyType.layout().byteSize()) {
                throw new AssertionError("Keys array length is wrong");
            }
            arr_len = (int) keys.byteSize() / (int) keyType.layout().byteSize();
        }
        if (values != null) {
            if (values.byteSize() != leafType.layout().byteSize()) {
                throw new AssertionError("Values array length is wrong");
            }
            var val_len = (int) values.byteSize() / (int) leafType.layout().byteSize();
            if (keys != null && arr_len != val_len) {
                throw new AssertionError("Keys array length != values array length");
            }
            arr_len = (int) values.byteSize() / (int) leafType.layout().byteSize();
        }
        if (arr_len < 1 || arr_len > maxEntries) {
            throw new AssertionError("Array's length is wrong");
        }
        return arr_len;
    }

    /**
     * Look up all the key-value pairs in the map.
     *
     * <p>Notes: lookup batch on a keys subset is not supported by the kernel.
     *
     * @return key-value pairs
     */
    public List<Map.Entry<K, V>> items_lookup_batch() {
        return items_lookup_and_optionally_delete_batch(false);
    }

    private static final HandlerWithErrno<Integer> BPF_DELETE_BATCH =
            new HandlerWithErrno<>(
                    "bpf_delete_batch",
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER));

    private ResultAndErr<Integer> bpf_delete_batch(
            Arena arena, int map_fd, @Nullable MemorySegment keys, MemorySegment count) {
        return BPF_DELETE_BATCH.call(arena, map_fd, keys, count);
    }

    /**
     * Delete the key-value pairs related to the keys given as parameters.
     *
     * <p>Note that if no keys are given, it is faster to call lib.bpf_lookup_and_delete_batch than
     * create keys array and then call lib.bpf_delete_batch on these keys.
     *
     * @param keys keys array to delete. If an array of keys is given then it deletes all the
     *     related keys-values. If keys is None (default) then it deletes all entries.
     */
    public void items_delete_batch(Arena arena, @Nullable MemorySegment keys) {
        if (keys != null) {
            var count = sanity_check_keys_values(keys, null);
            var countRef = arena.allocate(ValueLayout.JAVA_LONG);
            countRef.set(ValueLayout.JAVA_LONG, 0, count);
            var res = bpf_delete_batch(arena, mapFd, keys, countRef);
            if (res.result() != 0) {
                throw new BPFCallException("BPF_MAP_DELETE_BATCH has failed", res.err());
            }
        } else {
            items_lookup_and_optionally_delete_batch(true).forEach(e -> {});
        }
    }

    /**
     * Delete the key-value pairs related to the keys given as parameters.
     *
     * @param keys keys array to delete. If an array of keys is given then it deletes all
     */
    public void delete_keys(@Nullable List<K> keys) {
        try (var arena = Arena.ofConfined()) {
            if (keys != null) {
                var allocated = alloc_key_values(arena, true, false, keys.size());
                assert allocated.keySegment() != null;
                for (int i = 0; i < keys.size(); i++) {
                    keyType.setMemory(
                            allocated.keySegment().asSlice(i * keyType.sizePadded()), keys.get(i));
                }
                items_delete_batch(arena, allocated.keySegment());
            } else {
                items_lookup_and_optionally_delete_batch(true);
            }
        }
    }

    private static final HandlerWithErrno<Integer> BPF_UPDATE_BATCH =
            new HandlerWithErrno<>(
                    "bpf_update_batch",
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER));

    private static ResultAndErr<Integer> bpf_update_batch(
            Arena arena,
            int map_fd,
            @Nullable MemorySegment keys,
            @Nullable MemorySegment values,
            MemorySegment count) {
        return BPF_UPDATE_BATCH.call(arena, map_fd, keys, values, count);
    }

    /**
     * Update all the key-value pairs in the map provided.
     *
     * <p>The arrays must be the same length, between 1 and the maximum number of entries.
     *
     * @param keys keys array to update
     * @param values values array to update
     */
    public void items_update_batch(
            Arena arena, @Nullable MemorySegment keys, @Nullable MemorySegment values) {
        var count = sanity_check_keys_values(keys, values);
        var countRef = arena.allocate(ValueLayout.JAVA_LONG);
        countRef.set(ValueLayout.JAVA_LONG, 0, count);
        var res = bpf_update_batch(arena, mapFd, keys, values, countRef);
        if (res.result() != 0) {
            throw new BPFCallException("BPF_MAP_UPDATE_BATCH has failed", res.err());
        }
    }

    /** Look up and delete all the key-value pairs in the map. */
    public List<Map.Entry<K, V>> items_lookup_and_delete_batch() {
        return items_lookup_and_optionally_delete_batch(true);
    }

    private static final HandlerWithErrno<Integer> BPF_LOOKUP_AND_DELETE_BATCH =
            new HandlerWithErrno<>(
                    "bpf_lookup_and_delete_batch",
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER));

    private ResultAndErr<Integer> bpf_lookup_and_delete_batch(
            Arena arena,
            int map_fd,
            @Nullable MemorySegment in_batch,
            @Nullable MemorySegment out_batch,
            @Nullable MemorySegment keys,
            @Nullable MemorySegment values,
            MemorySegment count) {
        return BPF_LOOKUP_AND_DELETE_BATCH.call(
                arena, map_fd, in_batch, out_batch, keys, values, count);
    }

    private static final HandlerWithErrno<Integer> BPF_LOOKUP_BATCH =
            new HandlerWithErrno<>(
                    "bpf_lookup_batch",
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER));

    private ResultAndErr<Integer> bpf_lookup_batch(
            Arena arena,
            int map_fd,
            @Nullable MemorySegment in_batch,
            @Nullable MemorySegment out_batch,
            @Nullable MemorySegment keys,
            @Nullable MemorySegment values,
            MemorySegment count) {
        return BPF_LOOKUP_BATCH.call(arena, map_fd, in_batch, out_batch, keys, values, count);
    }

    /**
     * Look up and optionally delete all the key-value pairs in the map.
     *
     * <p>Note: lookup and delete batch on a keys subset is not supported by
     *
     * @param delete whether to delete the key-value pairs when true, else just look up
     * @return stream of key-value pairs that have been looked up and deleted
     */
    private List<Map.Entry<K, V>> items_lookup_and_optionally_delete_batch(boolean delete) {
        try (Arena arena = Arena.ofConfined()) {
            var bpf_cmd = delete ? "BPF_MAP_LOOKUP_AND_DELETE_BATCH" : "BPF_MAP_LOOKUP_BATCH";
            var allocated = alloc_key_values(arena, true, true);
            var out_batch = arena.allocate(ValueLayout.JAVA_LONG);
            var count_ref = arena.allocate(ValueLayout.JAVA_LONG);
            out_batch.set(ValueLayout.JAVA_LONG, 0, 0);
            count_ref.set(ValueLayout.JAVA_LONG, 0, 0);
            var total = 0;
            while (true) {
                count_ref.set(ValueLayout.JAVA_LONG, 0, allocated.count() - total);
                var in_batch = total == 0 ? MemorySegment.NULL : out_batch;
                var res =
                        delete
                                ? bpf_lookup_and_delete_batch(
                                        arena,
                                        mapFd,
                                        in_batch,
                                        out_batch,
                                        allocated.keySegment(),
                                        allocated.leafSegment(),
                                        count_ref)
                                : bpf_lookup_batch(
                                        arena,
                                        mapFd,
                                        in_batch,
                                        out_batch,
                                        allocated.keySegment(),
                                        allocated.leafSegment(),
                                        count_ref);
                total += (int) count_ref.get(ValueLayout.JAVA_LONG, 0);
                if (res.err() != 0 && res.err() != ERRNO_ENOENT) {
                    throw new BPFCallException(bpf_cmd + " failed", res.err());
                }
                if (total == allocated.count()) {
                    break;
                }
                if (count_ref.get(ValueLayout.JAVA_LONG, 0) == 0) {
                    break;
                }
            }
            assert allocated.keySegment() != null;
            assert allocated.leafSegment() != null;
            var entries = new ArrayList<Map.Entry<K, V>>();
            for (int i = 0; i < total; i++) {
                var key =
                        keyType.<K>parseMemory(
                                allocated
                                        .keySegment()
                                        .asSlice(
                                                i * keyType.sizePadded(),
                                                keyType.layout().byteSize()));
                var value =
                        leafType.<V>parseMemory(
                                allocated
                                        .leafSegment()
                                        .asSlice(
                                                i * leafType.sizePadded(),
                                                leafType.layout().byteSize()));
                entries.add(new AbstractMap.SimpleEntry<>(key, value));
            }
            return entries;
        }
    }

    /** Store <code>null</code> in every entry */
    public void zero() {
        try (var arena = Arena.ofConfined()) {
            for (var key : keySet()) {
                var keyInC = arena.allocate(keyType.layout());
                keyType.setMemory(keyInC, key);
                var res = bpf_update_elem(arena, mapFd, keyInC, MemorySegment.NULL, 0);
                if (res.result() < 0) {
                    throw new BPFCallException("Failed to update element", res.err());
                }
            }
        }
    }

    private @Nullable K nextKey(@Nullable K prevKey) {
        try (var arena = Arena.ofConfined()) {
            var keyInC = arena.allocate(keyType.layout());
            if (prevKey == null) {
                var res = Lib.bpf_get_first_key(mapFd, keyInC, keyType.layout().byteSize());
                if (res < 0) {
                    return null;
                }
            } else {
                keyType.setMemory(keyInC, prevKey);
                var res = Lib.bpf_get_next_key(mapFd, keyInC, keyInC);
                if (res < 0) {
                    return null;
                }
            }
            return keyType.parseMemory(keyInC);
        }
    }

    @NotNull
    public Iterator<K> keyIterator() {
        return new Iterator<>() {
            private K next = nextKey(null);

            @Override
            public boolean hasNext() {
                return next != null;
            }

            @Override
            public K next() {
                var res = next;
                next = nextKey(res);
                return res;
            }
        };
    }

    // TODO: implement log histrograms

    /**
     * Prints a table as a linear histogram. This is intended to span integer ranges, eg, from 0 to
     * 100. The val_type argument is optional, and is a column header. If the histogram has a
     * secondary key, multiple tables will print and section_header can be used as a header
     * description for each. If section_print_fn is not null, it will be passed the bucket value to
     * format into a string as it sees fit. If bucket_fn is not null, it will be used to produce a
     * bucket value for the histogram keys. If the value of strip_leading_zero is not False, prints
     * a histogram that is omitted leading zeros from the beginning. If bucket_sort_fn is not null,
     * it will be used to sort the buckets before iterating them, and it is useful when there are
     * multiple fields in the secondary key. The maximum index allowed is linear_index_max (1025),
     * which is hoped to be sufficient for integer ranges spanned.
     */
    public void print_linear_hist(
            String val_type,
            String section_header,
            String section_print_fn,
            String bucket_fn,
            String strip_leading_zero,
            String bucket_sort_fn) {
        // TODO: implement structs
        Integer[] vals = new Integer[HistogramUtils.LINEAR_INDEX_MAX];
        for (var entry : entrySet()) {
            var key = entry.getKey();
            var value = entry.getValue();
            try {
                vals[key.hashCode()] = value.hashCode();
            } catch (IndexOutOfBoundsException e) {
                throw new IndexOutOfBoundsException(
                        "Index in print_linear_hist() of "
                                + key.hashCode()
                                + " exceeds max of "
                                + HistogramUtils.LINEAR_INDEX_MAX);
            }
        }
        HistogramUtils.printLinearHist(
                Arrays.asList(vals),
                val_type,
                strip_leading_zero != null && !strip_leading_zero.equals("False"));
    }

    public int getMaxEntries() {
        return maxEntries;
    }

    public static class BaseMapTable<K, V> extends BPFTable<K, V> implements Map<K, V> {

        public BaseMapTable(
                BPF bpf, long mapId, int mapFd, BPFType keyType, BPFType leafType, String name) {
            super(bpf, mapId, mapFd, keyType, leafType, name);
        }

        @Override
        public V remove(Object key) {
            return removeEntry(key);
        }

        @Override
        public void putAll(@NotNull Map<? extends K, ? extends V> m) {
            for (var entry : m.entrySet()) {
                put(entry.getKey(), entry.getValue());
            }
        }

        @Override
        public void clear() {
            delete_keys(null);
        }
    }

    public @FunctionalInterface interface TableProvider<T extends BPFTable<?, ?>> {
        T createTable(BPF bpf, long mapId, int mapFd, String name);
    }

    public static class HashTable<K, V> extends BaseMapTable<K, V> {
        public HashTable(
                BPF bpf, long mapId, int mapFd, BPFType keyType, BPFType leafType, String name) {
            super(bpf, mapId, mapFd, keyType, leafType, name);
        }

        public static final TableProvider<HashTable<@Unsigned Long, @Unsigned Long>>
                UINT64T_MAP_PROVIDER =
                        (bpf, mapId, mapFd, name) ->
                                new HashTable<>(
                                        bpf,
                                        mapId,
                                        mapFd,
                                        BPFType.BPFIntType.UINT64,
                                        BPFType.BPFIntType.UINT64,
                                        name);

        public static <K, V> TableProvider<HashTable<K, V>> createProvider(
                BPFType keyType, BPFType leafType) {
            return (bpf, mapId, mapFd, name) ->
                    new HashTable<>(bpf, mapId, mapFd, keyType, leafType, name);
        }
    }

    public static class LruHash<K, V> extends BaseMapTable<K, V> {
        public LruHash(
                BPF bpf, long mapId, int mapFd, BPFType keyType, BPFType leafType, String name) {
            super(bpf, mapId, mapFd, keyType, leafType, name);
        }
    }

    /** Base class for all array like types, fixed size array */
    public static class Array<K, V> extends BPFTable<K, V> implements List<V> {
        public Array(
                BPF bpf, long mapId, int mapFd, BPFType keyType, BPFType leafType, String name) {
            super(bpf, mapId, mapFd, keyType, leafType, name);
            if (!(keyType instanceof BPFType.BPFIntType)) {
                throw new AssertionError("Array key must be an integer type");
            }
        }

        public int size() {
            return getMaxEntries();
        }

        @Override
        public boolean contains(Object o) {
            return super.containsValue(o);
        }

        @NotNull
        @Override
        public Object @NotNull [] toArray() {
            return toArray(new Object[0]);
        }

        @NotNull
        @Override
        public <T> T @NotNull [] toArray(@NotNull T @NotNull [] a) {
            return values().toArray(a);
        }

        /** Not supported, as array is fixed size */
        @Override
        public boolean add(V v) {
            throw new UnsupportedOperationException("Array is fixed size");
        }

        @Override
        public boolean containsAll(@NotNull Collection<?> c) {
            return values().containsAll(c);
        }

        /** Not supported, as array is fixed size */
        @Override
        public boolean addAll(@NotNull Collection<? extends V> c) {
            throw new UnsupportedOperationException("Array is fixed size");
        }

        /** Not supported, as array is fixed size */
        @Override
        public boolean addAll(int index, @NotNull Collection<? extends V> c) {
            throw new UnsupportedOperationException("Array is fixed size");
        }

        /** Nulls all elements */
        @Override
        public boolean removeAll(@NotNull Collection<?> c) {
            var toRemove = new ArrayList<K>();
            var entries = entrySet();
            for (var entry : entries) {
                if (c.contains(entry.getValue())) {
                    toRemove.add(entry.getKey());
                }
            }
            delete_keys(toRemove);
            return !toRemove.isEmpty();
        }

        @Override
        public boolean retainAll(@NotNull Collection<?> c) {
            var toRemove = new ArrayList<K>();
            var entries = entrySet();
            for (var entry : entries) {
                if (!c.contains(entry.getValue())) {
                    toRemove.add(entry.getKey());
                }
            }
            delete_keys(toRemove);
            return !toRemove.isEmpty();
        }

        @Override
        public void replaceAll(UnaryOperator<V> operator) {
            List.super.replaceAll(operator);
        }

        @Override
        public void clear() {
            zero();
        }

        @Override
        public V get(int index) {
            return get((Object) index);
        }

        @SuppressWarnings("unchecked")
        @Override
        public V set(int index, V element) {
            return put((K) (Object) index, element);
        }

        /** Not supported, as array is fixed size */
        @Override
        public void add(int index, V element) {
            throw new UnsupportedOperationException("Array is fixed size");
        }

        /** nulls the element */
        @Override
        public V remove(int index) {
            var val = get(index);
            set(index, null);
            return val;
        }

        @Override
        public boolean remove(Object o) {
            var index = indexOf(o);
            if (index == -1) {
                return false;
            }
            remove(index);
            return true;
        }

        @SuppressWarnings("unchecked")
        @Override
        public int indexOf(Object o) {
            return ((Optional<Integer>)
                            entrySet().stream()
                                    .filter(e -> e.getValue().equals(o))
                                    .map(Map.Entry::getKey)
                                    .findFirst())
                    .orElse(-1);
        }

        @Override
        public int lastIndexOf(Object o) {
            var findings =
                    entrySet().stream()
                            .filter(e -> e.getValue().equals(o))
                            .map(Map.Entry::getKey)
                            .toArray();
            return findings.length == 0 ? -1 : (int) findings[findings.length - 1];
        }

        @NotNull
        @Override
        public ListIterator<V> listIterator() {
            return listIterator(0);
        }

        @NotNull
        @Override
        public ListIterator<V> listIterator(int index) {
            return new ListIterator<>() {
                int currentIndex = index;

                @Override
                public boolean hasNext() {
                    return index < size() - 1;
                }

                @Override
                public V next() {
                    return get(currentIndex++);
                }

                @Override
                public boolean hasPrevious() {
                    return index > 0;
                }

                @Override
                public V previous() {
                    return get(currentIndex--);
                }

                @Override
                public int nextIndex() {
                    return currentIndex + 1;
                }

                @Override
                public int previousIndex() {
                    return currentIndex - 1;
                }

                @Override
                public void remove() {
                    Array.this.remove(currentIndex);
                }

                @Override
                public void set(V v) {
                    Array.this.set(currentIndex, v);
                }

                @Override
                public void add(V v) {
                    throw new UnsupportedOperationException("Array is fixed size");
                }
            };
        }

        @NotNull
        @Override
        public Iterator<V> iterator() {
            return listIterator();
        }

        /** Not supported, as array is fixed size */
        @NotNull
        @Override
        public List<V> subList(int fromIndex, int toIndex) {
            throw new UnsupportedOperationException("Array is fixed size");
        }
    }
}
