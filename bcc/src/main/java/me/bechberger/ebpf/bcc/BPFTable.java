/*
 * Copyright 2015 PLUMgrid, SAP SE
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.bcc.raw.Lib;
import me.bechberger.ebpf.bcc.raw.bcc_perf_buffer_opts;
import me.bechberger.ebpf.bcc.raw.perf_reader_lost_cb;
import me.bechberger.ebpf.bcc.raw.perf_reader_raw_cb;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.Closeable;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.channels.ClosedByInterruptException;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.UnaryOperator;

import static me.bechberger.ebpf.bcc.PanamaUtil.*;

/**
 * Implementation of BPF maps.
 * <p>
 * "BPF 'maps' provide generic storage of different types for sharing data between kernel and user space."
 * – <a href="https://www.kernel.org/doc/html/latest/bpf/maps.html">Linux documentation</a>
 * <p>
 * Translation of BCC's <code>class BPFTable</code>.
 */
public class BPFTable<K, V> {

    enum MapTypeId {
        HASH(1),
        ARRAY(2),
        PROG_ARRAY(3),
        PERF_EVENT_ARRAY(4),
        PERCPU_HASH(5),
        PERCPU_ARRAY(6),
        STACK_TRACE(7),
        CGROUP_ARRAY(8),
        LRU_HASH(9),
        LRU_PERCPU_HASH(10),
        LPM_TRIE(11),
        ARRAY_OF_MAPS(12),
        HASH_OF_MAPS(13),
        DEVMAP(14),
        SOCKMAP(15),
        CPUMAP(16),
        XSKMAP(17),
        SOCKHASH(18),
        CGROUP_STORAGE(19),
        REUSEPORT_SOCKARRAY(20),
        PERCPU_CGROUP_STORAGE(21),
        QUEUE(22),
        STACK(23),
        SK_STORAGE(24),
        DEVMAP_HASH(25),
        STRUCT_OPS(26),
        RINGBUF(27),
        INODE_STORAGE(28),
        TASK_STORAGE(29);
        private final int id;

        MapTypeId(int id) {
            this.id = id;
        }

        public int getId() {
            return id;
        }

        public static MapTypeId fromId(int id) {
            return Arrays.stream(values()).filter(m -> m.id == id).findFirst().get();
        }
    }

    final BPF bpf;
    private final long mapId;
    private final int mapFd;
    private final BPFType<K> keyType;
    private final BPFType<V> leafType;

    private final String name;
    private final int maxEntries;
    private final int ttype;
    private final int flags;

    public BPFTable(BPF bpf, MapTypeId typeId, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> leafType, String name) {
        this.bpf = bpf;
        this.mapId = mapId;
        this.mapFd = mapFd;
        this.keyType = keyType;
        this.leafType = leafType;
        this.name = name;
        this.ttype = Lib.bpf_table_type_id(bpf.getModule(), mapId);
        this.flags = Lib.bpf_table_flags_id(bpf.getModule(), mapId);
        this.maxEntries = (int) Lib.bpf_table_max_entries_id(bpf.getModule(), mapId);
        int expectedTypeId = Lib.bpf_table_type_id(bpf.getModule(), mapId);
        if (expectedTypeId != typeId.id) {
            throw new AssertionError("Expected type " + typeId + " but got " + MapTypeId.fromId(expectedTypeId));
        }
    }

    public int get_fd() {
        return mapFd;
    }

    @SuppressWarnings("unchecked")
    public V get(Object key) {
        try (var arena = Arena.ofConfined()) {
            var keyInC = arena.allocate(keyType.layout());
            keyType.setMemory(keyInC, (K)key);
            var leaf = arena.allocate(leafType.layout());
            var res = Lib.bpf_lookup_elem(mapFd, keyInC, leaf);
            if (res < 0) {
                return null;
            }
            return leafType.parseMemory(leaf);
        }
    }

    private static final HandlerWithErrno<Integer> BPF_UPDATE_ELEM = new HandlerWithErrno<>("bpf_update_elem",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, PanamaUtil.POINTER, PanamaUtil.POINTER, ValueLayout.JAVA_LONG));

    private ResultAndErr<Integer> bpf_update_elem(Arena arena, int map_fd, MemorySegment key, MemorySegment value, long flags) {
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

    @SuppressWarnings("unchecked")
    public V removeEntry(Object key) {
        try (var arena = Arena.ofConfined()) {
            var keyInC = arena.allocate(keyType.layout());
            keyType.setMemory(keyInC, (K)key);
            var leaf = arena.allocate(leafType.layout());
            var res = Lib.bpf_lookup_elem(mapFd, keyInC, leaf);
            if (res < 0) {
                return null;
            }
            rawRemove(key);
            return leafType.parseMemory(leaf);
        }
    }

    private static final HandlerWithErrno<Integer> BPF_DELETE_ELEM = new HandlerWithErrno<>("bpf_delete_elem", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, PanamaUtil.POINTER, PanamaUtil.POINTER));

    private ResultAndErr<Integer> bpf_delete_elem(Arena arena, int map_fd, MemorySegment key) {
        return BPF_DELETE_ELEM.call(arena, map_fd, key);
    }

    @SuppressWarnings("unchecked")
    public void rawRemove(Object key) {
        try (var arena = Arena.ofConfined()) {
            var keyInC = arena.allocate(keyType.layout());
            keyType.setMemory(keyInC, (K)key);
            var res = bpf_delete_elem(arena, mapFd, keyInC);
            if (res.result() < 0) {
                throw new BPFCallException("Failed to delete element", res.err());
            }
        }
    }

    @NotNull
    public Set<K> keySet() {
        return items_lookup_batch().stream().map(Map.Entry::getKey).collect(java.util.stream.Collectors.toSet());
    }

    @NotNull
    public Collection<V> values() {
        return items_lookup_batch().stream().map(Map.Entry::getValue).collect(java.util.stream.Collectors.toList());
    }

    @NotNull
    public Set<Map.Entry<K, V>> entrySet() {
        return new HashSet<>(items_lookup_batch());
    }

    /**
     * very inefficient
     */
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

    private record AllocatedKeyAndLeafs(int count, @Nullable MemorySegment keySegment,
                                        @Nullable MemorySegment leafSegment) {
    }

    private AllocatedKeyAndLeafs alloc_key_values(Arena arena, boolean allocateKeys, boolean allocateValues) {
        return alloc_key_values(arena, allocateKeys, allocateValues, -1);
    }

    /**
     * Allocates keys and values, useful for bulk operations.
     *
     * @param arena          arena to allocate memory in
     * @param allocateKeys   whether to allocate keys
     * @param allocateValues whether to allocate values
     * @param count          number of elements to allocate, or -1 to allocate all (@link BPFTable#max_entries)
     * @return allocated keys and values
     * @throws AssertionError if count is not -1 and smaller than 1 or larger than max_entries
     */
    private AllocatedKeyAndLeafs alloc_key_values(Arena arena, boolean allocateKeys, boolean allocateValues, int count) {
        if (count == -1) {
            count = maxEntries;
        }
        if (count < 1 || count > maxEntries) {
            throw new AssertionError("Invalid count");
        }
        return new AllocatedKeyAndLeafs(count, allocateKeys ? arena.allocateArray(keyType.layout(), count) : null, allocateValues ? arena.allocateArray(leafType.layout(), count) : null);
    }

    /**
     * Check if the given keys and values the right type and length.
     *
     * @return size of the array
     */
    private int sanity_check_keys_values(@Nullable MemorySegment keys, @Nullable MemorySegment values) {
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
     * <p>
     * Notes: lookup batch on a keys subset is not supported by the kernel.
     *
     * @return key-value pairs
     */
    public List<Map.Entry<K, V>> items_lookup_batch() {
        return items_lookup_and_optionally_delete_batch(false);
    }

    private static final HandlerWithErrno<Integer> BPF_DELETE_BATCH = new HandlerWithErrno<>("bpf_delete_batch", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, PanamaUtil.POINTER, PanamaUtil.POINTER));

    private ResultAndErr<Integer> bpf_delete_batch(Arena arena, int map_fd, @Nullable MemorySegment keys, MemorySegment count) {
        return BPF_DELETE_BATCH.call(arena, map_fd, keys, count);
    }

    /**
     * Delete the key-value pairs related to the keys given as parameters.
     * <p>
     * Note that if no keys are given, it is faster to call
     * lib.bpf_lookup_and_delete_batch than create keys array and then call
     * lib.bpf_delete_batch on these keys.
     *
     * @param keys keys array to delete. If an array of keys is given then it
     *             deletes all the related keys-values.
     *             If keys is None (default) then it deletes all entries.
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
            items_lookup_and_optionally_delete_batch(true).forEach(e -> {
            });
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
                    keyType.setMemory(allocated.keySegment().asSlice(i * keyType.sizePadded()), keys.get(i));
                }
                items_delete_batch(arena, allocated.keySegment());
            } else {
                items_lookup_and_optionally_delete_batch(true);
            }
        }
    }

    private static final HandlerWithErrno<Integer> BPF_UPDATE_BATCH = new HandlerWithErrno<>("bpf_update_batch", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER));

    private static ResultAndErr<Integer> bpf_update_batch(Arena arena, int map_fd, @Nullable MemorySegment keys, @Nullable MemorySegment values, MemorySegment count) {
        return BPF_UPDATE_BATCH.call(arena, map_fd, keys, values, count);
    }

    /**
     * Update all the key-value pairs in the map provided.
     * <p>
     * The arrays must be the same length, between 1 and the maximum number
     * of entries.
     *
     * @param keys   keys array to update
     * @param values values array to update
     */
    public void items_update_batch(Arena arena, @Nullable MemorySegment keys, @Nullable MemorySegment values) {
        var count = sanity_check_keys_values(keys, values);
        var countRef = arena.allocate(ValueLayout.JAVA_LONG);
        countRef.set(ValueLayout.JAVA_LONG, 0, count);
        var res = bpf_update_batch(arena, mapFd, keys, values, countRef);
        if (res.result() != 0) {
            throw new BPFCallException("BPF_MAP_UPDATE_BATCH has failed", res.err());
        }
    }

    /**
     * Look up and delete all the key-value pairs in the map.
     */
    public List<Map.Entry<K, V>> items_lookup_and_delete_batch() {
        return items_lookup_and_optionally_delete_batch(true);
    }

    private static final HandlerWithErrno<Integer> BPF_LOOKUP_AND_DELETE_BATCH = new HandlerWithErrno<>("bpf_lookup_and_delete_batch", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER));

    private ResultAndErr<Integer> bpf_lookup_and_delete_batch(Arena arena, int map_fd, @Nullable MemorySegment in_batch, @Nullable MemorySegment out_batch, @Nullable MemorySegment keys, @Nullable MemorySegment values, MemorySegment count) {
        return BPF_LOOKUP_AND_DELETE_BATCH.call(arena, map_fd, in_batch, out_batch, keys, values, count);
    }

    private static final HandlerWithErrno<Integer> BPF_LOOKUP_BATCH = new HandlerWithErrno<>("bpf_lookup_batch", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER));


    private ResultAndErr<Integer> bpf_lookup_batch(Arena arena, int map_fd, @Nullable MemorySegment in_batch, @Nullable MemorySegment out_batch, @Nullable MemorySegment keys, @Nullable MemorySegment values, MemorySegment count) {
        return BPF_LOOKUP_BATCH.call(arena, map_fd, in_batch, out_batch, keys, values, count);
    }

    /**
     * Look up and optionally delete all the key-value pairs in the map.
     * <p>
     * Note: lookup and delete batch on a keys subset is not supported by
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
                var res = delete ? bpf_lookup_and_delete_batch(arena, mapFd, in_batch, out_batch, allocated.keySegment(), allocated.leafSegment(), count_ref) : bpf_lookup_batch(arena, mapFd, in_batch, out_batch, allocated.keySegment(), allocated.leafSegment(), count_ref);
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
                var key = keyType.parseMemory(allocated.keySegment().asSlice(i * keyType.sizePadded(), keyType.layout().byteSize()));
                var value = leafType.parseMemory(allocated.leafSegment().asSlice(i * leafType.sizePadded(), leafType.layout().byteSize()));
                entries.add(new AbstractMap.SimpleEntry<>(key, value));
            }
            return entries;
        }
    }


    /**
     * Store <code>null</code> in every entry
     */
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
     * Prints a table as a linear histogram. This is intended to span integer
     * ranges, eg, from 0 to 100. The val_type argument is optional, and is a
     * column header.  If the histogram has a secondary key, multiple tables
     * will print and section_header can be used as a header description for
     * each.  If section_print_fn is not null, it will be passed the bucket
     * value to format into a string as it sees fit. If bucket_fn is not null,
     * it will be used to produce a bucket value for the histogram keys.
     * If the value of strip_leading_zero is not False, prints a histogram
     * that is omitted leading zeros from the beginning.
     * If bucket_sort_fn is not null, it will be used to sort the buckets
     * before iterating them, and it is useful when there are multiple fields
     * in the secondary key.
     * The maximum index allowed is linear_index_max (1025), which is hoped
     * to be sufficient for integer ranges spanned.
     */
    public void print_linear_hist(String val_type, String section_header, String section_print_fn, String bucket_fn, String strip_leading_zero, String bucket_sort_fn) {
        // TODO: implement structs
        Integer[] vals = new Integer[HistogramUtils.LINEAR_INDEX_MAX];
        for (var entry : entrySet()) {
            var key = entry.getKey();
            var value = entry.getValue();
            try {
                vals[key.hashCode()] = value.hashCode();
            } catch (IndexOutOfBoundsException e) {
                throw new IndexOutOfBoundsException("Index in print_linear_hist() of " + key.hashCode() + " exceeds max of " + HistogramUtils.LINEAR_INDEX_MAX);
            }
        }
        HistogramUtils.printLinearHist(Arrays.asList(vals), val_type, strip_leading_zero != null && !strip_leading_zero.equals("False"));
    }

    public int getMaxEntries() {
        return maxEntries;
    }

    public static class BaseMapTable<K, V> extends BPFTable<K, V> implements Map<K, V> {

        public BaseMapTable(BPF bpf, MapTypeId typeId, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> leafType, String name) {
            super(bpf, typeId, mapId, mapFd, keyType, leafType, name);
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
        HashTable(BPF bpf, MapTypeId id, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> leafType, String name) {
            super(bpf, MapTypeId.HASH, mapId, mapFd, keyType, leafType, name);
        }

        public HashTable(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> leafType, String name) {
            this(bpf, MapTypeId.HASH, mapId, mapFd, keyType, leafType, name);
        }

        public static final TableProvider<HashTable<@Unsigned Long, @Unsigned Long>> UINT64T_MAP_PROVIDER = (bpf, mapId, mapFd, name) -> new HashTable<>(bpf, mapId, mapFd, BPFType.BPFIntType.UINT64, BPFType.BPFIntType.UINT64, name);

        public static <K, V> TableProvider<HashTable<K, V>> createProvider(BPFType<K> keyType, BPFType<V> leafType) {
            return (bpf, mapId, mapFd, name) -> new HashTable<>(bpf, mapId, mapFd, keyType, leafType, name);
        }
    }

    public static class LruHash<K, V> extends BaseMapTable<K, V> {
        public LruHash(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> leafType, String name) {
            super(bpf, MapTypeId.LRU_HASH, mapId, mapFd, keyType, leafType, name);
        }
    }

    /**
     * Base class for all array like types, fixed size array
     */
    public abstract static class ArrayBase<K, V> extends BPFTable<K, V> implements List<V> {
        public ArrayBase(BPF bpf, MapTypeId typeId, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> leafType, String name) {
            super(bpf, typeId, mapId, mapFd, keyType, leafType, name);
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

        /**
         * Not supported, as array is fixed size
         */
        @Override
        public boolean add(V v) {
            throw new UnsupportedOperationException("Array is fixed size");
        }

        @Override
        public boolean containsAll(@NotNull Collection<?> c) {
            return values().containsAll(c);
        }

        /**
         * Not supported, as array is fixed size
         */
        @Override
        public boolean addAll(@NotNull Collection<? extends V> c) {
            throw new UnsupportedOperationException("Array is fixed size");
        }

        /**
         * Not supported, as array is fixed size
         */
        @Override
        public boolean addAll(int index, @NotNull Collection<? extends V> c) {
            throw new UnsupportedOperationException("Array is fixed size");
        }

        /**
         * Nulls all elements
         */
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

        /**
         * Not supported, as array is fixed size
         */
        @Override
        public void add(int index, V element) {
            throw new UnsupportedOperationException("Array is fixed size");
        }

        @Override
        public V remove(int index) {
            var val = get(index);
            remove((K) (Object) index);
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
            return ((Optional<Integer>) entrySet().stream().filter(e -> e.getValue().equals(o)).map(Map.Entry::getKey).findFirst()).orElse(-1);
        }

        @Override
        public int lastIndexOf(Object o) {
            var findings = entrySet().stream().filter(e -> e.getValue().equals(o)).map(Map.Entry::getKey).toArray();
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
                    ArrayBase.this.remove(currentIndex);
                }

                @Override
                public void set(V v) {
                    ArrayBase.this.set(currentIndex, v);
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

        /**
         * Not supported, as array is fixed size
         */
        @NotNull
        @Override
        public List<V> subList(int fromIndex, int toIndex) {
            throw new UnsupportedOperationException("Array is fixed size");
        }
    }

    public static class Array<K, V> extends ArrayBase<K, V> {
        public Array(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> leafType, String name) {
            super(bpf, MapTypeId.ARRAY, mapId, mapFd, keyType, leafType, name);
        }

        @Override
        public V remove(int index) {
            var val = get(index);
            set(index, null);
            return val;
        }
    }

    /**
     * array of bpf function fds
     */
    public static class ProgArray<K> extends ArrayBase<K, Integer> {
        public ProgArray(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, String name) {
            super(bpf, MapTypeId.PROG_ARRAY, mapId, mapFd, keyType, BPFType.BPFIntType.INT32, name);
        }

        public Integer set(int index, BPF.BPFFunction function) {
            return set(index, function.fd());
        }

        public static TableProvider<ProgArray<Integer>> createProvider() {
            return (bpf, mapId, mapFd, name) -> new ProgArray<>(bpf, mapId, mapFd, BPFType.BPFIntType.INT32, name);
        }
    }

    /**
         * automatically closes the file descriptor when closed
         */
        private record FileDesc(int fd) implements Closeable {
        private FileDesc {
            if (fd < 0) {
                throw new IllegalArgumentException("Invalid file descriptor");
            }
        }

            @Override
            public void close() {
                if (fd >= 0) {
                    Lib.close(fd);
                }
            }
        }

    public static class CgroupArray<K> extends ArrayBase<K, Integer> {
        public CgroupArray(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, String name) {
            super(bpf, MapTypeId.CGROUP_ARRAY, mapId, mapFd, keyType, BPFType.BPFIntType.INT32, name);
        }

        public Integer set(int index, String path) {
            // use Lib.fopen
            try (Arena arena = Arena.ofConfined()) {
                var pathInC = allocateNullOrString(arena, path);
                try (FileDesc desc = new FileDesc(Lib.open(pathInC, O_RDONLY))) {
                    return set(index, desc.fd());
                }
            }
        }
    }

    /**
     * Pollable event array, maps CPU to event fd
     * <p>
     * Assumes that cpu id == cpu index
     *
     * @param <E> event type
     */
    public static class PerfEventArray<E> extends ArrayBase<Integer, @Unsigned Integer> implements Closeable {

        public record FuncAndLostCallbacks(MemorySegment func, MemorySegment lost, perf_reader_raw_cb rawFunc,
                                           @Nullable perf_reader_lost_cb rawLost) {
        }

        @FunctionalInterface
        public interface EventCallback<E> {
            /**
             * Called when a new event is received
             *
             * @param array perf array that received the event
             * @param cpu   cpu id of the event
             * @param data  event data, use {@link PerfEventArray#event(MemorySegment)} to parse
             * @param size  size of the event data
             * @throws IOException can be thrown by the callback
             */
            void call(PerfEventArray<E> array, int cpu, MemorySegment data, int size) throws IOException;
        }

        @FunctionalInterface
        public interface LostCallback<E> {
            void call(PerfEventArray<E> array, long lost) throws IOException;
        }

        private static final AtomicInteger nextId = new AtomicInteger(0);

        private final int id = nextId.getAndIncrement();

        private final BPFType<E> eventType;
        /**
         * cpu to event fd
         */
        private final Map<Integer, Integer> openKeyFds = new HashMap<>();
        /**
         * Just there to prevent the callbacks to be garbage collected
         */
        private final Map<Integer, FuncAndLostCallbacks> callbacks = new HashMap<>();

        public PerfEventArray(BPF bpf, long mapId, int mapFd, String name, BPFType<E> eventType) {
            super(bpf, MapTypeId.PERF_EVENT_ARRAY, mapId, mapFd, BPFType.BPFIntType.INT32, BPFType.BPFIntType.UINT32, name);
            this.eventType = eventType;
        }

        @Override
        public void close() {
            for (var fd : openKeyFds.values()) {
                if (this.bpf.hasPerfBuffer(id(id))) {
                    Lib.perf_reader_free(this.bpf.getPerfBuffer(id(id)));
                    this.bpf.removePerfBuffer(id(id));
                }
            }
            openKeyFds.clear();
        }

        @Override
        public @Unsigned Integer remove(int cpu) {
            if (!openKeyFds.containsKey(cpu)) {
                return null;
            }
            // Delete entry from the array
            var ret = super.remove(cpu);
            var id = id(cpu);
            if (this.bpf.hasPerfBuffer(id)) {
                // The key is opened for perf ring buffer
                Lib.perf_reader_free(this.bpf.getPerfBuffer(id));
                this.bpf.removePerfBuffer(id);
                callbacks.remove(cpu);
            } else {
                // The key is opened for perf event read
                Lib.bpf_close_perf_event_fd(openKeyFds.get(cpu));
            }
            return ret;
        }

        public PerfEventArrayId id(int cpu) {
            return new PerfEventArrayId(id, cpu);
        }

        public record PerfEventArrayId(int id, int cpu) {
        }

        /**
         * When perf buffers are opened to receive custom perf event,
         * the underlying event data struct which is defined in C in
         * the BPF program can be deduced via this function.
         */
        public E event(MemorySegment data) {
            return eventType.parseMemory(data);
        }

        public PerfEventArray<E> open_perf_buffer(EventCallback<E> callback) {
            open_perf_buffer(callback, 8, null, 1);
            return this;
        }

        /**
         * Opens a set of per-cpu ring buffer to receive custom perf event
         * data from the bpf program. The callback will be invoked for each
         * event submitted from the kernel, up to millions per second. Use
         * page_cnt to change the size of the per-cpu ring buffer. The value
         * must be a power of two and defaults to 8.
         */
        public void open_perf_buffer(EventCallback<E> callback, int pageCnt, @Nullable LostCallback<E> lostCallback, int wakeupEvents) {
            if ((pageCnt & (pageCnt - 1)) != 0) {
                throw new IllegalArgumentException("Perf buffer page_cnt must be a power of two");
            }
            for (var cpu : Util.getOnlineCPUs()) {
                open_perf_buffer(cpu, callback, pageCnt, lostCallback, wakeupEvents);
            }
        }

        private void open_perf_buffer(int cpu, EventCallback<E> callback, int pageCnt, @Nullable LostCallback<E> lostCallback, int wakeupEvents) {

            perf_reader_raw_cb rawFn = (ctx, data, size) -> {
                try {
                    callback.call(this, cpu, data, size);
                } catch (IOException e) {
                    if (e instanceof ClosedByInterruptException) {
                        System.exit(0);
                    } else {
                        throw new RuntimeException(e);
                    }
                }
            };

            perf_reader_lost_cb rawLostFn = (ctx, lost) -> {
                try {
                    assert lostCallback != null;
                    lostCallback.call(this, lost);
                } catch (IOException e) {
                    if (e instanceof ClosedByInterruptException) {
                        System.exit(0);
                    } else {
                        throw new RuntimeException(e);
                    }
                }
            };
            try (var arena = Arena.ofConfined()) {
                var fn = perf_reader_raw_cb.allocate(rawFn, bpf.arena());
                var lostFn = lostCallback != null ? perf_reader_lost_cb.allocate(rawLostFn, bpf.arena()) : MemorySegment.NULL;
                var opts = bcc_perf_buffer_opts.allocate(arena);
                bcc_perf_buffer_opts.pid$set(opts, -1);
                bcc_perf_buffer_opts.cpu$set(opts, cpu);
                bcc_perf_buffer_opts.wakeup_events$set(opts, wakeupEvents);
                var reader = Lib.bpf_open_perf_buffer_opts(fn, lostFn, MemorySegment.NULL, pageCnt, opts);
                if (reader == null) {
                    throw new IllegalStateException("Could not open perf buffer");
                }
                var fd = Lib.perf_reader_fd(reader);
                set(cpu, fd);
                bpf.setPerfBuffer(id(cpu), reader);
                // keep a refcnt
                callbacks.put(cpu, new FuncAndLostCallbacks(fn, lostFn, rawFn, rawLostFn));
                // The actual fd is held by the perf reader, add to track opened keys
                openKeyFds.put(cpu, -1);
            }
        }

        private void open_perf_event(int cpu, int typ, int config, int pid) {
            var fd = Lib.bpf_open_perf_event(typ, config, pid, cpu);
            if (fd < 0) {
                throw new IllegalStateException("bpf_open_perf_event failed");
            }
            set(cpu, fd);
            openKeyFds.put(cpu, fd);
        }

        /**
         * Configures the table such that calls from the bpf program to
         * table.perf_read(CUR_CPU_IDENTIFIER) will return the hardware
         * counter denoted by event ev on the local cpu.
         */
        public PerfEventArray<E> open_perf_event(int typ, int config, int pid) {
            for (var cpu : Util.getOnlineCPUs()) {
                open_perf_event(cpu, typ, config, pid);
            }
            return this;
        }

        public static <E> TableProvider<PerfEventArray<E>> createProvider(BPFType<E> eventType) {
            return (bpf, mapId, mapFd, name) -> new PerfEventArray<>(bpf, mapId, mapFd, name, eventType);
        }

        public static class PerCPUHash<K, V> extends HashTable<K, List<V>> {

            private final @Nullable Function<List<V>, V> reducer;
            private final List<Integer> totalCPUs;
            private final BPFType<V> innerType;

            static <T> BPFType.BPFArrayType<T> createLeafType(BPFType<T> type, int size) {
                // Currently Float, Char, un-aligned structs are not supported
                if (type.size() == 8) {
                    return BPFType.BPFArrayType.of(type, size);
                }
                throw new AssertionError("Unaligned structs, ints, floats and chars currently not supported");
            }

            public PerCPUHash(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> innerType, String name) {
                this(bpf, mapId, mapFd, keyType, innerType, name, null);
            }

            public PerCPUHash(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> innerType, String name, @Nullable Function<List<V>, V> reducer) {
                this(bpf, MapTypeId.PERCPU_HASH, mapId, mapFd, keyType, innerType, name, reducer);
            }

            PerCPUHash(BPF bpf, MapTypeId typeId, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> innerType, String name, @Nullable Function<List<V>, V> reducer) {
                super(bpf, typeId, mapId, mapFd, keyType, createLeafType(innerType, Util.getPossibleCPUs().size()), name);
                this.reducer = reducer;
                this.totalCPUs = Util.getPossibleCPUs();
                this.innerType = innerType;
            }

            @Override
            public List<V> get(Object key) {
                return super.get(key);
            }

            public V getReduced(K key) {
                assert reducer != null;
                return reducer.apply(get(key));
            }
        }
    }

    public static class LRUPerCPUHash<K, V> extends PerfEventArray.PerCPUHash<K, V> {
        public LRUPerCPUHash(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> innerType, String name) {
            super(bpf, MapTypeId.LRU_PERCPU_HASH, mapId, mapFd, keyType, innerType, name, null);
        }

        public LRUPerCPUHash(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> innerType, String name, Function<List<V>, V> reducer) {
            super(bpf, MapTypeId.LRU_PERCPU_HASH, mapId, mapFd, keyType, innerType, name, reducer);
        }
    }

    public static class PerCPUArray<K, V> extends ArrayBase<K, List<V>> {

        private final @Nullable Function<List<V>, V> reducer;
        public PerCPUArray(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> innerType, String name, @Nullable Function<List<V>, V> reducer) {
            super(bpf, MapTypeId.PERCPU_ARRAY, mapId, mapFd, keyType, PerfEventArray.PerCPUHash.createLeafType(innerType, Util.getPossibleCPUs().size()), name);
            this.reducer = reducer;
        }

        public V getReduced(K key) {
            assert reducer != null;
            return reducer.apply(get(key));
        }
    }

    public static class LpmTrie<K, V> extends BPFTable<K, V> {
        public LpmTrie(BPF bpf, long mapId, int mapFd, BPFType<K> keyType, BPFType<V> leafType, String name) {
            super(bpf, MapTypeId.LPM_TRIE, mapId, mapFd, keyType, leafType, name);
        }
    }
}
