package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.BPFType.BPFIntType;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/** eBPF array map */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_ARRAY);
            __type (key, u32);
            __type (value, $c1);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $maxEntries)
        """)
public class BPFArray<V> extends BPFBaseMap<@Unsigned Integer, V> {

    private final int size;

    public BPFArray(FileDescriptor fd, BPFType<V> valueType, int size) {
        super(fd, MapTypeId.ARRAY, BPFIntType.UINT32, valueType.alignTo(8));
        this.size = size;
    }

    public int size() {
        return size;
    }

    @Override
    public V get(Integer i) {
        if (i < size) {
            return super.get(i);
        }
        throw new ArrayIndexOutOfBoundsException("Index " + i +
                " is out of bounds of array with size " + size);
    }

    @Override
    @BuiltinBPFFunction("!bpf_map_update_elem(&$this, $pointery$arg1, $pointery$arg2, BPF_ANY)")
    public boolean put(Integer i, V value) {
        if (i < 0 || i >= size) {
            throw new ArrayIndexOutOfBoundsException("Index " + i +
                    " is out of bounds of array with size " + size);
        }
        return super.put(i, value);
    }

    public void set(int i, V value) {
        put(i, value);
    }

    /** Copy as many values as possible */
    public void copy(Iterable<V> values) {
        AtomicInteger index = new AtomicInteger(-1);
        StreamSupport.stream(values.spliterator(), false).limit(size)
                .forEach(v -> put(index.incrementAndGet(), v));
    }

    /**
     * Returns all values in the array as a list, in index order.
     */
    public List<V> toList() {
        List<V> result = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            result.add(get(i));
        }
        return result;
    }

    /**
     * Calls {@code action} for each value in the array, in index order.
     */
    public void forEachValue(Consumer<V> action) {
        for (int i = 0; i < size; i++) {
            action.accept(get(i));
        }
    }

    /**
     * Returns a sequential stream over the array values, in index order.
     */
    public Stream<V> valueStream() {
        return StreamSupport.stream(valueSpliterator(), false);
    }

    /**
     * Returns a spliterator over the array values.
     */
    public Spliterator<V> valueSpliterator() {
        return new Spliterator<V>() {
            int index = 0;

            @Override
            public boolean tryAdvance(Consumer<? super V> action) {
                if (index < size) {
                    action.accept(get(index++));
                    return true;
                }
                return false;
            }

            @Override
            public Spliterator<V> trySplit() { return null; }

            @Override
            public long estimateSize() { return size - index; }

            @Override
            public int characteristics() {
                return ORDERED | SIZED | SUBSIZED | IMMUTABLE;
            }
        };
    }
}
