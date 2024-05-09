package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.BPFType.BPFIntType;

import java.util.Iterator;
import java.util.List;
import java.util.Spliterator;
import java.util.concurrent.atomic.AtomicInteger;
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

    public void set(int i, V value) {
        put(i, value);
    }

    /** Copy as many values as possible */
    public void copy(Iterable<V> values) {
        AtomicInteger index = new AtomicInteger(-1);
        StreamSupport.stream(values.spliterator(), false).limit(size)
                .forEach(v -> put(index.incrementAndGet(), v));
    }
}
