package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.type.BPFType;

/**
 * A LIFO stack
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_STACK);
            __type (value, $c1);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFStack<V> extends BPFQueueAndStack<V> {

    public BPFStack(FileDescriptor fd, BPFType<V> valueType) {
        super(fd, MapTypeId.STACK, valueType);
    }
}
