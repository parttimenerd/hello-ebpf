package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.type.BPFType;

/**
 * A FIFO queue
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_QUEUE);
            __type (value, $c1);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFQueue<V> extends BPFQueueAndStack<V> {

    public BPFQueue(FileDescriptor fd, BPFType<V> valueType) {
        super(fd, MapTypeId.QUEUE, valueType);
    }
}
