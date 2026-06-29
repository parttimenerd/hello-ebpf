package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

/**
 * User ring buffer (user→kernel direction) — typed wrapper.
 *
 * <p>The BPF program uses {@code bpf_user_ringbuf_drain} to consume entries
 * that user space has previously written into the ring buffer.  This is the
 * inverse of {@link BPFRingBuffer}: data flows <em>from</em> user space
 * <em>to</em> the kernel/BPF program.
 *
 * <p>Full implementation (reserve/submit/discard on the Java/user-space side)
 * is in Task 1.  This stub provides enough for the compiler plugin to emit the
 * correct C map definition.
 *
 * @param <E> type of the entries written by user space
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
            __uint(max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFUserRingBuffer<E> extends BPFMap {

    private final BPFType<E> elementType;

    /**
     * Create a new user ring buffer handle.
     *
     * @param fd          file descriptor of the map
     * @param elementType BPF type descriptor for {@code E}
     */
    public BPFUserRingBuffer(FileDescriptor fd, BPFType<E> elementType) {
        super(MapTypeId.USER_RINGBUF, fd);
        this.elementType = elementType;
    }

    /**
     * Reserve a slot in the ring buffer (BPF-side no-op stub; full impl in Task 1).
     */
    @BuiltinBPFFunction("bpf_ringbuf_reserve(&$this, sizeof($C1), 0)")
    public Ptr<E> reserve() {
        throw new UnsupportedOperationException("BPFUserRingBuffer.reserve() not yet implemented (Task 1)");
    }

    /**
     * Submit a reserved entry (BPF-side no-op stub; full impl in Task 1).
     */
    @BuiltinBPFFunction("bpf_ringbuf_submit($arg1, 0)")
    public void submit(Ptr<E> ptr) {
        throw new UnsupportedOperationException("BPFUserRingBuffer.submit() not yet implemented (Task 1)");
    }

    /**
     * Discard a reserved entry (BPF-side no-op stub; full impl in Task 1).
     */
    @BuiltinBPFFunction("bpf_ringbuf_discard($arg1, 0)")
    public void discard(Ptr<E> ptr) {
        throw new UnsupportedOperationException("BPFUserRingBuffer.discard() not yet implemented (Task 1)");
    }

    /**
     * Drain entries from the user ring buffer into a BPF callback.
     *
     * <p>Maps to {@code bpf_user_ringbuf_drain} which iterates over entries
     * the user-space producer has committed, calling {@code callback} for each.
     *
     * @param callback BPF callback function
     * @param ctx      opaque context pointer passed to the callback
     * @return number of entries drained, or a negative error code
     */
    @BuiltinBPFFunction("bpf_user_ringbuf_drain(&$this, $arg1, $arg2, 0)")
    public int drain(Object callback, Ptr<?> ctx) {
        throw new MethodIsBPFRelatedFunction();
    }
}
