package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.MemorySegment;

/**
 * Typed Java wrapper for {@code BPF_MAP_TYPE_USER_RINGBUF} — the user→kernel
 * ringbuf used by user-space producers to submit entries that the BPF program
 * consumes via {@code bpf_user_ringbuf_drain}.  This is the inverse of
 * {@link BPFRingBuffer}: data flows <em>from</em> user space <em>to</em> the
 * kernel/BPF program.
 *
 * <h3>Producer API (Java / user-space side)</h3>
 * <ol>
 *   <li>Call {@link #reserve()} to claim a slot of {@code sizeof(E)} bytes.
 *       Returns {@code null} if the buffer is full.</li>
 *   <li>Write the record into the returned {@link MemorySegment} (which is a
 *       direct view into the ring-buffer's shared memory).</li>
 *   <li>Call {@link #submit(MemorySegment)} to commit the slot and wake the
 *       BPF consumer, <em>or</em> {@link #discard(MemorySegment)} to abandon
 *       it without making it visible.</li>
 * </ol>
 *
 * <h3>Consumer API (BPF side)</h3>
 * Use {@link #drain} in your BPF program — the compiler plugin lowers it to
 * {@code bpf_user_ringbuf_drain}.
 *
 * <p><strong>Single-thread per buffer.</strong> The libbpf user-ring-buffer
 * implementation is not thread-safe on the producer path; callers must
 * serialise {@link #reserve}/{@link #submit}/{@link #discard} externally.
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
    /** Pointer to the libbpf {@code user_ring_buffer} struct. */
    private final MemorySegment urb;

    /**
     * Create a new user ring buffer handle.
     *
     * @param fd          file descriptor of the map
     * @param elementType BPF type descriptor for {@code E}
     * @throws BPFError if {@code user_ring_buffer__new} fails
     */
    public BPFUserRingBuffer(FileDescriptor fd, BPFType<E> elementType) {
        super(MapTypeId.USER_RINGBUF, fd);
        this.elementType = elementType;
        MemorySegment handle = Lib.user_ring_buffer__new(fd.fd(), MemorySegment.NULL);
        if (handle == null || handle.address() == 0) {
            throw new BPFError("user_ring_buffer__new failed for fd " + fd.fd(), -1);
        }
        this.urb = handle;
    }

    /**
     * Reserve a slot of {@code sizeof(E)} bytes in the ring buffer.
     *
     * <p>Returns a {@link MemorySegment} pointing directly into the ring
     * buffer's shared memory region, already sized to {@code sizeof(E)}.
     * The segment MUST be either {@link #submit submitted} or
     * {@link #discard discarded} before the next call on this thread.
     *
     * @return a writable memory segment for the reserved slot, or {@code null}
     *         if the buffer is full
     */
    public MemorySegment reserve() {
        long size = elementType.size();
        if (size > Integer.MAX_VALUE) {
            throw new BPFError("element size " + size + " exceeds Integer.MAX_VALUE", -1);
        }
        MemorySegment slot = Lib.user_ring_buffer__reserve(urb, (int) size);
        if (slot == null || slot.address() == 0) return null;
        return slot.reinterpret(size);
    }

    /**
     * Commit a previously {@link #reserve reserved} slot and wake the BPF consumer.
     *
     * @param slot the segment returned by {@link #reserve()}
     */
    public void submit(MemorySegment slot) {
        Lib.user_ring_buffer__submit(urb, slot);
    }

    /**
     * Abandon a previously {@link #reserve reserved} slot without making it
     * visible to the BPF consumer.
     *
     * @param slot the segment returned by {@link #reserve()}
     */
    public void discard(MemorySegment slot) {
        Lib.user_ring_buffer__discard(urb, slot);
    }

    @Override
    public void close() {
        Lib.user_ring_buffer__free(urb);
        super.close();
    }

    /**
     * BPF-side drain: consumes records from the ring buffer and invokes
     * {@code callback} for each. The compiler plugin lowers this to
     * {@code bpf_user_ringbuf_drain}.  The callback receives a pointer to a
     * stack-allocated {@code E} populated via {@code bpf_dynptr_read}.
     *
     * <p>Return {@code 0} from the callback to continue draining, {@code 1}
     * to stop early (matches libbpf's {@code bpf_user_ringbuf_callback_fn}
     * contract).
     *
     * @param <Ctx>    type of the opaque context pointer
     * @param callback typed drain callback — receives a pointer to the decoded
     *                 record
     * @param ctx      context pointer forwarded to each callback invocation
     * @return number of entries drained, or a negative error code
     */
    @BuiltinBPFFunction("bpf_user_ringbuf_drain(&$this, $func1:dynptr, $arg2, 0)")
    public <Ctx> int drain(BPFUserRingbufCallback<E, Ctx> callback, Ptr<Ctx> ctx) {
        throw new MethodIsBPFRelatedFunction();
    }
}
