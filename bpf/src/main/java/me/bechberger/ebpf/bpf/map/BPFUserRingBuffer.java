package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
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
     * BPF-side: reserve a slot in the ring buffer. Lowered by the plugin to
     * {@code bpf_ringbuf_reserve}; not callable from Java.
     *
     * <p>The user-space producer side (Java {@code reserve}/{@code submit}) is
     * introduced in Task 1 as separate Java methods.
     */
    @BuiltinBPFFunction("bpf_ringbuf_reserve(&$this, sizeof($C1), 0)")
    @NotUsableInJava
    public Ptr<E> reserve() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * BPF-side: submit a reserved entry. Lowered by the plugin to
     * {@code bpf_ringbuf_submit}; not callable from Java.
     */
    @BuiltinBPFFunction("bpf_ringbuf_submit($arg1, 0)")
    @NotUsableInJava
    public void submit(Ptr<E> ptr) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * BPF-side: discard a reserved entry. Lowered by the plugin to
     * {@code bpf_ringbuf_discard}; not callable from Java.
     */
    @BuiltinBPFFunction("bpf_ringbuf_discard($arg1, 0)")
    @NotUsableInJava
    public void discard(Ptr<E> ptr) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Drain entries from the user ring buffer into a typed BPF callback.
     *
     * <p>Maps to {@code bpf_user_ringbuf_drain}.  The compiler plugin lowers
     * the lambda into a C thunk with signature
     * {@code int thunk(struct bpf_dynptr *dynptr, void *ctx)} that:
     * <ol>
     *   <li>stack-allocates an {@code E} record;</li>
     *   <li>reads {@code sizeof(E)} bytes from the dynptr via
     *       {@code bpf_dynptr_read};</li>
     *   <li>forwards {@code &record} and {@code ctx} to the user lambda body.</li>
     * </ol>
     *
     * <p>Return {@code 0} from the callback to continue draining, {@code 1} to
     * stop (matches libbpf's {@code bpf_user_ringbuf_callback_fn} contract).
     * If a {@code bpf_dynptr_read} fails for a record, the generated thunk
     * returns {@code 1} — i.e. <strong>the entire drain batch aborts on the
     * first malformed entry</strong>. There is no in-band way to skip a single
     * record under the libbpf ABI.
     *
     * @param <Ctx>    type of the opaque context pointer
     * @param callback typed drain callback — receives a pointer to the decoded record
     * @param ctx      context pointer forwarded to each callback invocation
     * @return number of entries drained, or a negative error code
     */
    @BuiltinBPFFunction("bpf_user_ringbuf_drain(&$this, $func1:dynptr, $arg2, 0)")
    public <Ctx> int drain(BPFUserRingbufCallback<E, Ctx> callback, Ptr<Ctx> ctx) {
        throw new MethodIsBPFRelatedFunction();
    }
}
