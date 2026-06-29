package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.ring_buffer_sample_fn;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_ringbuf_reserve;
import static me.bechberger.ebpf.shared.PanamaUtil.*;

/**
 * <a href="https://www.kernel.org/doc/html/latest/bpf/ringbuf.html">BPF ring buffer</a>
 * that allows to efficiently communicate between the eBPF program and the user space using events
 *
 * @param <E> type of the event
 *
 * <p>Note: {@code consumeRaw(...)} is <b>single-consumer</b>. The framework swaps the
 * internal callback/context fields per invocation; two concurrent {@code consumeRaw}
 * calls (with different callbacks) can race and one may observe a transient null
 * or a mismatched (cb, ctx) pair. The scheduler drain loop is single-threaded
 * by design — callers in other contexts must serialize externally.
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_RINGBUF);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFRingBuffer<E> extends BPFMap {

    /**
     * Error thrown when consuming events went wrong
     */
    public static class BPFRingBufferError extends BPFError {
        private BPFRingBufferError(String message, int errorCode) {
            super(message, errorCode);
        }

        private BPFRingBufferError(String message, List<CaughtBPFRingBufferError> caughtErrorsInCallBack) {
            super(message + ": " + caughtErrorsInCallBack.toString(), caughtErrorsInCallBack.getFirst().exception());
        }

        /**
         * Returns {@code true} when the kernel does not support BPF ring buffer consumption
         * (errno {@code EOPNOTSUPP = 95}).  This can happen on older kernels; callers that
         * want to skip the test or degrade gracefully should check this flag.
         */
        public boolean isUnsupported() {
            return getErrorCode() == ERRNO_EOPNOTSUPP;
        }
    }

    /**
     * Callback that is called when a new event is received
     *
     * @param <E> type of the event
     */
    @FunctionalInterface
    public interface EventCallback<E> {
        /**
         * Called when a new event is received
         */
        void call(BPFRingBuffer<E> buffer, E event) throws Throwable;
    }

    /**
     * Callback that is called when a new event is received
     *
     * @param <E> type of the event
     */
    @FunctionalInterface
    public interface EventCallbackWOBuffer<E> {
        /**
         * Called when a new event is received
         */
        void call(E event) throws Throwable;
    }

    private final Arena ringArena;

    private final BPFType<E> eventType;

    /**
     * Pointer to a {@code ring_buffer} struct
     */
    private final MemorySegment rb;

    private EventCallback<E> callback;

    /**
     * Second libbpf {@code ring_buffer} handle bound to the same map fd, lazily
     * constructed on the first {@link #consumeRaw} call. libbpf binds the sample
     * callback at {@code ring_buffer__new()} time, so we need a separate handle
     * for the raw-segment dispatch path; this keeps the typed {@link #consume()}
     * path unchanged.
     */
    private volatile MemorySegment rawRb = MemorySegment.NULL;
    /** Latest SegmentCallback bound to {@link #rawRb}; the trampoline reads this volatile field. */
    private volatile SegmentCallback rawCb;
    /**
     * Latest AddressCallback bound to {@link #rawRb}; preferred over {@link #rawCb} when set
     * because it avoids the {@code MemorySegment.reinterpret} on the hot path.
     */
    private volatile AddressCallback rawAddrCb;
    /** User-supplied ctx forwarded to {@link #rawCb} or {@link #rawAddrCb} on every record. */
    private volatile Object rawCtx;

    /**
     * Error caught while calling the callback
     */
    public sealed interface CaughtBPFRingBufferError {

        Throwable exception();

        /**
         * Error caught while parsing the event
         */
        record CaughtBPFRingBufferParseError(Throwable exception, MemorySegment data,
                                             long len) implements CaughtBPFRingBufferError {
        }

        /**
         * Error caught while calling the callback
         */
        record CaughtBPFRingBufferCallbackError<E>(Throwable exception, E event) implements CaughtBPFRingBufferError {
        }
    }

    private final List<CaughtBPFRingBufferError> caughtErrorsInCallBack = new ArrayList<>();

    /**
     * Create a new ring buffer
     *
     * @param fd        file descriptor of the ring buffer
     * @param eventType type of the event
     * @param callback  callback that is called when a new event is received
     * @throws BPFError if the ring buffer could not be created
     */
    public BPFRingBuffer(FileDescriptor fd, BPFType<E> eventType, EventCallback<E> callback) {
        super(MapTypeId.RINGBUF, fd);
        this.ringArena = Arena.ofShared();
        this.eventType = eventType;
        this.callback = callback;
        this.rb = initRingBuffer(fd, eventType, callback);
    }

    public BPFRingBuffer(FileDescriptor fd, BPFType<E> eventType) {
        super(MapTypeId.RINGBUF, fd);
        this.ringArena = Arena.ofShared();
        this.eventType = eventType;
        this.rb = initRingBuffer(fd, eventType, (buffer, event) -> {
            if (callback != null) {
                callback.call(buffer, event);
            }
        });
    }

    /**
     * Sets the callback if it is not already set,
     * use in combination with {@link BPFRingBuffer#BPFRingBuffer(FileDescriptor, BPFType)}
     */
    public void setCallback(EventCallback<E> callback) {
        if (this.callback != null) {
            throw new IllegalStateException("Callback already set");
        }
        this.callback = callback;
    }

    public void setCallback(EventCallbackWOBuffer<E> callback) {
        setCallback((_, event) -> callback.call(event));
    }

    private static final HandlerWithErrno<MemorySegment> RING_BUFFER_NEW = new HandlerWithErrno<>("ring_buffer__new",
            FunctionDescriptor.of(POINTER, JAVA_INT, POINTER, POINTER, POINTER));

    private static ResultAndErr<MemorySegment> ring_buffer__new(Arena arena, int fd, MemorySegment sampleFn,
                                                                MemorySegment flags, MemorySegment ctx) {
        return RING_BUFFER_NEW.call(arena, fd, sampleFn, flags, ctx);
    }

    private MemorySegment initRingBuffer(FileDescriptor fd, BPFType<E> eventType, EventCallback<E> callback) {
        ring_buffer_sample_fn.Function sample = (ctx, data, len) -> {
            E event;
            try {
                event = eventType.parseMemory(data);
            } catch (RuntimeException e) {
                addCaughtError(new CaughtBPFRingBufferError.CaughtBPFRingBufferParseError(e, data, len));
                return 0;
            }
            try {
                callback.call(this, event);
            } catch (Throwable e) {
                addCaughtError(new CaughtBPFRingBufferError.CaughtBPFRingBufferCallbackError<>(e, event));
                return 0;
            }
            return 0;
        };
        var sampleFn = ring_buffer_sample_fn.allocate(sample, ringArena);
        var rb = ring_buffer__new(ringArena, fd.fd(), sampleFn, MemorySegment.NULL, MemorySegment.NULL);
        if (rb.result() == MemorySegment.NULL) {
            throw new BPFError("Failed to create ring buffer", rb.err());
        }
        return rb.result();
    }

    private void addCaughtError(CaughtBPFRingBufferError caughtError) {
        synchronized (caughtErrorsInCallBack) {
            caughtErrorsInCallBack.add(caughtError);
        }
    }

    private static final HandlerWithErrno<Integer> ring_buffer__consume = new HandlerWithErrno<>(
            "ring_buffer__consume", FunctionDescriptor.of(ValueLayout.JAVA_INT, POINTER));

    private static final HandlerWithErrno<Integer> RING_BUFFER_POLL = new HandlerWithErrno<>(
            "ring_buffer__poll", FunctionDescriptor.of(ValueLayout.JAVA_INT, POINTER, JAVA_INT));

    private static final HandlerWithErrno<Long> RING_BUFFER_LOST_COUNT = new HandlerWithErrno<>(
            "ring_buffer__lost_count", FunctionDescriptor.of(JAVA_LONG, POINTER));

    /**
     * Result of calling the {@link BPFRingBuffer#consume() consume} method
     * @param consumed number of events consumed
     * @param caughtErrorsInCallBack list of caught errors if any
     */
    public record ConsumeResult(int consumed, List<CaughtBPFRingBufferError> caughtErrorsInCallBack) {
        public boolean hasCaughtErrors() {
            return !caughtErrorsInCallBack.isEmpty();
        }
    }

    /**
     * Polls data from the ring buffer and consumes if available.
     *
     * @return the number of events consumed (max MAX_INT) and a list of caught errors if any
     * @throws BPFRingBufferError if calling the consume method failed
     */
    public ConsumeResult consume() {
        try (Arena arena = Arena.ofConfined()) {
            var ret = ring_buffer__consume.call(arena, rb);
            ConsumeResult res;
            synchronized (caughtErrorsInCallBack) {
                res = new ConsumeResult(ret.result(), new ArrayList<>(caughtErrorsInCallBack));
                caughtErrorsInCallBack.clear();
            }
            // ring_buffer__consume returns -errno on error, >=0 on success.
            // errno is only meaningful when the return value is negative; a stale errno
            // from a prior syscall (e.g. a failed BPF_LINK_CREATE) must not be mistaken
            // for a consume error.
            if ((int) ret.result() < 0) {
                int err = ret.err();
                if (err == ERRNO_EAGAIN || err == ERRNO_EINVAL || err == ERRNO_ENOENT) {
                    return res;
                }
                throw new BPFRingBufferError("Failed to consume events", err);
            }
            return res;
        }
    }

    /**
     * Polls data from the ring buffer and consumes if available.
     *
     * @return the number of events consumed (max MAX_INT)
     * @throws BPFRingBufferError if calling the consume method failed or if any errors were caught in the call back
     */
    public int consumeAndThrow() {
        var res = consume();
        if (res.hasCaughtErrors()) {
            throw new BPFRingBufferError("Caught errors while consuming events", res.caughtErrorsInCallBack);
        }
        return res.consumed();
    }

    /**
     * Blocks until at least one event is available or {@code timeoutMs} elapses, then
     * consumes all currently available events.
     *
     * <p>Unlike {@link #consume()}, which returns immediately when no events are ready,
     * {@code poll} waits up to {@code timeoutMs} milliseconds for the kernel to wake the
     * listener.  A timeout of {@code 0} makes it equivalent to {@link #consume()}.
     *
     * @param timeoutMs maximum milliseconds to wait; {@code -1} to wait indefinitely
     * @return the number of events consumed and any errors caught in callbacks
     * @throws BPFRingBufferError if the underlying {@code ring_buffer__poll} call fails
     */
    public ConsumeResult poll(int timeoutMs) {
        try (Arena arena = Arena.ofConfined()) {
            var ret = RING_BUFFER_POLL.call(arena, rb, timeoutMs);
            ConsumeResult res;
            synchronized (caughtErrorsInCallBack) {
                res = new ConsumeResult(ret.result(), new ArrayList<>(caughtErrorsInCallBack));
                caughtErrorsInCallBack.clear();
            }
            if ((int) ret.result() < 0) {
                int err = ret.err();
                if (err == ERRNO_EAGAIN || err == ERRNO_EINVAL || err == ERRNO_ENOENT) {
                    return res;
                }
                throw new BPFRingBufferError("Failed to poll ring buffer", err);
            }
            return res;
        }
    }

    /**
     * Returns the number of events that were dropped because the ring buffer was full
     * when the BPF program tried to reserve space.
     *
     * <p>The counter is maintained by the kernel per ring buffer map fd and is never
     * reset; callers that want a delta should record the previous value themselves.
     *
     * @return cumulative count of lost events since the ring buffer was created
     */
    public long lostCount() {
        try (Arena arena = Arena.ofConfined()) {
            var ret = RING_BUFFER_LOST_COUNT.call(arena, rb);
            return ret.result();
        }
    }

    /**
     * Drains all currently available events from the ring buffer into a list.
     * <p>
     * This method temporarily replaces the ring buffer's callback with a
     * list-collecting callback, calls {@link #consume()}, then restores the
     * original callback.  It is therefore only compatible with ring buffers
     * constructed via {@link #BPFRingBuffer(FileDescriptor, BPFType)} (the
     * deferred-callback constructor) — using it on a ring buffer whose
     * callback was baked into {@link #initRingBuffer} will silently return an
     * empty list because the native callback bypasses {@code this.callback}.
     *
     * @return snapshot list of events drained in this call
     * @throws BPFRingBufferError if the underlying consume fails
     */
    public List<E> drainToList() {
        List<E> collected = new ArrayList<>();
        EventCallback<E> saved = this.callback;
        this.callback = (_, event) -> collected.add(event);
        try {
            consumeAndThrow();
        } finally {
            this.callback = saved;
        }
        return collected;
    }

    /**
     * Returns a {@link Stream} of all events currently available in the ring buffer.
     * <p>
     * Internally delegates to {@link #drainToList()}; see that method for
     * compatibility notes.
     *
     * @return stream of drained events
     */
    public Stream<E> stream() {
        return drainToList().stream();
    }

    /**
     * Drain the ring buffer without materialising records into Java objects.
     *
     * <p>Each available record is delivered to {@code cb} as an unmaterialised
     * {@link MemorySegment} view (zero-copy, zero per-record heap allocation).
     * The callee reads only the fields it cares about via
     * {@link java.lang.foreign.ValueLayout}/VarHandle.
     *
     * <p>This is intentionally a separate code path from {@link #consume()}:
     * libbpf binds the sample callback at {@code ring_buffer__new()} time, so
     * the typed callback used by {@link #initRingBuffer} cannot be swapped per
     * call. We lazily build a second {@code ring_buffer} handle ({@link #rawRb})
     * on the first invocation, bound to a trampoline that reads the latest
     * {@link SegmentCallback} from a {@code volatile} field. Subsequent calls
     * just update the field and invoke {@code ring_buffer__consume} on
     * {@link #rawRb}; allocations on the hot path are zero.
     *
     * <p>{@link #consume()}, {@link #poll(int)}, and the typed callback path
     * continue to work concurrently and independently of this method.
     *
     * @param cb  the callback to invoke per record. Return {@code 0} to keep
     *            consuming, non-zero to stop early (matches libbpf's
     *            {@code ring_buffer_sample_fn} contract).
     * @param ctx user context forwarded to {@code cb} on every record; may be
     *            {@code null}.
     * @return the number of records consumed, or a negative value when libbpf
     *         reports a non-recoverable error.
     * @throws BPFRingBufferError if the second ring buffer handle could not be
     *         created or the underlying consume call failed non-trivially.
     * @implNote This method is <b>single-consumer</b>; see the class-level note on
     *         {@code consumeRaw} for the concurrency contract.
     */
    public int consumeRaw(SegmentCallback cb, Object ctx) {
        // Update before kicking off the consume so the trampoline picks up the
        // latest callback even on the very first dispatch.
        this.rawAddrCb = null;  // clear the fast path so trampoline falls back to SegmentCallback
        this.rawCb = cb;
        this.rawCtx = ctx;
        if (rawRb == MemorySegment.NULL) {
            initRawRingBuffer();
        }
        try (Arena arena = Arena.ofConfined()) {
            var ret = ring_buffer__consume.call(arena, rawRb);
            if ((int) ret.result() < 0) {
                int err = ret.err();
                if (err == ERRNO_EAGAIN || err == ERRNO_EINVAL || err == ERRNO_ENOENT) {
                    return ret.result();
                }
                throw new BPFRingBufferError("Failed to consume raw events", err);
            }
            return ret.result();
        }
    }

    /**
     * Drain the ring buffer without materialising records into Java objects or
     * even creating a transient {@link java.lang.foreign.MemorySegment}.
     *
     * <p>Each available record is delivered to {@code cb} as a raw native address
     * ({@code long}) and its length. This avoids the {@code MemorySegment.reinterpret}
     * call present in the {@link #consumeRaw(SegmentCallback, Object)} path, cutting
     * per-record allocation to near zero and making it suitable for scheduler hot paths.
     *
     * <p>Shares the lazily created {@link #rawRb} handle with
     * {@link #consumeRaw(SegmentCallback, Object)}. When this overload is active,
     * the trampoline skips the {@code reinterpret} branch entirely.
     *
     * @param cb  the callback to invoke per record. Return {@code 0} to keep
     *            consuming, non-zero to stop early (matches libbpf's
     *            {@code ring_buffer_sample_fn} contract).
     * @param ctx user context forwarded to {@code cb} on every record; may be
     *            {@code null}.
     * @return the number of records consumed, or a negative value when libbpf
     *         reports a non-recoverable error.
     * @throws BPFRingBufferError if the second ring buffer handle could not be
     *         created or the underlying consume call failed non-trivially.
     * @implNote This method is <b>single-consumer</b>; see the class-level note on
     *         {@code consumeRaw} for the concurrency contract.
     */
    public int consumeRaw(AddressCallback cb, Object ctx) {
        // Set the fast-path callback first; trampoline will prefer rawAddrCb over rawCb.
        this.rawAddrCb = cb;
        this.rawCb = null;  // clear SegmentCallback so trampoline won't fall back to it
        this.rawCtx = ctx;
        if (rawRb == MemorySegment.NULL) {
            initRawRingBuffer();
        }
        try (Arena arena = Arena.ofConfined()) {
            var ret = ring_buffer__consume.call(arena, rawRb);
            if ((int) ret.result() < 0) {
                int err = ret.err();
                if (err == ERRNO_EAGAIN || err == ERRNO_EINVAL || err == ERRNO_ENOENT) {
                    return ret.result();
                }
                throw new BPFRingBufferError("Failed to consume raw events", err);
            }
            return ret.result();
        }
    }

    /**
     * Lazily build {@link #rawRb}. Synchronized to ensure exactly one handle
     * is created even under concurrent first-call races.
     */
    private synchronized void initRawRingBuffer() {
        if (rawRb != MemorySegment.NULL) {
            return;
        }
        // Trampoline bridges libbpf's int(*)(void*ctx, void*data, size_t size)
        // to AddressCallback.apply (fast path, no reinterpret) or SegmentCallback.apply
        // (fallback), reading the latest cb/ctx from volatile fields so callers can
        // swap them between consumeRaw calls without tearing down the libbpf handle.
        //
        // Priority: rawAddrCb (set) → call apply(address, len, ctx) with zero allocation.
        //           rawCb (set)     → reinterpret data to len bytes, call apply(segment, len, ctx).
        //
        // The {@code data} segment is delivered by Panama as a zero-sized
        // address-only segment (the underlying libbpf descriptor has no
        // target layout). We re-interpret it to {@code len} bytes so the
        // SegmentCallback can read fields directly. HotSpot is expected to scalarise
        // the transient segment header for fast-path callees that do not
        // capture {@code record} across the callback boundary.
        ring_buffer_sample_fn.Function trampoline = (ringCtx, data, len) -> {
            Object userCtx = this.rawCtx;
            AddressCallback addrCb = this.rawAddrCb;
            if (addrCb != null) {
                // Fast path: pass native address directly — no MemorySegment allocation.
                try {
                    return addrCb.apply(data.address(), len, userCtx);
                } catch (Throwable t) {
                    addCaughtError(new CaughtBPFRingBufferError.CaughtBPFRingBufferParseError(t, data, len));
                    return 0;
                }
            }
            SegmentCallback cb = this.rawCb;
            if (cb == null) {
                return 0;
            }
            try {
                MemorySegment record = data.reinterpret(len);
                return cb.apply(record, len, userCtx);
            } catch (Throwable t) {
                addCaughtError(new CaughtBPFRingBufferError.CaughtBPFRingBufferParseError(t, data, len));
                return 0;
            }
        };
        var sampleFn = ring_buffer_sample_fn.allocate(trampoline, ringArena);
        var rawNew = ring_buffer__new(ringArena, getFd().fd(), sampleFn, MemorySegment.NULL, MemorySegment.NULL);
        if (rawNew.result() == MemorySegment.NULL) {
            throw new BPFRingBufferError("Failed to create raw ring buffer", rawNew.err());
        }
        this.rawRb = rawNew.result();
    }

    @Override
    public void close() {
        Lib.ring_buffer__free(rb);
        if (rawRb != MemorySegment.NULL) {
            Lib.ring_buffer__free(rawRb);
        }
        ringArena.close();
        super.close();
    }

    /**
     * Reserve and return a slot in the ring buffer, or {@code null} if the ring buffer is full
     * <p>
     * Be sure to check if the return value is {@code null} before submitting the event.
     * <p>
     * <b>Every event has to be either submitted ({@link #submit(Ptr)}) or discarded ({@link #discard(Ptr)})</b>
     * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_ringbuf_reserve(Ptr, long, long)
     */
    @BuiltinBPFFunction("bpf_ringbuf_reserve(&$this, sizeof($C1), 0)")
    @NotUsableInJava
    public Ptr<E> reserve() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Discard a reserved event
     *
     * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_ringbuf_discard(Ptr, long)
     */
    @BuiltinBPFFunction("bpf_ringbuf_discard($arg1, 0)")
    @NotUsableInJava
    public void discard(Ptr<E> event) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Submit an event to the ring buffer, be sure to obtain it via {@link BPFRingBuffer#reserve() reserve} first
     *
     * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_ringbuf_submit(Ptr, long)
     */
    @BuiltinBPFFunction("bpf_ringbuf_submit($arg1, 0)")
    @NotUsableInJava
    public void submit(Ptr<E> event) {
        throw new MethodIsBPFRelatedFunction();
    }
}