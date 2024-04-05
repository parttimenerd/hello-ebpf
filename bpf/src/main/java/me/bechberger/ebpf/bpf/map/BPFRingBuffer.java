package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.ring_buffer_sample_fn;
import me.bechberger.ebpf.type.BPFType;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static me.bechberger.ebpf.shared.PanamaUtil.*;

/**
 * <a href="https://www.kernel.org/doc/html/latest/bpf/ringbuf.html">BPF ring buffer</a>
 * that allows to efficiently communicate between the eBPF program and the user space using events
 *
 * @param <E> type of the event
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
        void call(me.bechberger.ebpf.bpf.map.BPFRingBuffer<E> buffer, E event) throws Throwable;
    }

    private final Arena ringArena;

    private final BPFType<E> eventType;

    /**
     * Pointer to a {@code ring_buffer} struct
     */
    private final MemorySegment rb;

    private EventCallback<E> callback;

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
     *^
     * @param fd        file descriptor of the ring buffer
     * @param eventType type of the event
     * @param callback  callback that is called when a new event is received
     * @throws BPFError if the ring buffer could not be created
     */
    public BPFRingBuffer(FileDescriptor fd, BPFType<E> eventType, EventCallback<E> callback) {
        super(MapTypeId.RINGBUF, fd);
        this.ringArena = Arena.ofConfined();
        this.eventType = eventType;
        this.callback = callback;
        this.rb = initRingBuffer(fd, eventType, callback);
    }

    public BPFRingBuffer(FileDescriptor fd, BPFType<E> eventType) {
        super(MapTypeId.RINGBUF, fd);
        this.ringArena = Arena.ofConfined();
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
            if (ret.err() != 0) {
                if (ret.err() == ERRNO_EAGAIN) {
                    // this is not an error, just no events available
                    return res;
                }
                if (ret.err() == ERRNO_EINVAL) {
                    return res; // don't know why this happens, but it does
                }
                if (ret.err() == 2) {
                    return res;
                }
                throw new BPFRingBufferError("Failed to consume events", ret.err());
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

    @Override
    public void close() {
        System.out.println("Closing ring buffer");
        Lib.ring_buffer__free(rb);
        ringArena.close();
        super.close();
    }
}