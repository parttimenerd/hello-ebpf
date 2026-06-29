package me.bechberger.ebpf.bpf.map;

/**
 * Low-level zero-allocation ring-buffer callback. {@link #apply} receives the
 * raw native address of the record and its length — the callee is expected to
 * wrap it into a {@link java.lang.foreign.MemorySegment} ONCE outside the
 * drain loop (using {@code MemorySegment.ofAddress(addr).reinterpret(size)})
 * or to read via Panama VarHandles bound to a fixed layout.
 *
 * <p>Use this for the scheduler hot path. Use {@link SegmentCallback} when
 * the per-record reinterpret cost (~100 B/record) is acceptable.
 *
 * <p>Return 0 to continue, non-zero to stop (matches libbpf's
 * {@code ring_buffer_sample_fn} contract).
 */
@FunctionalInterface
public interface AddressCallback {
    int apply(long address, long size, Object ctx);
}
