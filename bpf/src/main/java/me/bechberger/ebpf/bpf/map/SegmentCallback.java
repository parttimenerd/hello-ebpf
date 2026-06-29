package me.bechberger.ebpf.bpf.map;

import java.lang.foreign.MemorySegment;

/**
 * Zero-deserialisation ring-buffer callback. The framework drains records by
 * invoking {@link #apply} with the raw {@link MemorySegment} view of one
 * record — the callee reads only the fields it cares about via
 * {@link java.lang.foreign.ValueLayout} / VarHandle. No intermediate POJO is
 * allocated.
 *
 * <p>Return 0 to continue consuming, non-zero to stop early (matches
 * libbpf's {@code ring_buffer_sample_fn} contract).
 */
@FunctionalInterface
public interface SegmentCallback {
    int apply(MemorySegment record, long size, Object ctx);
}
