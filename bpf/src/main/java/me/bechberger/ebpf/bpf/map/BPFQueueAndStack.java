package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Objects;

/**
 * "BPF_MAP_TYPE_QUEUE provides FIFO storage and BPF_MAP_TYPE_STACK provides
 * LIFO storage for BPF programs. These maps support peek, pop and push operations
 * that are exposed to BPF programs through the respective helpers."
 * <a href="https://docs.kernel.org/next/bpf/map_queue_stack.html">docs.kernel.org</a>
 */
public abstract class BPFQueueAndStack<V> extends BPFMap {

    private final BPFType<V> valueType;

    /**
     * Create a new map
     *
     * @param mapType type of the map
     * @param fd     file descriptor of the map
     * @throws BPFMapTypeMismatch if the type of the map does not match the expected type
     */
    BPFQueueAndStack(FileDescriptor fd, MapTypeId mapType, BPFType<V> valueType) {
        super(mapType, fd);
        if (mapType != MapTypeId.STACK && mapType != MapTypeId.QUEUE) {
            throw new BPFError("Map type must be either STACK or QUEUE, but got " + mapType);
        }
        this.valueType = valueType;
    }

    /**
     * Push a value onto the stack or the back of the queue
     * <p>Usage in ebpf:</p>
     * Update the value in the map with the given key
     * @param value value if pointery, otherwise an lvalue (like a variable)
     * @return success?
     * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_map_update_elem(Ptr, Ptr, Ptr, long)
     */
    @BuiltinBPFFunction("!bpf_map_push_elem(&$this, $pointery$arg1, BPF_ANY)")
    public boolean push(V value) {
        try (var arena = Arena.ofConfined()) {
            var valueSegment = valueType.allocate(arena, Objects.requireNonNull(value));
            var ret = Lib.bpf_map_update_elem(fd.fd(), MemorySegment.NULL, valueSegment, Lib_2.BPF_ANY());
            return ret == 0;
        }
    }

    // long bpf_map_peek_elem(struct bpf_map *map, void *value)
    /**
     * Peek at the value at the top of the stack or the front of the queue
     */
    @BPFFunctionAlternative("bpf_peek")
    public @Nullable V peek() {
        try (var arena = Arena.ofConfined()) {
            var valueSegment = valueType.allocate(arena);
            var ret = Lib.bpf_map_lookup_elem(fd.fd(), MemorySegment.NULL, valueSegment);
            if (ret != 0) {
                return null;
            }
            return valueType.parseMemory(valueSegment);
        }
    }

    /**
     * Get the value from the top of the stack or the front of the queue, in eBPF
     *
     * @param value value if pointery, otherwise an lvalue (like a variable)
     * @return true if the value was peeked, false on error
     * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_map_peek_elem(Ptr, Ptr)
     */
    @BuiltinBPFFunction("!bpf_map_peek_elem(&$this, $pointery$arg1)")
    public boolean bpf_peek(V value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Pop the value from the top of the stack or the front of the queue
     *
     * @return the value, or null if the stack/queue is empty
     */
    @BPFFunctionAlternative("pop")
    public @Nullable V pop() {
        try (var arena = Arena.ofConfined()) {
            var valueSegment = valueType.allocate(arena);
            var ret = Lib.bpf_map_lookup_and_delete_elem(fd.fd(), MemorySegment.NULL, valueSegment);
            if (ret != 0) {
                return null;
            }
            return valueType.parseMemory(valueSegment);
        }
    }

    /**
     * Pop the value from the top of the stack or the front of the queue, in eBPF
     *
     * @param value value if pointery, otherwise an lvalue (like a variable)
     * @return true if the value was popped, false on error
     * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_map_pop_elem(Ptr, Ptr)
     */
    @BuiltinBPFFunction("!bpf_map_pop_elem(&$this, $pointery$arg1)")
    public boolean bpf_pop(V value) {
        throw new MethodIsBPFRelatedFunction();
    }
}
