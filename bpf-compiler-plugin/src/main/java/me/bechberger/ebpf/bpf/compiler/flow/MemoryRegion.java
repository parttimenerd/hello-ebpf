package me.bechberger.ebpf.bpf.compiler.flow;

/**
 * Memory region lattice for tracking pointer provenance in BPF programs.
 *
 * <p>Ordering (bottom → top): {@code UNKNOWN < USER, KERNEL, PACKET, MAP_VALUE, STACK}.
 * Mixing regions without an explicit cast is an error.
 *
 * <p>Sources:
 * <ul>
 *   <li>{@link #USER}: syscall tracepoint arguments (e.g. {@code filename} in openat)</li>
 *   <li>{@link #KERNEL}: task_struct, kernel data structures</li>
 *   <li>{@link #PACKET}: xdp_md.data, sk_buff.data — must be bounds-checked before access</li>
 *   <li>{@link #MAP_VALUE}: pointer returned from a BPF map lookup</li>
 *   <li>{@link #STACK}: local variables, struct copies on the BPF stack</li>
 *   <li>{@link #UNKNOWN}: unresolved / not yet inferred</li>
 * </ul>
 */
public enum MemoryRegion implements Lattice<MemoryRegion> {
    USER,
    KERNEL,
    PACKET,
    MAP_VALUE,
    STACK,
    UNKNOWN;

    @Override
    public MemoryRegion bottom() {
        return UNKNOWN;
    }

    /**
     * Join: if both values are identical, return that value. Otherwise return {@code UNKNOWN}
     * (mixing regions is unsafe — the caller must insert an explicit cast).
     */
    @Override
    public MemoryRegion join(MemoryRegion a, MemoryRegion b) {
        if (a == b) return a;
        return UNKNOWN;
    }

    /** True if dereferencing a pointer of this region requires {@code bpf_probe_read_user}. */
    public boolean requiresUserRead() {
        return this == USER;
    }

    /** True if dereferencing requires {@code bpf_probe_read_kernel} (unverifier-tracked pointer). */
    public boolean requiresKernelRead() {
        return this == KERNEL;
    }
}
