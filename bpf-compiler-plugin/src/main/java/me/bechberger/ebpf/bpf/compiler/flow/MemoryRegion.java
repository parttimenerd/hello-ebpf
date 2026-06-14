package me.bechberger.ebpf.bpf.compiler.flow;

/**
 * Memory-region lattice for BPF pointer provenance.
 *
 * <p>Refined per the unified type-system plan: {@code KERNEL} splits into
 * {@link #KERNEL_TRACKED} (verifier-traced; direct {@code ->} access allowed) and
 * {@link #KERNEL_UNTRACKED} (BTF chain or cast — needs {@code bpf_probe_read_kernel}).
 *
 * <p>The lattice forms a flat region taxonomy with {@link #UNKNOWN} as bottom and a synthetic
 * {@link #CONFLICT} as top — the latter signals incompatible joins (e.g. USER ∪ KERNEL_TRACKED)
 * so callers can produce a {@code region.mixing} diagnostic instead of silently degrading to
 * {@code UNKNOWN}.
 *
 * <p>Sources (full table in plan §"Seed table"):
 * <ul>
 *   <li>{@link #USER}: syscall-arg {@code String}/{@code Ptr}, {@code @Uprobe} arg,
 *       {@code @BPFUserMemory}</li>
 *   <li>{@link #KERNEL_TRACKED}: {@code xdp_md.data}, {@code __sk_buff.data}, verifier-traced
 *       {@code task_struct} fields, hook-interface contexts</li>
 *   <li>{@link #KERNEL_UNTRACKED}: {@code bpf_get_current_task()} chains, raw BTF pointer
 *       casts, {@code @BPFKernelMemory}</li>
 *   <li>{@link #PACKET}: {@code xdp_md.data}/{@code data_end} — bounds-checked separately</li>
 *   <li>{@link #MAP_VALUE}: {@code bpf_map_lookup_elem} / {@code BPFHashMap.bpf_get} return</li>
 *   <li>{@link #STACK}: locals, {@code bpf_probe_read_*} destination, struct copies</li>
 *   <li>{@link #ARENA}: {@code BPFArena}/{@code @InArena}/{@code bpfArenaAllocPages}</li>
 * </ul>
 */
public enum MemoryRegion implements Lattice<MemoryRegion> {
    UNKNOWN,
    USER,
    KERNEL_TRACKED,
    KERNEL_UNTRACKED,
    PACKET,
    MAP_VALUE,
    STACK,
    ARENA,
    /** Synthetic top: incompatible regions joined. Caller treats as a {@code region.mixing} error. */
    CONFLICT;

    @Override public MemoryRegion bottom() { return UNKNOWN; }
    @Override public MemoryRegion top()    { return CONFLICT; }

    /**
     * Region join with explicit safe-degrade rules per plan §"Mixing rules".
     *
     * <p>Compatible pairs join to a (sometimes broader) region; incompatible pairs join to
     * {@link #CONFLICT}. Callers (e.g. {@code RegionAnalyzer}) detect {@code CONFLICT} at
     * assignment / branch-merge sites and emit a {@code region.mixing} diagnostic.
     */
    @Override
    public MemoryRegion join(MemoryRegion a, MemoryRegion b) {
        if (a == b) return a;
        if (a == UNKNOWN) return b;
        if (b == UNKNOWN) return a;
        if (a == CONFLICT || b == CONFLICT) return CONFLICT;

        // KERNEL_TRACKED ∪ KERNEL_UNTRACKED → KERNEL_UNTRACKED (safe degrade, needs probe-read).
        if ((a == KERNEL_TRACKED && b == KERNEL_UNTRACKED)
                || (a == KERNEL_UNTRACKED && b == KERNEL_TRACKED)) return KERNEL_UNTRACKED;
        // PACKET ∪ KERNEL_TRACKED → KERNEL_TRACKED (loses bounds-check property).
        if ((a == PACKET && b == KERNEL_TRACKED) || (a == KERNEL_TRACKED && b == PACKET)) return KERNEL_TRACKED;
        // PACKET ∪ KERNEL_UNTRACKED → KERNEL_UNTRACKED (transitive: PACKET⊑KERNEL_TRACKED⊑KERNEL_UNTRACKED).
        if ((a == PACKET && b == KERNEL_UNTRACKED) || (a == KERNEL_UNTRACKED && b == PACKET)) return KERNEL_UNTRACKED;
        // STACK is a near-bottom for anything non-USER/non-ARENA:
        // STACK ∪ X → X for non-USER/non-ARENA; STACK ∪ USER/ARENA → CONFLICT.
        if (a == STACK) {
            return (b == USER || b == ARENA) ? CONFLICT : b;
        }
        if (b == STACK) {
            return (a == USER || a == ARENA) ? CONFLICT : a;
        }
        // MAP_VALUE pairs with KERNEL_TRACKED safely (it's a verifier-tracked kernel pointer).
        if ((a == MAP_VALUE && b == KERNEL_TRACKED) || (a == KERNEL_TRACKED && b == MAP_VALUE)) return KERNEL_TRACKED;
        // MAP_VALUE ∪ KERNEL_UNTRACKED → KERNEL_UNTRACKED (transitive degrade).
        if ((a == MAP_VALUE && b == KERNEL_UNTRACKED) || (a == KERNEL_UNTRACKED && b == MAP_VALUE)) return KERNEL_UNTRACKED;
        // MAP_VALUE ∪ PACKET → KERNEL_TRACKED (both are tracked-kernel kinds).
        if ((a == MAP_VALUE && b == PACKET) || (a == PACKET && b == MAP_VALUE)) return KERNEL_TRACKED;

        // USER vs anything-not-USER, ARENA vs anything-not-ARENA → CONFLICT.
        return CONFLICT;
    }

    @Override
    public boolean leq(MemoryRegion a, MemoryRegion b) {
        if (a == b) return true;
        if (a == UNKNOWN) return true;
        if (b == CONFLICT) return true;
        // Safe-degrade orderings:
        if (a == KERNEL_TRACKED && b == KERNEL_UNTRACKED) return true;
        if (a == PACKET && (b == KERNEL_TRACKED || b == KERNEL_UNTRACKED)) return true;
        if (a == STACK && b != USER && b != ARENA && b != UNKNOWN) return true;
        if (a == MAP_VALUE && (b == KERNEL_TRACKED || b == KERNEL_UNTRACKED)) return true;
        return false;
    }

    /** True if dereferencing this region requires {@code bpf_probe_read_user(_str)}. */
    public boolean requiresUserRead() {
        return this == USER;
    }

    /**
     * True if dereferencing this region requires {@code bpf_probe_read_kernel(_str)}.
     * Tracked-kernel pointers don't (the verifier allows direct {@code ->}).
     */
    public boolean requiresKernelRead() {
        return this == KERNEL_UNTRACKED;
    }

    /** True if direct {@code ->} or {@code *p} dereference is verifier-legal. */
    public boolean allowsDirectDeref() {
        return this == KERNEL_TRACKED || this == STACK || this == ARENA
                || this == MAP_VALUE; // null-check enforced separately by NullabilityAnalyzer
    }
}
