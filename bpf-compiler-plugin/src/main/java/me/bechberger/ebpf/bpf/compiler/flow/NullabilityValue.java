package me.bechberger.ebpf.bpf.compiler.flow;

/**
 * Three-valued nullability lattice used by {@link NullabilityAnalyzer}.
 *
 * <p>Ordering (bottom → top): {@code MAYBE_NULL < UNKNOWN < NON_NULL}.
 * {@code join} returns the lower (more conservative) value when two branches disagree.
 */
public enum NullabilityValue implements Lattice<NullabilityValue> {
    /** Definitely not null — safe to dereference. */
    NON_NULL,
    /** Unknown — not yet determined (initial state for most variables). */
    UNKNOWN,
    /** Potentially null — dereference without a prior null-check is an error. */
    MAYBE_NULL;

    @Override
    public NullabilityValue bottom() {
        return MAYBE_NULL;
    }

    /**
     * Join: take the more conservative (lower) value.
     * e.g. join(NON_NULL, MAYBE_NULL) = MAYBE_NULL (could be null after a merge).
     */
    @Override
    public NullabilityValue join(NullabilityValue a, NullabilityValue b) {
        if (a == MAYBE_NULL || b == MAYBE_NULL) return MAYBE_NULL;
        if (a == UNKNOWN || b == UNKNOWN) return UNKNOWN;
        return NON_NULL;
    }

    /** True if this value is safe to dereference without a null check. */
    public boolean isSafe() {
        return this == NON_NULL;
    }
}
