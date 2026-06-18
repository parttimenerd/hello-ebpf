package me.bechberger.ebpf.bpf.compiler.flow;

/**
 * Three-valued nullability lattice: {@code NON_NULL ⊑ UNKNOWN ⊑ MAYBE_NULL}.
 *
 * <p>Bottom is {@link #NON_NULL} (most precise — definitely safe). Top is {@link #MAYBE_NULL}
 * (most conservative — may fault). The {@code join} of two abstract states takes the
 * worse-case (higher) value, so a value reaches {@code MAYBE_NULL} as soon as <em>any</em>
 * incoming path could be null.
 *
 * <p>This direction (NON_NULL = bottom) matches how flow analyses propagate "good news":
 * a fresh local has the precise value {@code NON_NULL} (or {@code UNKNOWN}); merging with
 * an unknown branch widens it to {@code UNKNOWN} or {@code MAYBE_NULL}. The
 * {@code NullabilityAnalyzer} then errors on dereference if the abstract value is
 * {@code MAYBE_NULL}.
 */
public enum NullabilityValue implements Lattice<NullabilityValue> {
    NON_NULL,
    UNKNOWN,
    MAYBE_NULL;

    @Override public NullabilityValue bottom() { return NON_NULL; }
    @Override public NullabilityValue top()    { return MAYBE_NULL; }

    /** Join: take the more conservative (higher) value. */
    @Override
    public NullabilityValue join(NullabilityValue a, NullabilityValue b) {
        if (a == MAYBE_NULL || b == MAYBE_NULL) return MAYBE_NULL;
        if (a == UNKNOWN || b == UNKNOWN) return UNKNOWN;
        return NON_NULL;
    }

    /** Meet: take the more precise (lower) value. */
    @Override
    public NullabilityValue meet(NullabilityValue a, NullabilityValue b) {
        if (a == NON_NULL || b == NON_NULL) return NON_NULL;
        if (a == UNKNOWN || b == UNKNOWN) return UNKNOWN;
        return MAYBE_NULL;
    }

    @Override
    public boolean leq(NullabilityValue a, NullabilityValue b) {
        if (a == b) return true;
        if (a == NON_NULL) return true;
        if (a == UNKNOWN) return b == MAYBE_NULL;
        return false;
    }

    /** True if this value is safe to dereference without a null check. */
    public boolean isSafe() {
        return this == NON_NULL;
    }
}
