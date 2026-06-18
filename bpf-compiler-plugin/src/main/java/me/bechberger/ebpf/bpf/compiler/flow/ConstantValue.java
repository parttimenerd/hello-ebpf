package me.bechberger.ebpf.bpf.compiler.flow;

import java.util.Objects;

/**
 * Three-valued constant-folding lattice: {@code BOTTOM ⊑ Constant(v) ⊑ TOP}.
 *
 * <p>{@link #BOTTOM} means "no information yet" (unreachable / not-yet-analysed). A
 * {@code Constant(v)} is "definitely the literal {@code v}". {@link #TOP} is "definitely
 * not statically known" (varies at runtime).
 *
 * <p>The {@code join} of two abstract states takes the *less precise* outcome: joining two
 * different constants → {@code TOP}; joining a constant with itself → the same constant;
 * joining anything with {@code BOTTOM} is the identity.
 *
 * <p>Values are 64-bit signed long for arithmetic uniformity. The propagator boxes {@code int},
 * {@code char}, {@code short}, and {@code byte} literals to {@code long}; floating-point
 * literals are intentionally <em>not</em> tracked (the plan scopes Stage 5 to integral consts).
 *
 * <p>Bottom = most precise, top = most conservative — the same direction as
 * {@link NullabilityValue}.
 */
public final class ConstantValue implements Lattice<ConstantValue> {

    /** No information yet. Initial state for unreached locations. */
    public static final ConstantValue BOTTOM = new ConstantValue(Kind.BOTTOM, 0L);

    /** Definitely-not-statically-known. Once a value reaches TOP it stays there. */
    public static final ConstantValue TOP = new ConstantValue(Kind.TOP, 0L);

    /** Pre-allocated common cases to keep allocations down on hot paths. */
    public static final ConstantValue ZERO = constant(0L);
    public static final ConstantValue ONE  = constant(1L);

    public enum Kind { BOTTOM, CONSTANT, TOP }

    private final Kind kind;
    private final long value;

    private ConstantValue(Kind kind, long value) {
        this.kind = kind;
        this.value = value;
    }

    public static ConstantValue constant(long v) {
        return new ConstantValue(Kind.CONSTANT, v);
    }

    public Kind kind() { return kind; }

    /** The constant value. Caller must ensure {@link #isConstant()}. */
    public long asLong() {
        if (kind != Kind.CONSTANT) {
            throw new IllegalStateException("not a CONSTANT: " + this);
        }
        return value;
    }

    public boolean isConstant() { return kind == Kind.CONSTANT; }
    public boolean isTop()      { return kind == Kind.TOP; }
    public boolean isBottom()   { return kind == Kind.BOTTOM; }

    @Override public ConstantValue bottom() { return BOTTOM; }
    @Override public ConstantValue top()    { return TOP; }

    /** Join: bottom is identity; equal constants stay; everything else widens to top. */
    @Override
    public ConstantValue join(ConstantValue a, ConstantValue b) {
        if (a.isBottom()) return b;
        if (b.isBottom()) return a;
        if (a.isTop() || b.isTop()) return TOP;
        // both CONSTANT
        return a.value == b.value ? a : TOP;
    }

    /**
     * Meet: top is identity; bottom annihilates; equal constants stay; mixed constants become
     * bottom (no value satisfies both).
     */
    @Override
    public ConstantValue meet(ConstantValue a, ConstantValue b) {
        if (a.isTop()) return b;
        if (b.isTop()) return a;
        if (a.isBottom() || b.isBottom()) return BOTTOM;
        // both CONSTANT
        return a.value == b.value ? a : BOTTOM;
    }

    @Override
    public boolean leq(ConstantValue a, ConstantValue b) {
        if (a.isBottom()) return true;
        if (b.isTop()) return true;
        if (a.isConstant() && b.isConstant()) return a.value == b.value;
        return false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ConstantValue cv)) return false;
        return kind == cv.kind && value == cv.value;
    }

    @Override
    public int hashCode() { return Objects.hash(kind, value); }

    @Override
    public String toString() {
        return switch (kind) {
            case BOTTOM -> "⊥";
            case TOP -> "⊤";
            case CONSTANT -> "Constant(" + value + ")";
        };
    }
}
