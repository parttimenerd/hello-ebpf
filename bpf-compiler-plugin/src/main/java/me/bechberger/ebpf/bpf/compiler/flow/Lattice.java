package me.bechberger.ebpf.bpf.compiler.flow;

/**
 * Bounded lattice with optional widening, used by the monotone dataflow framework.
 *
 * <p>This interface follows the Cousot &amp; Cousot abstract-interpretation tradition: a finite
 * (or finite-height) complete lattice with a {@code bottom}, {@code top}, monotone {@code join}
 * (least upper bound) and {@code meet} (greatest lower bound), and a partial-order test
 * {@code leq}. {@code widen} accelerates fixpoint convergence at loop heads when the lattice
 * has infinite ascending chains; for finite lattices it can default to {@code join}.
 *
 * <p>Implementations must be <em>immutable</em>: lattice values are shared across many
 * program points, and the worklist solver compares them with {@link #leq} to detect a fixpoint.
 *
 * <p>Algebraic laws (monotonicity, commutativity, associativity, idempotence of {@code join};
 * absorption) are documented per method but not enforced — implementers are responsible.
 *
 * @param <V> immutable lattice-value type
 */
public interface Lattice<V> {

    /** The least element. {@code join(bottom, x) == x}. */
    V bottom();

    /**
     * The greatest element. {@code join(x, top) == top}. Defaults to {@code null} for lattices
     * where a top is meaningless (e.g. environments — top would be a degenerate "all variables
     * are top" map). The solver only requires {@code top} for backward analyses initialised
     * from top.
     */
    default V top() {
        return null;
    }

    /** Least upper bound. Must be commutative, associative, idempotent, monotone in both args. */
    V join(V a, V b);

    /**
     * Greatest lower bound. Default: {@code a} when {@code leq(a, b)} else {@code b} when
     * {@code leq(b, a)}, else {@code bottom()} — a safe approximation for lattices without
     * a precise meet. Override when a tighter meet exists.
     */
    default V meet(V a, V b) {
        if (leq(a, b)) return a;
        if (leq(b, a)) return b;
        return bottom();
    }

    /**
     * Partial-order test: {@code true} iff {@code a} is below or equal to {@code b}.
     * The solver uses this to detect a fixpoint (a transferred value is {@code leq} the
     * existing value at a join point ⇒ no further work).
     */
    boolean leq(V a, V b);

    /**
     * Widening operator (Cousot &amp; Cousot 1977). Used at loop headers to force convergence
     * on lattices with infinite ascending chains (e.g. integer intervals). For finite-height
     * lattices like the BPF region/nullability ones, widening can safely degrade to
     * {@code join}.
     */
    default V widen(V old, V incoming) {
        return join(old, incoming);
    }

    /**
     * Narrowing operator. Used post-fixpoint to recover precision lost to widening.
     * Default is {@code meet}; for finite lattices it's a no-op effectively.
     */
    default V narrow(V old, V incoming) {
        return meet(old, incoming);
    }
}
