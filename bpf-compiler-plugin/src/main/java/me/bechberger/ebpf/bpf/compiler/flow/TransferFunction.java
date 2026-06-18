package me.bechberger.ebpf.bpf.compiler.flow;

/**
 * Transfer function for a monotone dataflow analysis.
 *
 * <p>Implementations supply the lattice and three transfer methods:
 *
 * <ul>
 *   <li>{@link #initialEntry} — abstract value at the CFG entry (e.g. parameter regions).</li>
 *   <li>{@link #transferNode} — effect of one {@link FlowNode} on the in-state.</li>
 *   <li>{@link #transferEdge} — flow-sensitive narrowing applied along a specific edge
 *       (e.g. on the TRUE branch of {@code if (x != null)} narrow {@code x} to {@code NON_NULL}).</li>
 * </ul>
 *
 * <p>The default {@code transferEdge} is identity. Override only when the analysis benefits
 * from predicate-aware narrowing.
 *
 * @param <S> abstract state type (typically a {@link MapLattice.Env})
 */
public interface TransferFunction<S> {

    /** The lattice over abstract states. The solver uses it for join, leq, widening. */
    Lattice<S> lattice();

    /** Direction of the analysis. */
    default FlowDirection direction() { return FlowDirection.FORWARD; }

    /** Initial state at the entry block (forward) / exit block (backward). */
    S initialEntry();

    /**
     * Transfer the abstract state across one {@link FlowNode}. Must be monotone:
     * {@code in1 ⊑ in2 ⇒ transferNode(n, in1) ⊑ transferNode(n, in2)}.
     */
    S transferNode(FlowNode node, S in);

    /**
     * Optional flow-sensitive narrowing along a specific outgoing edge.
     *
     * <p>The default is identity — override to recognise idioms like
     * {@code if (x != null) { ... }} (narrow {@code x} on TRUE branch) or
     * {@code if (region(p) == USER) { ... }}.
     */
    default S transferEdge(BasicBlock.Edge edge, S out) {
        return out;
    }
}
