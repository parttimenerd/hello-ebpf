package me.bechberger.ebpf.bpf.compiler.flow;

/**
 * Generic lattice interface for intra-procedural flow analysis over BPF method bodies.
 *
 * <p>Implementations must satisfy the lattice laws: monotonicity of {@code join} and a finite
 * ascending chain condition so the worklist terminates. BPF programs are small (≤1M instructions
 * verified), so even a naive repeated-scan reaches a fixpoint quickly.
 *
 * @param <V> the lattice value type (must be immutable)
 */
public interface Lattice<V> {

    /** The bottom element — most conservative / least information. */
    V bottom();

    /**
     * Least upper bound of two lattice values. Must be commutative, associative, and idempotent,
     * and satisfy {@code join(a, b) >= a} and {@code join(a, b) >= b}.
     */
    V join(V a, V b);
}
