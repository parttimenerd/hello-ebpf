package me.bechberger.ebpf.bpf.compiler.flow;

import com.sun.source.tree.Tree;

/**
 * A single program point in the CFG: an evaluation of a statement or expression with
 * potential side-effects on the abstract state.
 *
 * <p>The {@link Kind} discriminator lets transfer functions dispatch cheaply without
 * pattern-matching the full {@link Tree} taxonomy on every visit.
 *
 * <p>{@code FlowNode} is intentionally lightweight — the heavy AST traversal happens once
 * during CFG construction, after which the solver only iterates over a flat list per block.
 */
public final class FlowNode {

    public enum Kind {
        /** Variable declaration: {@code T x = init;} (init may be null). */
        DECL,
        /** Assignment / compound-assignment to a variable or field. */
        ASSIGN,
        /** Method invocation evaluated for its side effects. */
        CALL,
        /** Branch test — sits at the end of a block whose successors carry TRUE/FALSE edges. */
        BRANCH,
        /** {@code return expr;} — followed by an EXIT edge to the synthetic exit block. */
        RETURN,
        /** Throw — currently unsupported in BPF, but tracked so passes can flag it. */
        THROW,
        /** Generic expression statement evaluated for its side-effects. */
        EXPR,
        /** Lambda body entry — flagged so passes that need capture analysis can hook in. */
        LAMBDA,
        /** Loop header marker — synthetic; sits at the start of a loop's header block. */
        LOOP_HEADER,
        /** Phi-like merge marker — synthetic; sits at a join point. Useful for diagnostics. */
        MERGE
    }

    public final Kind kind;
    public final Tree tree;
    /** Optional auxiliary tree (e.g., the LHS of an assignment when {@code tree} is the RHS). */
    public final Tree aux;

    public FlowNode(Kind kind, Tree tree) { this(kind, tree, null); }

    public FlowNode(Kind kind, Tree tree, Tree aux) {
        this.kind = kind;
        this.tree = tree;
        this.aux = aux;
    }

    @Override public String toString() {
        return kind + "(" + (tree == null ? "<null>" : tree.getKind()) + ")";
    }
}
