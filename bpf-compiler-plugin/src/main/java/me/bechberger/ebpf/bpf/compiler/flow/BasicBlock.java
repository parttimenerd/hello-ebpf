package me.bechberger.ebpf.bpf.compiler.flow;

import com.sun.source.tree.Tree;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A basic block in the {@link ControlFlowGraph}.
 *
 * <p>Each block holds a sequence of {@link FlowNode}s (statement or expression-side-effect nodes)
 * and references to its successor blocks. Successors carry an {@link EdgeKind} so transfer
 * functions can distinguish, e.g., the true vs false branch out of an {@code if}.
 *
 * <p>Loop headers are marked so the worklist solver can apply widening at exactly those points
 * (Cousot &amp; Cousot 1977, Bourdoncle 1993 — weak topological order).
 */
public final class BasicBlock {

    /** Kind of outgoing edge — drives flow-sensitive narrowing in transfer functions. */
    public enum EdgeKind {
        /** Unconditional fall-through. */
        NORMAL,
        /** Branch taken when the condition is true ({@code if}, {@code while}, {@code &&} short-circuit). */
        TRUE,
        /** Branch taken when the condition is false. */
        FALSE,
        /** Back-edge into a loop header — solver applies {@link Lattice#widen}. */
        BACK,
        /** Exceptional / abort exit (e.g. {@code return}). */
        EXIT
    }

    public static final class Edge {
        public final BasicBlock target;
        public final EdgeKind kind;
        /** Optional condition tree (the {@code if} predicate / loop condition) — used by
         *  predicate-aware transfer functions to narrow on the taken branch. */
        public final Tree condition;

        public Edge(BasicBlock target, EdgeKind kind, Tree condition) {
            this.target = target;
            this.kind = kind;
            this.condition = condition;
        }
    }

    private final int id;
    private final List<FlowNode> nodes = new ArrayList<>();
    private final List<Edge> successors = new ArrayList<>();
    private final List<BasicBlock> predecessors = new ArrayList<>();
    private boolean loopHeader;
    /** Reverse-postorder index (set by CFG builder); -1 if unreached. */
    int rpoIndex = -1;
    /** Optional label for diagnostics. */
    private String label;

    BasicBlock(int id) { this.id = id; }

    public int id() { return id; }
    public List<FlowNode> nodes() { return Collections.unmodifiableList(nodes); }
    public List<Edge> successors() { return Collections.unmodifiableList(successors); }
    public List<BasicBlock> predecessors() { return Collections.unmodifiableList(predecessors); }
    public boolean isLoopHeader() { return loopHeader; }
    public int rpoIndex() { return rpoIndex; }
    public String label() { return label; }

    void addNode(FlowNode n) { nodes.add(n); }
    void addSuccessor(BasicBlock target, EdgeKind kind, Tree condition) {
        successors.add(new Edge(target, kind, condition));
        target.predecessors.add(this);
    }
    void markLoopHeader() { this.loopHeader = true; }
    void setLabel(String l) { this.label = l; }

    @Override public String toString() {
        return "BB" + id + (label == null ? "" : "(" + label + ")")
                + (loopHeader ? "*" : "") + "[" + nodes.size() + " nodes, "
                + successors.size() + " succs]";
    }
}
