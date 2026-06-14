package me.bechberger.ebpf.bpf.compiler.flow;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * Generic worklist-based monotone dataflow solver (Kildall 1973, Cousot &amp; Cousot 1977).
 *
 * <p><b>Algorithm.</b> Each block has an "in" abstract state. The solver propagates per-block
 * out-states to successors (forward) or predecessors (backward), joining at merge points.
 * A block is queued when an incoming join changes its in-state. Termination is guaranteed
 * by lattice monotonicity + finite ascending chain (or widening at loop headers).
 *
 * <p><b>Priority.</b> Reverse-postorder (Cooper, Harvey &amp; Kennedy 2006) — processing blocks
 * in RPO converges forward analyses in roughly {@code O(d × |E|)} updates where {@code d} is
 * loop nesting depth.
 *
 * <p><b>Widening.</b> Applied at loop headers (blocks marked {@link BasicBlock#isLoopHeader})
 * to force convergence on lattices with infinite ascending chains. For finite lattices like
 * the BPF region/nullability ones, {@link Lattice#widen} defaults to {@link Lattice#join}, so
 * widening is essentially free.
 *
 * <p><b>Result.</b> {@link Result#inAt} / {@link Result#outAt} return the abstract state at the
 * entry / exit of each block. For per-{@link FlowNode} state, callers re-run the transfer
 * function from {@code inAt(block)} forward through the node list — this is what
 * {@code AnalysisContext} adapters do.
 */
public final class MonotoneFramework {

    private MonotoneFramework() {}

    public static <S> Result<S> solve(ControlFlowGraph cfg, TransferFunction<S> tf) {
        Lattice<S> lat = tf.lattice();
        Map<BasicBlock, S> in = new HashMap<>();
        Map<BasicBlock, S> out = new HashMap<>();

        // Seed in-state for the start block.
        BasicBlock start = tf.direction() == FlowDirection.FORWARD ? cfg.entry() : cfg.exit();
        for (var b : cfg.blocks()) {
            in.put(b, lat.bottom());
            out.put(b, lat.bottom());
        }
        in.put(start, tf.initialEntry());

        // Worklist ordered by reverse-postorder index; back-edges still funnel through here
        // but won't dominate priority because their target's RPO index is small.
        PriorityQueue<BasicBlock> work = new PriorityQueue<>(
                Comparator.comparingInt(BasicBlock::rpoIndex));
        // Seed with all reachable blocks so each gets visited at least once. This is essential:
        // the first time a block runs, its successors must be propagated to even if the in-state
        // is lattice-equivalent to bottom (otherwise newly-added bottom-valued keys never cause
        // an "increased" join and the analysis terminates before reaching downstream blocks).
        for (var b : cfg.blocks()) if (b.rpoIndex() >= 0) work.add(b);

        // Bound the number of iterations defensively. With widening this should never trigger.
        int maxIter = Math.max(1000, cfg.blocks().size() * 100);
        int iter = 0;

        while (!work.isEmpty()) {
            if (++iter > maxIter) {
                throw new IllegalStateException("Monotone solver did not converge in "
                        + maxIter + " iterations — check transfer function monotonicity / widening.");
            }
            BasicBlock b = work.poll();
            S inState = in.get(b);
            // Run the block's nodes forward (or backward) accumulating into a local state.
            S state = inState;
            if (tf.direction() == FlowDirection.FORWARD) {
                for (var n : b.nodes()) state = tf.transferNode(n, state);
            } else {
                var nodes = b.nodes();
                for (int i = nodes.size() - 1; i >= 0; i--) state = tf.transferNode(nodes.get(i), state);
            }
            out.put(b, state);

            // Propagate to successors (forward) or predecessors (backward).
            if (tf.direction() == FlowDirection.FORWARD) {
                for (var edge : b.successors()) {
                    var edgeOut = tf.transferEdge(edge, state);
                    var oldIn = in.get(edge.target);
                    var newIn = edge.kind == BasicBlock.EdgeKind.BACK
                            ? lat.widen(oldIn, lat.join(oldIn, edgeOut))
                            : lat.join(oldIn, edgeOut);
                    if (!lat.leq(newIn, oldIn)) {
                        in.put(edge.target, newIn);
                        if (!work.contains(edge.target)) work.add(edge.target);
                    }
                }
            } else {
                for (var pred : b.predecessors()) {
                    // Find the edge from pred to b to drive transferEdge.
                    BasicBlock.Edge incoming = null;
                    for (var e : pred.successors()) if (e.target == b) { incoming = e; break; }
                    var edgeOut = incoming == null ? state : tf.transferEdge(incoming, state);
                    var oldIn = in.get(pred);
                    var newIn = lat.join(oldIn, edgeOut);
                    if (!lat.leq(newIn, oldIn)) {
                        in.put(pred, newIn);
                        if (!work.contains(pred)) work.add(pred);
                    }
                }
            }
        }
        return new Result<>(in, out, tf);
    }

    /**
     * Solver result: per-block in/out states. Use {@link #stateAtNode} to get the state
     * just before a specific {@link FlowNode} (re-runs the transfer function across earlier
     * nodes in the same block).
     */
    public static final class Result<S> {
        private final Map<BasicBlock, S> in;
        private final Map<BasicBlock, S> out;
        private final TransferFunction<S> tf;

        Result(Map<BasicBlock, S> in, Map<BasicBlock, S> out, TransferFunction<S> tf) {
            this.in = in; this.out = out; this.tf = tf;
        }

        public S inAt(BasicBlock b) { return in.get(b); }
        public S outAt(BasicBlock b) { return out.get(b); }

        /** State just before the given node in the given block (forward analyses only). */
        public S stateBeforeNode(BasicBlock b, FlowNode node) {
            S s = inAt(b);
            for (var n : b.nodes()) {
                if (n == node) return s;
                s = tf.transferNode(n, s);
            }
            return s;
        }

        /** State just after the given node. */
        public S stateAfterNode(BasicBlock b, FlowNode node) {
            S s = inAt(b);
            for (var n : b.nodes()) {
                s = tf.transferNode(n, s);
                if (n == node) return s;
            }
            return s;
        }
    }
}
