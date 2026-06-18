package me.bechberger.ebpf.bpf.compiler.flow;

import com.sun.source.tree.AssignmentTree;
import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.VariableTree;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Advanced solver tests: backward analyses (liveness), edge-based predicate narrowing,
 * and short-circuit operator handling.
 *
 * <p>The CFG builder does NOT lower {@code &&} / {@code ||} into separate branch blocks —
 * they show up as plain {@link BinaryTree} nodes inside a {@code BRANCH}/{@code EXPR} node.
 * These tests document that contract and verify the solver still handles them via
 * {@link TransferFunction#transferEdge}.
 */
class MonotoneFrameworkAdvancedTest {

    /**
     * Backward live-variable analysis. State = set of live identifier names. A {@code USE} is
     * approximated by any identifier appearing in an {@code ASSIGN}/{@code DECL} initializer or
     * {@code EXPR}/{@code RETURN} expression; a {@code DEF} kills the assigned name.
     *
     * <p>Direction is {@link FlowDirection#BACKWARD}: state flows from successor to predecessor,
     * starting at the exit (empty live set).
     */
    private static final class Liveness implements TransferFunction<SetLattice.Env> {
        @Override public Lattice<SetLattice.Env> lattice() { return SetLattice.INSTANCE; }
        @Override public FlowDirection direction() { return FlowDirection.BACKWARD; }
        @Override public SetLattice.Env initialEntry() { return SetLattice.INSTANCE.bottom(); }

        @Override
        public SetLattice.Env transferNode(FlowNode node, SetLattice.Env out) {
            // Backward: out comes from "after", we compute "before".
            switch (node.kind) {
                case DECL -> {
                    if (node.tree instanceof VariableTree v) {
                        var name = v.getName().toString();
                        var before = out.remove(name);
                        // gen the initializer's identifiers
                        if (v.getInitializer() instanceof IdentifierTree id) {
                            before = before.add(id.getName().toString());
                        }
                        return before;
                    }
                }
                case ASSIGN -> {
                    if (node.tree instanceof AssignmentTree a
                            && a.getVariable() instanceof IdentifierTree lhs) {
                        var before = out.remove(lhs.getName().toString());
                        if (a.getExpression() instanceof IdentifierTree rhs) {
                            before = before.add(rhs.getName().toString());
                        }
                        return before;
                    }
                }
                default -> { /* fall through */ }
            }
            return out;
        }
    }

    /**
     * Forward null-tracking transfer with predicate-based narrowing on the TRUE/FALSE edges of
     * an {@code if (x != null)} branch. Verifies {@link TransferFunction#transferEdge}.
     */
    private static final class NullWithNarrowing implements TransferFunction<MapLattice.Env<String, NullabilityValue>> {
        private final MapLattice<String, NullabilityValue> lat = new MapLattice<>(NullabilityValue.NON_NULL);

        @Override public Lattice<MapLattice.Env<String, NullabilityValue>> lattice() { return lat; }
        @Override public MapLattice.Env<String, NullabilityValue> initialEntry() { return lat.empty(); }

        @Override
        public MapLattice.Env<String, NullabilityValue> transferNode(
                FlowNode node, MapLattice.Env<String, NullabilityValue> in) {
            if (node.kind == FlowNode.Kind.DECL && node.tree instanceof VariableTree v) {
                var name = v.getName().toString();
                if (v.getInitializer() instanceof LiteralTree lit && lit.getValue() == null) {
                    return in.put(name, NullabilityValue.MAYBE_NULL);
                }
                return in.put(name, NullabilityValue.NON_NULL);
            }
            return in;
        }

        @Override
        public MapLattice.Env<String, NullabilityValue> transferEdge(
                BasicBlock.Edge edge, MapLattice.Env<String, NullabilityValue> out) {
            // Recognise `x != null` (or `x == null` inverted) on TRUE/FALSE edges.
            var cond = edge.condition;
            while (cond instanceof com.sun.source.tree.ParenthesizedTree p) cond = p.getExpression();
            if (cond instanceof BinaryTree bt) {
                var k = bt.getKind();
                IdentifierTree id = null;
                boolean compareWithNull = false;
                if (bt.getLeftOperand() instanceof IdentifierTree i
                        && bt.getRightOperand() instanceof LiteralTree l && l.getValue() == null) {
                    id = i; compareWithNull = true;
                } else if (bt.getRightOperand() instanceof IdentifierTree i
                        && bt.getLeftOperand() instanceof LiteralTree l && l.getValue() == null) {
                    id = i; compareWithNull = true;
                }
                if (id != null && compareWithNull) {
                    var name = id.getName().toString();
                    boolean isNotEqual = k == com.sun.source.tree.Tree.Kind.NOT_EQUAL_TO;
                    boolean isEqual = k == com.sun.source.tree.Tree.Kind.EQUAL_TO;
                    if (isNotEqual && edge.kind == BasicBlock.EdgeKind.TRUE) {
                        return out.put(name, NullabilityValue.NON_NULL);
                    }
                    if (isEqual && edge.kind == BasicBlock.EdgeKind.TRUE) {
                        return out.put(name, NullabilityValue.MAYBE_NULL);
                    }
                    if (isNotEqual && edge.kind == BasicBlock.EdgeKind.FALSE) {
                        return out.put(name, NullabilityValue.MAYBE_NULL);
                    }
                    if (isEqual && edge.kind == BasicBlock.EdgeKind.FALSE) {
                        return out.put(name, NullabilityValue.NON_NULL);
                    }
                }
            }
            return out;
        }
    }

    @Test
    void backwardLivenessConvergesOnStraightLine() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f() {
                        Object a = null;
                        Object b = a;
                        Object c = b;
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        var result = MonotoneFramework.solve(cfg, new Liveness());
        // For backward analyses, outAt(entry) = live-IN of the entry block (post-transfer state).
        assertTrue(result.outAt(cfg.entry()).set().isEmpty(),
                "no externally-live vars at entry of self-contained body");
    }

    @Test
    void backwardLivenessDetectsLiveParameter() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(Object a) {
                        Object b = a;
                        Object c = b;
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        var result = MonotoneFramework.solve(cfg, new Liveness());
        // `a` flows transitively to `c`. At entry, `a` should be live (used downstream).
        // For backward analyses, outAt(entry) = live-IN of the entry block.
        assertTrue(result.outAt(cfg.entry()).set().contains("a"),
                "parameter `a` must be live at entry — its value is used by `b = a`");
    }

    @Test
    void backwardLivenessAcrossLoop() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(Object a) {
                        Object x = a;
                        while (x != null) {
                            x = a;
                        }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        var result = MonotoneFramework.solve(cfg, new Liveness());
        // `a` is used inside the loop body — must be live at entry.
        assertTrue(result.outAt(cfg.entry()).set().contains("a"));
    }

    @Test
    void transferEdgeNarrowsOnTrueBranch() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(Object x) {
                        Object y = null;
                        if (y != null) { Object z = y; }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        var result = MonotoneFramework.solve(cfg, new NullWithNarrowing());
        // Find the THEN block — the one whose predecessor edge is TRUE.
        BasicBlock thenBlock = null;
        for (var b : cfg.blocks()) {
            for (var pred : b.predecessors()) {
                for (var e : pred.successors()) {
                    if (e.target == b && e.kind == BasicBlock.EdgeKind.TRUE) {
                        thenBlock = b;
                    }
                }
            }
            if (thenBlock != null) break;
        }
        assertNotNull(thenBlock, "should have located the THEN branch block");
        // After narrowing on `y != null`, y must be NON_NULL on entry to THEN.
        assertEquals(NullabilityValue.NON_NULL, result.inAt(thenBlock).get("y"));
    }

    @Test
    void shortCircuitAndAppearsAsBinaryNotLowered() {
        // Document current contract: `&&` is NOT lowered to two branches; it remains a single
        // BinaryTree inside the IF condition's BRANCH node.
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(Object a, Object b) {
                        if (a != null && b != null) { int x = 1; }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        long branches = cfg.blocks().stream()
                .flatMap(bb -> bb.nodes().stream())
                .filter(n -> n.kind == FlowNode.Kind.BRANCH)
                .count();
        // One BRANCH for the if (not two). Lowering `&&` would produce two.
        assertEquals(1, branches, "&& must remain a single BinaryTree in one BRANCH node");
    }

    @Test
    void shortCircuitOrAppearsAsBinaryNotLowered() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(Object a, Object b) {
                        if (a == null || b == null) { int x = 1; }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        long branches = cfg.blocks().stream()
                .flatMap(bb -> bb.nodes().stream())
                .filter(n -> n.kind == FlowNode.Kind.BRANCH)
                .count();
        assertEquals(1, branches);
    }

    /** Tiny set lattice for liveness — uses immutable copy-on-write semantics. */
    private static final class SetLattice implements Lattice<SetLattice.Env> {
        static final SetLattice INSTANCE = new SetLattice();
        @Override public Env bottom() { return new Env(Set.of()); }
        @Override public Env top()    { throw new UnsupportedOperationException(); }
        @Override public Env join(Env a, Env b) {
            var u = new HashSet<>(a.set);
            u.addAll(b.set);
            return new Env(u);
        }
        @Override public boolean leq(Env a, Env b) { return b.set.containsAll(a.set); }

        static final class Env {
            private final Set<String> set;
            Env(Set<String> s) { this.set = Set.copyOf(s); }
            Set<String> set() { return set; }
            Env add(String name) {
                if (set.contains(name)) return this;
                var u = new HashSet<>(set); u.add(name); return new Env(u);
            }
            Env remove(String name) {
                if (!set.contains(name)) return this;
                var u = new HashSet<>(set); u.remove(name); return new Env(u);
            }
        }
    }
}
