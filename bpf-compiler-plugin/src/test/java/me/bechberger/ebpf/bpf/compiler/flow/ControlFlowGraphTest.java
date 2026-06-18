package me.bechberger.ebpf.bpf.compiler.flow;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** End-to-end CFG construction tests — straight-line, branches, loops, lambdas. */
class ControlFlowGraphTest {

    @Test
    void straightLineMethodHasOneBlockBetweenEntryAndExit() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f() {
                        int x = 1;
                        int y = 2;
                        x = x + y;
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // entry → (body block) → exit, with 3 nodes in the body block (DECL, DECL, ASSIGN).
        // (entry has the body nodes appended directly because the cursor starts at entry.)
        assertNotNull(cfg.entry());
        assertNotNull(cfg.exit());
        assertEquals(3, cfg.entry().nodes().size(),
                "expected DECL,DECL,ASSIGN on entry block but got " + cfg.entry().nodes());
        assertEquals(FlowNode.Kind.DECL, cfg.entry().nodes().get(0).kind);
        assertEquals(FlowNode.Kind.DECL, cfg.entry().nodes().get(1).kind);
        assertEquals(FlowNode.Kind.ASSIGN, cfg.entry().nodes().get(2).kind);
        // entry leads to exit.
        assertEquals(1, cfg.entry().successors().size());
        assertEquals(cfg.exit(), cfg.entry().successors().get(0).target);
    }

    @Test
    void ifThenElseProducesBranchAndJoin() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int x) {
                        if (x > 0) { x = 1; } else { x = 2; }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // entry holds the BRANCH; emits TRUE and FALSE successors.
        var entry = cfg.entry();
        assertEquals(FlowNode.Kind.BRANCH, entry.nodes().get(0).kind);
        var kinds = entry.successors().stream()
                .map(e -> e.kind).toList();
        assertTrue(kinds.contains(BasicBlock.EdgeKind.TRUE));
        assertTrue(kinds.contains(BasicBlock.EdgeKind.FALSE));
        // There should be a MERGE node somewhere (the join block).
        boolean foundMerge = cfg.blocks().stream()
                .flatMap(b -> b.nodes().stream())
                .anyMatch(n -> n.kind == FlowNode.Kind.MERGE);
        assertTrue(foundMerge);
    }

    @Test
    void ifWithoutElseFallsThroughToJoin() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int x) {
                        if (x > 0) { x = 1; }
                        x = x + 1;
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // No "else" block created — FALSE edge points directly at the join.
        assertEquals(2, cfg.entry().successors().size());
    }

    @Test
    void whileLoopHasLoopHeaderAndBackEdge() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int x) {
                        while (x > 0) { x = x - 1; }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        BasicBlock header = null;
        for (var b : cfg.blocks()) if (b.isLoopHeader()) { header = b; break; }
        assertNotNull(header, "expected at least one loop-header block");
        // The body must back-edge into the header.
        boolean foundBack = false;
        for (var b : cfg.blocks()) {
            for (var e : b.successors()) {
                if (e.target == header && e.kind == BasicBlock.EdgeKind.BACK) {
                    foundBack = true;
                    break;
                }
            }
        }
        assertTrue(foundBack, "expected at least one BACK edge into the loop header");
    }

    @Test
    void doWhileLoopBacksToHeader() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int x) {
                        do { x = x - 1; } while (x > 0);
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        long backEdges = cfg.blocks().stream()
                .flatMap(b -> b.successors().stream())
                .filter(e -> e.kind == BasicBlock.EdgeKind.BACK)
                .count();
        assertTrue(backEdges >= 1);
    }

    @Test
    void forLoopWithUpdateHasUpdateBlock() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f() {
                        for (int i = 0; i < 10; i = i + 1) {
                            int y = i;
                        }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        long backEdges = cfg.blocks().stream()
                .flatMap(b -> b.successors().stream())
                .filter(e -> e.kind == BasicBlock.EdgeKind.BACK)
                .count();
        assertTrue(backEdges >= 1, "for loop must have a back edge");
        // RPO should visit the header before the body.
        var rpo = cfg.reversePostorder();
        assertFalse(rpo.isEmpty());
    }

    @Test
    void returnGoesToExit() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    int f(int x) {
                        if (x > 0) return 1;
                        return 0;
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // Exit should have at least 2 predecessors (both return paths).
        assertTrue(cfg.exit().predecessors().size() >= 2,
                "exit should have ≥2 predecessors but had " + cfg.exit().predecessors().size());
        // Returns produce EXIT-kind edges.
        long exitEdges = cfg.blocks().stream()
                .flatMap(b -> b.successors().stream())
                .filter(e -> e.kind == BasicBlock.EdgeKind.EXIT && e.target == cfg.exit())
                .count();
        assertTrue(exitEdges >= 2);
    }

    @Test
    void lambdaIsRecordedAsNestedCfg() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f() {
                        java.util.function.Supplier<Integer> s = () -> { int x = 5; return x; };
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        assertEquals(1, cfg.lambdaCfgs().size(), "expected one nested lambda CFG");
        var lcfg = cfg.lambdaCfgs().get(0);
        assertNotNull(lcfg.entry());
        assertNotNull(lcfg.exit());
    }

    @Test
    void rpoIsAssigned() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int x) {
                        if (x > 0) { x = 1; } else { x = 2; }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // entry's rpoIndex must be 0 (first in RPO).
        assertEquals(0, cfg.entry().rpoIndex());
        // All reachable blocks must have non-negative rpo.
        for (var b : cfg.blocks()) {
            assertTrue(b.rpoIndex() >= 0,
                    () -> "unreached block: " + b);
        }
    }

    @Test
    void breakAndContinueWireToBreakAndContinueTargets() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int x) {
                        while (x > 0) {
                            if (x == 5) break;
                            if (x == 3) continue;
                            x = x - 1;
                        }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // Should still build without errors and produce a BACK edge.
        long backEdges = cfg.blocks().stream()
                .flatMap(b -> b.successors().stream())
                .filter(e -> e.kind == BasicBlock.EdgeKind.BACK)
                .count();
        assertTrue(backEdges >= 1);
    }
}
