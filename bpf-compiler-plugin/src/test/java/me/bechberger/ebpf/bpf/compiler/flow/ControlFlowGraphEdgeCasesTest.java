package me.bechberger.ebpf.bpf.compiler.flow;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Edge-case CFG construction: nested loops, switch, try/catch, short-circuit operators. */
class ControlFlowGraphEdgeCasesTest {

    @Test
    void nestedWhileHasTwoLoopHeaders() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int n, int m) {
                        while (n > 0) {
                            while (m > 0) { m = m - 1; }
                            n = n - 1;
                        }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        long headers = cfg.blocks().stream().filter(BasicBlock::isLoopHeader).count();
        assertEquals(2, headers, "expected exactly two loop-header blocks for nested while");
        // Two distinct BACK edges: outer-body→outer-header, inner-body→inner-header.
        long backEdges = cfg.blocks().stream()
                .flatMap(b -> b.successors().stream())
                .filter(e -> e.kind == BasicBlock.EdgeKind.BACK)
                .count();
        assertEquals(2, backEdges, "expected exactly two BACK edges for nested loops");
    }

    @Test
    void breakInNestedLoopExitsInnerOnly() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int n, int m) {
                        while (n > 0) {
                            while (m > 0) { if (m == 5) break; m = m - 1; }
                            n = n - 1;
                        }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // Should still build cleanly with two loops + a break.
        long headers = cfg.blocks().stream().filter(BasicBlock::isLoopHeader).count();
        assertEquals(2, headers);
        long backEdges = cfg.blocks().stream()
                .flatMap(b -> b.successors().stream())
                .filter(e -> e.kind == BasicBlock.EdgeKind.BACK)
                .count();
        assertEquals(2, backEdges);
    }

    @Test
    void enhancedForBuildsLoopHeader() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(java.util.List<Integer> xs) {
                        for (Integer x : xs) {
                            int y = x + 1;
                        }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // The CFG builder emits a degenerate enhanced-for loop header per the source comment.
        long headers = cfg.blocks().stream().filter(BasicBlock::isLoopHeader).count();
        assertTrue(headers >= 1, "expected at least one loop-header for enhanced-for");
    }

    @Test
    void tryBlockIsVisitedAsPlainBlock() {
        // Per Builder.visitStatement, TryTree just visits the body block (no exception edges).
        // We just verify the body still gets nodes.
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f() {
                        try { int x = 1; } catch (RuntimeException e) { }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // The DECL inside try should land somewhere.
        boolean foundDecl = cfg.blocks().stream()
                .flatMap(b -> b.nodes().stream())
                .anyMatch(n -> n.kind == FlowNode.Kind.DECL);
        assertTrue(foundDecl);
    }

    @Test
    void synchronizedBlockIsTraversed() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(Object lock) {
                        synchronized (lock) { int x = 1; }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        boolean foundDecl = cfg.blocks().stream()
                .flatMap(b -> b.nodes().stream())
                .anyMatch(n -> n.kind == FlowNode.Kind.DECL);
        assertTrue(foundDecl);
    }

    @Test
    void labeledStatementIsTraversed() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int n) {
                        outer: while (n > 0) {
                            int x = n;
                            n = n - 1;
                        }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        long headers = cfg.blocks().stream().filter(BasicBlock::isLoopHeader).count();
        assertEquals(1, headers);
    }

    @Test
    void emptyMethodHasEntryAndExit() {
        var m = JavacTestSupport.parseMethod("""
                class T { void f() { } }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        assertNotNull(cfg.entry());
        assertNotNull(cfg.exit());
        assertTrue(cfg.entry().nodes().isEmpty());
        // Entry must fall through to exit.
        assertEquals(1, cfg.entry().successors().size());
        assertEquals(cfg.exit(), cfg.entry().successors().get(0).target);
    }

    @Test
    void unreachableCodeAfterReturnIsSkipped() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    int f() {
                        return 1;
                        // dead code below — javac would warn at compile time, but parse succeeds
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // Entry has the RETURN node; should connect directly to exit via EXIT edge.
        assertTrue(cfg.entry().nodes().stream().anyMatch(n -> n.kind == FlowNode.Kind.RETURN));
        boolean exitEdge = cfg.entry().successors().stream()
                .anyMatch(e -> e.kind == BasicBlock.EdgeKind.EXIT && e.target == cfg.exit());
        assertTrue(exitEdge);
    }

    @Test
    void lambdaCfgsContainOwnReturn() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f() {
                        java.util.function.Function<Integer,Integer> g = x -> x + 1;
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        assertEquals(1, cfg.lambdaCfgs().size());
        var lcfg = cfg.lambdaCfgs().get(0);
        // Expression-bodied lambda → entry has a RETURN node.
        assertTrue(lcfg.entry().nodes().stream().anyMatch(n -> n.kind == FlowNode.Kind.RETURN));
    }

    @Test
    void multipleLambdasInOneExpression() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f() {
                        Runnable r = () -> { Runnable inner = () -> { int x = 1; }; };
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // Outer CFG sees only the outer lambda; the inner lambda is a nested CFG of the outer.
        assertEquals(1, cfg.lambdaCfgs().size(), "outer cfg should record 1 lambda");
        assertEquals(1, cfg.lambdaCfgs().get(0).lambdaCfgs().size(),
                "inner lambda must be a nested CFG of the outer lambda");
    }

    @Test
    void switchStatementBodyIsNotVisited() {
        // KNOWN LIMITATION: visitStatement's default case skips switch — so the body's
        // statements never become CFG nodes. Pin this so we notice if/when the builder
        // grows proper switch support.
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(int x) {
                        switch (x) {
                            case 1: { int a = 1; break; }
                            case 2: { int b = 2; break; }
                            default: { int c = 3; }
                        }
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        // No DECLs from inside the switch survive in the CFG.
        boolean foundDecl = cfg.blocks().stream()
                .flatMap(b -> b.nodes().stream())
                .anyMatch(n -> n.kind == FlowNode.Kind.DECL);
        assertFalse(foundDecl,
                "switch body is currently a known gap — DECLs inside cases should be invisible");
    }

    @Test
    void methodReferenceIsNotCollectedAsLambda() {
        // KNOWN GAP: collectLambdas handles LambdaExpressionTree but not MemberReferenceTree.
        // `String::length` is a functional-interface target, but doesn't produce a nested CFG.
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f() {
                        java.util.function.Function<String,Integer> g = String::length;
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        assertEquals(0, cfg.lambdaCfgs().size(),
                "method references currently a known gap — no nested CFG produced");
    }

    @Test
    void lambdaInsideTernaryIsCollected() {
        // Ternary (ConditionalExpressionTree) is one of the recursion arms in collectLambdas;
        // make sure a lambda buried in either branch still surfaces.
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(boolean b) {
                        Runnable r = b ? () -> { int x = 1; } : () -> { int y = 2; };
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        assertEquals(2, cfg.lambdaCfgs().size(),
                "both branches of a ternary should contribute a lambda CFG");
    }

    @Test
    void lambdaInBinaryExpressionIsCollected() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(java.util.function.Predicate<Integer> p) {
                        boolean b = p.test(1) && ((java.util.function.Predicate<Integer>)(x -> x > 0)).test(2);
                    }
                }
                """, "f");
        var cfg = ControlFlowGraph.buildFromMethod(m);
        assertEquals(1, cfg.lambdaCfgs().size(),
                "lambda nested in a && operand should still be collected");
    }
}
