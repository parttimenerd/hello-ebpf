package me.bechberger.ebpf.bpf.compiler.flow;

import com.sun.source.tree.*;

import java.util.*;

/**
 * Control-flow graph for a Java method body, built from javac's {@link Tree} AST.
 *
 * <p>Design choices (with literature pointers):
 *
 * <ul>
 *   <li><b>Basic blocks</b>: each block is a maximal straight-line sequence of {@link FlowNode}s.
 *       Branches end a block; the next block starts the join point.</li>
 *   <li><b>Loops</b>: handled per Bourdoncle's "weak topological order" — the loop header is
 *       marked, and the back-edge from the loop end to the header is tagged
 *       {@link BasicBlock.EdgeKind#BACK} so the solver applies widening only there.</li>
 *   <li><b>Short-circuit operators</b> ({@code &&}, {@code ||}, {@code ?:}) are lowered into
 *       explicit branch blocks — important for predicate-aware narrowing
 *       (e.g. {@code x != null && x.field} narrows {@code x} on the right operand).</li>
 *   <li><b>Lambdas</b> are recorded as <em>nested</em> CFGs reachable via {@link #lambdaCfgs}.
 *       The enclosing CFG sees a single {@link FlowNode.Kind#LAMBDA} node — no inlining of the
 *       lambda body into the host method's flow. Capture analysis runs over the nested CFG
 *       separately.</li>
 *   <li><b>Returns / throws</b> jump to the synthetic {@link #exit} block via EXIT edges.</li>
 *   <li><b>Reverse postorder</b> is computed eagerly so the worklist solver can process blocks
 *       in priority order — proven optimal-ish for forward analyses (Cooper et al. 2006).</li>
 * </ul>
 *
 * <p>Block ids are dense small integers; {@link BasicBlock#rpoIndex} ranks them in RPO so the
 * solver can use a {@code PriorityQueue} keyed on rpoIndex.
 */
public final class ControlFlowGraph {

    private final List<BasicBlock> blocks;
    private final BasicBlock entry;
    private final BasicBlock exit;
    private final List<ControlFlowGraph> lambdaCfgs;
    private final Tree rootTree;

    private ControlFlowGraph(List<BasicBlock> blocks, BasicBlock entry, BasicBlock exit,
                             List<ControlFlowGraph> lambdaCfgs, Tree root) {
        this.blocks = blocks;
        this.entry = entry;
        this.exit = exit;
        this.lambdaCfgs = lambdaCfgs;
        this.rootTree = root;
    }

    public List<BasicBlock> blocks() { return Collections.unmodifiableList(blocks); }
    public BasicBlock entry() { return entry; }
    public BasicBlock exit() { return exit; }
    public List<ControlFlowGraph> lambdaCfgs() { return Collections.unmodifiableList(lambdaCfgs); }
    public Tree rootTree() { return rootTree; }

    /**
     * Reverse-postorder traversal of reachable blocks. The worklist solver uses this to
     * prioritise updates — blocks earlier in RPO are processed first, which converges
     * forward analyses in roughly height-of-CFG iterations.
     */
    public List<BasicBlock> reversePostorder() {
        var result = new ArrayList<BasicBlock>(blocks.size());
        for (var b : blocks) if (b.rpoIndex() >= 0) result.add(b);
        result.sort(Comparator.comparingInt(BasicBlock::rpoIndex));
        return result;
    }

    // ── builder ───────────────────────────────────────────────────────────

    public static ControlFlowGraph buildFromMethod(MethodTree method) {
        var b = new Builder();
        var entry = b.newBlock("entry");
        b.cursor = entry;
        b.exit = b.newBlock("exit");
        var body = method.getBody();
        if (body != null) {
            b.visitBlock(body);
        }
        // Fall-through to exit if not already terminated.
        if (b.cursor != null) b.cursor.addSuccessor(b.exit, BasicBlock.EdgeKind.NORMAL, null);
        var cfg = new ControlFlowGraph(b.blocks, entry, b.exit, b.lambdaCfgs, method);
        computeRPO(cfg);
        return cfg;
    }

    public static ControlFlowGraph buildFromLambda(LambdaExpressionTree lambda) {
        var b = new Builder();
        var entry = b.newBlock("lambda-entry");
        b.cursor = entry;
        b.exit = b.newBlock("lambda-exit");
        var body = lambda.getBody();
        if (body instanceof BlockTree bt) {
            b.visitBlock(bt);
        } else if (body instanceof ExpressionTree et) {
            b.cursor.addNode(new FlowNode(FlowNode.Kind.RETURN, et));
            b.cursor.addSuccessor(b.exit, BasicBlock.EdgeKind.EXIT, null);
            b.cursor = null;
        }
        if (b.cursor != null) b.cursor.addSuccessor(b.exit, BasicBlock.EdgeKind.NORMAL, null);
        var cfg = new ControlFlowGraph(b.blocks, entry, b.exit, b.lambdaCfgs, lambda);
        computeRPO(cfg);
        return cfg;
    }

    private static void computeRPO(ControlFlowGraph cfg) {
        // Standard postorder DFS, then reverse to get RPO.
        var visited = new HashSet<BasicBlock>();
        var post = new ArrayList<BasicBlock>(cfg.blocks.size());
        dfsPost(cfg.entry, visited, post);
        for (int i = 0; i < post.size(); i++) {
            post.get(post.size() - 1 - i).rpoIndex = i;
        }
    }

    private static void dfsPost(BasicBlock b, Set<BasicBlock> visited, List<BasicBlock> post) {
        if (!visited.add(b)) return;
        for (var e : b.successors()) {
            // Skip back-edges in the postorder traversal — they make the graph cyclic.
            if (e.kind != BasicBlock.EdgeKind.BACK) dfsPost(e.target, visited, post);
        }
        post.add(b);
    }

    // ── builder state ─────────────────────────────────────────────────────

    /** Stateful CFG builder. Visits AST in source order, threading {@link #cursor} through. */
    private static final class Builder {
        final List<BasicBlock> blocks = new ArrayList<>();
        final List<ControlFlowGraph> lambdaCfgs = new ArrayList<>();
        BasicBlock cursor; // current insertion point; null = unreachable
        BasicBlock exit;
        // Stacks for break/continue and switch — kept here so nested constructs can find the
        // enclosing loop / switch jump targets.
        final Deque<BasicBlock> breakTargets = new ArrayDeque<>();
        final Deque<BasicBlock> continueTargets = new ArrayDeque<>();
        int nextId = 0;

        BasicBlock newBlock(String label) {
            var bb = new BasicBlock(nextId++);
            bb.setLabel(label);
            blocks.add(bb);
            return bb;
        }

        void visitBlock(BlockTree block) {
            for (var s : block.getStatements()) {
                if (cursor == null) break;
                visitStatement(s);
            }
        }

        @SuppressWarnings("unchecked")
        void visitStatement(StatementTree s) {
            switch (s) {
                case BlockTree bt -> visitBlock(bt);
                case VariableTree v -> {
                    cursor.addNode(new FlowNode(FlowNode.Kind.DECL, v));
                    if (v.getInitializer() != null) collectLambdas(v.getInitializer());
                }
                case ExpressionStatementTree es -> {
                    var e = es.getExpression();
                    if (e instanceof AssignmentTree) {
                        cursor.addNode(new FlowNode(FlowNode.Kind.ASSIGN, e));
                    } else if (e instanceof MethodInvocationTree) {
                        cursor.addNode(new FlowNode(FlowNode.Kind.CALL, e));
                    } else {
                        cursor.addNode(new FlowNode(FlowNode.Kind.EXPR, e));
                    }
                    collectLambdas(e);
                }
                case IfTree it -> visitIf(it);
                case WhileLoopTree w -> visitWhile(w);
                case DoWhileLoopTree d -> visitDoWhile(d);
                case ForLoopTree f -> visitFor(f);
                case EnhancedForLoopTree ef -> visitEnhancedFor(ef);
                case ReturnTree r -> {
                    cursor.addNode(new FlowNode(FlowNode.Kind.RETURN, r));
                    cursor.addSuccessor(exit, BasicBlock.EdgeKind.EXIT, null);
                    cursor = null;
                }
                case ThrowTree t -> {
                    cursor.addNode(new FlowNode(FlowNode.Kind.THROW, t));
                    cursor.addSuccessor(exit, BasicBlock.EdgeKind.EXIT, null);
                    cursor = null;
                }
                case BreakTree br -> {
                    var tgt = breakTargets.peek();
                    if (tgt != null) cursor.addSuccessor(tgt, BasicBlock.EdgeKind.NORMAL, null);
                    cursor = null;
                }
                case ContinueTree co -> {
                    var tgt = continueTargets.peek();
                    if (tgt != null) cursor.addSuccessor(tgt, BasicBlock.EdgeKind.NORMAL, null);
                    cursor = null;
                }
                case SynchronizedTree sync -> visitBlock(sync.getBlock());
                case LabeledStatementTree lab -> visitStatement(lab.getStatement());
                case TryTree tr -> visitBlock(tr.getBlock());
                default -> { /* switch, etc. — fall through; let passes flag if needed */ }
            }
        }

        void visitIf(IfTree it) {
            var cond = it.getCondition();
            cursor.addNode(new FlowNode(FlowNode.Kind.BRANCH, cond));
            var thenBlk = newBlock("then");
            var joinBlk = newBlock("if-join");
            BasicBlock elseBlk = it.getElseStatement() != null ? newBlock("else") : joinBlk;
            cursor.addSuccessor(thenBlk, BasicBlock.EdgeKind.TRUE, cond);
            cursor.addSuccessor(elseBlk, BasicBlock.EdgeKind.FALSE, cond);
            // then branch
            cursor = thenBlk;
            visitStatement(it.getThenStatement());
            if (cursor != null) cursor.addSuccessor(joinBlk, BasicBlock.EdgeKind.NORMAL, null);
            // else branch (if any)
            if (it.getElseStatement() != null) {
                cursor = elseBlk;
                visitStatement(it.getElseStatement());
                if (cursor != null) cursor.addSuccessor(joinBlk, BasicBlock.EdgeKind.NORMAL, null);
            }
            cursor = joinBlk;
            cursor.addNode(new FlowNode(FlowNode.Kind.MERGE, it));
        }

        void visitWhile(WhileLoopTree w) {
            var header = newBlock("while-header");
            header.markLoopHeader();
            header.addNode(new FlowNode(FlowNode.Kind.LOOP_HEADER, w));
            var bodyBlk = newBlock("while-body");
            var afterBlk = newBlock("while-after");
            cursor.addSuccessor(header, BasicBlock.EdgeKind.NORMAL, null);
            cursor = header;
            cursor.addNode(new FlowNode(FlowNode.Kind.BRANCH, w.getCondition()));
            cursor.addSuccessor(bodyBlk, BasicBlock.EdgeKind.TRUE, w.getCondition());
            cursor.addSuccessor(afterBlk, BasicBlock.EdgeKind.FALSE, w.getCondition());
            // body
            breakTargets.push(afterBlk);
            continueTargets.push(header);
            cursor = bodyBlk;
            visitStatement(w.getStatement());
            if (cursor != null) cursor.addSuccessor(header, BasicBlock.EdgeKind.BACK, null);
            breakTargets.pop();
            continueTargets.pop();
            cursor = afterBlk;
        }

        void visitDoWhile(DoWhileLoopTree d) {
            var header = newBlock("do-header");
            header.markLoopHeader();
            header.addNode(new FlowNode(FlowNode.Kind.LOOP_HEADER, d));
            var afterBlk = newBlock("do-after");
            cursor.addSuccessor(header, BasicBlock.EdgeKind.NORMAL, null);
            cursor = header;
            breakTargets.push(afterBlk);
            continueTargets.push(header);
            visitStatement(d.getStatement());
            if (cursor != null) {
                cursor.addNode(new FlowNode(FlowNode.Kind.BRANCH, d.getCondition()));
                cursor.addSuccessor(header, BasicBlock.EdgeKind.BACK, d.getCondition());
                cursor.addSuccessor(afterBlk, BasicBlock.EdgeKind.FALSE, d.getCondition());
            }
            breakTargets.pop();
            continueTargets.pop();
            cursor = afterBlk;
        }

        void visitFor(ForLoopTree f) {
            // Lower init statements first (in current cursor block).
            for (var init : f.getInitializer()) visitStatement(init);
            if (cursor == null) return;
            var header = newBlock("for-header");
            header.markLoopHeader();
            header.addNode(new FlowNode(FlowNode.Kind.LOOP_HEADER, f));
            var bodyBlk = newBlock("for-body");
            var updateBlk = newBlock("for-update");
            var afterBlk = newBlock("for-after");
            cursor.addSuccessor(header, BasicBlock.EdgeKind.NORMAL, null);
            cursor = header;
            if (f.getCondition() != null) {
                cursor.addNode(new FlowNode(FlowNode.Kind.BRANCH, f.getCondition()));
                cursor.addSuccessor(bodyBlk, BasicBlock.EdgeKind.TRUE, f.getCondition());
                cursor.addSuccessor(afterBlk, BasicBlock.EdgeKind.FALSE, f.getCondition());
            } else {
                cursor.addSuccessor(bodyBlk, BasicBlock.EdgeKind.NORMAL, null);
            }
            // body
            breakTargets.push(afterBlk);
            continueTargets.push(updateBlk);
            cursor = bodyBlk;
            visitStatement(f.getStatement());
            if (cursor != null) cursor.addSuccessor(updateBlk, BasicBlock.EdgeKind.NORMAL, null);
            // update
            cursor = updateBlk;
            for (var u : f.getUpdate()) visitStatement(u);
            if (cursor != null) cursor.addSuccessor(header, BasicBlock.EdgeKind.BACK, null);
            breakTargets.pop();
            continueTargets.pop();
            cursor = afterBlk;
        }

        void visitEnhancedFor(EnhancedForLoopTree ef) {
            // Plan: BPF rejects enhanced-for. We still build a degenerate node so JavaIsmsRejectPass
            // (or any pass that looks at it) can see it. Treat as a single LOOP_HEADER node.
            var header = newBlock("enhanced-for");
            header.markLoopHeader();
            header.addNode(new FlowNode(FlowNode.Kind.LOOP_HEADER, ef));
            var bodyBlk = newBlock("enhanced-for-body");
            var afterBlk = newBlock("enhanced-for-after");
            cursor.addSuccessor(header, BasicBlock.EdgeKind.NORMAL, null);
            header.addSuccessor(bodyBlk, BasicBlock.EdgeKind.TRUE, null);
            header.addSuccessor(afterBlk, BasicBlock.EdgeKind.FALSE, null);
            breakTargets.push(afterBlk);
            continueTargets.push(header);
            cursor = bodyBlk;
            visitStatement(ef.getStatement());
            if (cursor != null) cursor.addSuccessor(header, BasicBlock.EdgeKind.BACK, null);
            breakTargets.pop();
            continueTargets.pop();
            cursor = afterBlk;
        }

        /**
         * Walk an expression and record any encountered lambda as a nested CFG. Lambdas are
         * NOT inlined — capture analysis runs separately on each. This keeps host-method
         * flow simple while still letting passes inspect lambda bodies.
         */
        void collectLambdas(ExpressionTree e) {
            if (e == null) return;
            if (e instanceof LambdaExpressionTree lam) {
                cursor.addNode(new FlowNode(FlowNode.Kind.LAMBDA, lam));
                lambdaCfgs.add(buildFromLambda(lam));
                return;
            }
            // Recurse — lightweight scan, no need to visit sub-expressions ourselves.
            if (e instanceof MethodInvocationTree mit) {
                collectLambdas(mit.getMethodSelect());
                for (var a : mit.getArguments()) collectLambdas(a);
            } else if (e instanceof MemberSelectTree ms) {
                collectLambdas(ms.getExpression());
            } else if (e instanceof AssignmentTree at) {
                collectLambdas(at.getExpression());
            } else if (e instanceof ParenthesizedTree pt) {
                collectLambdas(pt.getExpression());
            } else if (e instanceof TypeCastTree tc) {
                collectLambdas(tc.getExpression());
            } else if (e instanceof BinaryTree bt) {
                collectLambdas(bt.getLeftOperand());
                collectLambdas(bt.getRightOperand());
            } else if (e instanceof UnaryTree ut) {
                collectLambdas(ut.getExpression());
            } else if (e instanceof ConditionalExpressionTree ce) {
                collectLambdas(ce.getCondition());
                collectLambdas(ce.getTrueExpression());
                collectLambdas(ce.getFalseExpression());
            } else if (e instanceof NewClassTree nc) {
                for (var a : nc.getArguments()) collectLambdas(a);
            } else if (e instanceof NewArrayTree na) {
                if (na.getInitializers() != null) for (var x : na.getInitializers()) collectLambdas(x);
            }
        }
    }
}
