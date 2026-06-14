package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;
import me.bechberger.ebpf.bpf.compiler.flow.ConstantValue;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Stage 5 — D8 constant propagation. Records literal-integer constants and trivial copies
 * into {@link AnalysisContext} via the {@link #CONST} slot so the Translator (and downstream
 * passes) can dead-code-eliminate provably-false branches, fold array-index loads, and
 * unroll {@code bpf_loop(N, ...)} for small constant {@code N}.
 *
 * <h2>Scope (intentionally narrow)</h2>
 * <ul>
 *   <li>Tracks integer-typed locals only (long/int/char/short/byte/boolean; float/double
 *       excluded).</li>
 *   <li>Single forward syntactic walk — <em>no CFG fixpoint</em>. The plan's risk note
 *       (§"Stage 5 ConstantPropagator scope creep") explicitly forbids fixpoint analysis here.</li>
 *   <li>An assignment, {@code ++}/{@code --}, or compound-assign of a tracked local widens it
 *       to {@link ConstantValue#TOP} for the rest of the method.</li>
 *   <li>At the merge point of an {@code if/else} (or after a loop body), every local that
 *       differs between branches widens to {@code TOP}. We do not track per-branch state past
 *       the merge.</li>
 *   <li>Folds: literal integer / boolean / char; {@code (paren)}; unary {@code -}, {@code +},
 *       {@code ~}, {@code !}; binary arithmetic / bitwise / shift / comparison on two
 *       {@code Constant(_)} operands; reads of locals whose state is {@code Constant(_)}.</li>
 * </ul>
 *
 * <p>Category for any future diagnostics: {@code const.fold-rejected} (unused today; reserved
 * for div-by-zero etc. should that ever become an error rather than silent {@code TOP}).
 */
public final class ConstantPropagator {

    /** Slot for the per-tree constant map. Other passes can read via {@link AnalysisContext#get}. */
    public static final AnalysisContext.Slot<ConstantValue> CONST =
            AnalysisContext.slot("constant");

    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public ConstantPropagator(TypedTreePath<MethodTree> methodPath, AnalysisContext ctx) {
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var body = methodPath.leaf().getBody();
        if (body == null) return;
        new Walker(ctx).scan(body, null);
    }

    /**
     * Test entry point. Walks {@code subtree}, returns the populated context — callers query
     * via {@link AnalysisContext#get(AnalysisContext.Slot, Tree) ctx.get(CONST, tree)}.
     */
    public static AnalysisContext propagate(Tree subtree) {
        var ctx = new AnalysisContext();
        new Walker(ctx).scan(subtree, null);
        return ctx;
    }

    // ── implementation ───────────────────────────────────────────────────

    private static final class Walker extends TreeScanner<Void, Void> {
        private final AnalysisContext ctx;
        /** Per-local state at the current program point. */
        private final Map<String, ConstantValue> state = new HashMap<>();

        Walker(AnalysisContext ctx) { this.ctx = ctx; }

        @Override
        public Void visitVariable(VariableTree node, Void unused) {
            super.visitVariable(node, unused);
            var init = node.getInitializer();
            if (init == null) return null;
            state.put(node.getName().toString(), evaluate(init));
            return null;
        }

        @Override
        public Void visitAssignment(AssignmentTree node, Void unused) {
            super.visitAssignment(node, unused);
            if (node.getVariable() instanceof IdentifierTree id) {
                state.put(id.getName().toString(), evaluate(node.getExpression()));
            }
            return null;
        }

        @Override
        public Void visitCompoundAssignment(CompoundAssignmentTree node, Void unused) {
            super.visitCompoundAssignment(node, unused);
            // Even when both sides are const we widen — keeping the pass simple. Folding
            // compound-assign through the current state is explicitly out of scope.
            if (node.getVariable() instanceof IdentifierTree id) {
                state.put(id.getName().toString(), ConstantValue.TOP);
            }
            return null;
        }

        @Override
        public Void visitUnary(UnaryTree node, Void unused) {
            super.visitUnary(node, unused);
            switch (node.getKind()) {
                case POSTFIX_INCREMENT, POSTFIX_DECREMENT,
                     PREFIX_INCREMENT, PREFIX_DECREMENT -> {
                    if (node.getExpression() instanceof IdentifierTree id) {
                        state.put(id.getName().toString(), ConstantValue.TOP);
                    }
                }
                default -> { /* pure unary handled in evaluate() */ }
            }
            return null;
        }

        @Override
        public Void visitIf(IfTree node, Void unused) {
            scan(node.getCondition(), null);
            var pre = new HashMap<>(state);
            scan(node.getThenStatement(), null);
            var afterThen = new HashMap<>(state);
            state.clear(); state.putAll(pre);
            if (node.getElseStatement() != null) scan(node.getElseStatement(), null);
            var afterElse = new HashMap<>(state);
            state.clear();
            var keys = new HashSet<String>();
            keys.addAll(afterThen.keySet());
            keys.addAll(afterElse.keySet());
            for (var k : keys) {
                var t = afterThen.getOrDefault(k, pre.getOrDefault(k, ConstantValue.BOTTOM));
                var e = afterElse.getOrDefault(k, pre.getOrDefault(k, ConstantValue.BOTTOM));
                state.put(k, ConstantValue.BOTTOM.join(t, e));
            }
            return null;
        }

        @Override
        public Void visitWhileLoop(WhileLoopTree node, Void unused) {
            scan(node.getCondition(), null);
            widenAssignedIn(node.getStatement());
            scan(node.getStatement(), null);
            return null;
        }

        @Override
        public Void visitDoWhileLoop(DoWhileLoopTree node, Void unused) {
            widenAssignedIn(node.getStatement());
            scan(node.getStatement(), null);
            scan(node.getCondition(), null);
            return null;
        }

        @Override
        public Void visitForLoop(ForLoopTree node, Void unused) {
            for (var stmt : node.getInitializer()) scan(stmt, null);
            scan(node.getCondition(), null);
            widenAssignedIn(node.getStatement());
            scan(node.getStatement(), null);
            for (var stmt : node.getUpdate()) scan(stmt, null);
            return null;
        }

        @Override
        public Void visitEnhancedForLoop(EnhancedForLoopTree node, Void unused) {
            scan(node.getExpression(), null);
            state.put(node.getVariable().getName().toString(), ConstantValue.TOP);
            widenAssignedIn(node.getStatement());
            scan(node.getStatement(), null);
            return null;
        }

        @Override
        public Void visitArrayAccess(ArrayAccessTree node, Void unused) {
            // Fold the index so downstream passes (MapValueIndexBoundsPass) can read
            // ctx.get(CONST, index) for constant-propagated indices — without this the index
            // expression is never an evaluate() target.
            evaluate(node.getIndex());
            return super.visitArrayAccess(node, unused);
        }

        /** Widen every local that's the LHS of any assignment / inc / dec inside {@code body}. */
        private void widenAssignedIn(Tree body) {
            new TreeScanner<Void, Void>() {
                @Override public Void visitAssignment(AssignmentTree n, Void u) {
                    if (n.getVariable() instanceof IdentifierTree id) {
                        state.put(id.getName().toString(), ConstantValue.TOP);
                    }
                    return super.visitAssignment(n, u);
                }
                @Override public Void visitCompoundAssignment(CompoundAssignmentTree n, Void u) {
                    if (n.getVariable() instanceof IdentifierTree id) {
                        state.put(id.getName().toString(), ConstantValue.TOP);
                    }
                    return super.visitCompoundAssignment(n, u);
                }
                @Override public Void visitUnary(UnaryTree n, Void u) {
                    switch (n.getKind()) {
                        case POSTFIX_INCREMENT, POSTFIX_DECREMENT,
                             PREFIX_INCREMENT, PREFIX_DECREMENT -> {
                            if (n.getExpression() instanceof IdentifierTree id) {
                                state.put(id.getName().toString(), ConstantValue.TOP);
                            }
                        }
                        default -> {}
                    }
                    return super.visitUnary(n, u);
                }
            }.scan(body, null);
        }

        /** Evaluate {@code e}, record into {@code ctx} when it folds to a constant, return value. */
        private ConstantValue evaluate(ExpressionTree e) {
            var v = doEvaluate(e);
            if (v.isConstant()) ctx.put(CONST, e, v);
            return v;
        }

        private ConstantValue doEvaluate(ExpressionTree e) {
            if (e instanceof ParenthesizedTree p) return evaluate(p.getExpression());
            if (e instanceof LiteralTree lit) {
                var val = lit.getValue();
                if (val instanceof Float || val instanceof Double) return ConstantValue.TOP;
                if (val instanceof Number n) return ConstantValue.constant(n.longValue());
                if (val instanceof Character c) return ConstantValue.constant((long) (int) c);
                if (val instanceof Boolean b) return ConstantValue.constant(b ? 1L : 0L);
                return ConstantValue.TOP;
            }
            if (e instanceof IdentifierTree id) {
                return state.getOrDefault(id.getName().toString(), ConstantValue.TOP);
            }
            if (e instanceof UnaryTree u) {
                var inner = evaluate(u.getExpression());
                if (!inner.isConstant()) return ConstantValue.TOP;
                long v = inner.asLong();
                return switch (u.getKind()) {
                    case UNARY_MINUS -> ConstantValue.constant(-v);
                    case UNARY_PLUS  -> inner;
                    case BITWISE_COMPLEMENT -> ConstantValue.constant(~v);
                    case LOGICAL_COMPLEMENT -> ConstantValue.constant(v == 0 ? 1L : 0L);
                    default -> ConstantValue.TOP;
                };
            }
            if (e instanceof BinaryTree b) {
                var lhs = evaluate(b.getLeftOperand());
                var rhs = evaluate(b.getRightOperand());
                if (!lhs.isConstant() || !rhs.isConstant()) return ConstantValue.TOP;
                long L = lhs.asLong(), R = rhs.asLong();
                return switch (b.getKind()) {
                    case PLUS     -> ConstantValue.constant(L + R);
                    case MINUS    -> ConstantValue.constant(L - R);
                    case MULTIPLY -> ConstantValue.constant(L * R);
                    case DIVIDE   -> R == 0 ? ConstantValue.TOP : ConstantValue.constant(L / R);
                    case REMAINDER -> R == 0 ? ConstantValue.TOP : ConstantValue.constant(L % R);
                    case AND -> ConstantValue.constant(L & R);
                    case OR  -> ConstantValue.constant(L | R);
                    case XOR -> ConstantValue.constant(L ^ R);
                    case LEFT_SHIFT          -> ConstantValue.constant(L << R);
                    case RIGHT_SHIFT         -> ConstantValue.constant(L >> R);
                    case UNSIGNED_RIGHT_SHIFT -> ConstantValue.constant(L >>> R);
                    case EQUAL_TO     -> ConstantValue.constant(L == R ? 1L : 0L);
                    case NOT_EQUAL_TO -> ConstantValue.constant(L != R ? 1L : 0L);
                    case LESS_THAN          -> ConstantValue.constant(L <  R ? 1L : 0L);
                    case LESS_THAN_EQUAL    -> ConstantValue.constant(L <= R ? 1L : 0L);
                    case GREATER_THAN       -> ConstantValue.constant(L >  R ? 1L : 0L);
                    case GREATER_THAN_EQUAL -> ConstantValue.constant(L >= R ? 1L : 0L);
                    default -> ConstantValue.TOP;
                };
            }
            return ConstantValue.TOP;
        }
    }
}
