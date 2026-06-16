package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.ArrayList;
import java.util.List;

/**
 * Pre-pass that flags loops the BPF verifier cannot bound. Stage 3 leftover.
 *
 * <p>The verifier rejects any loop whose iteration count it cannot prove to be ≤ 1M (or
 * ≤ 8M with bounded-loops on). This pass catches the common cases statically:
 * <ul>
 *   <li>{@code while (true)} / {@code for (;;)}</li>
 *   <li>{@code while (cond)} / {@code do … while (cond)} where {@code cond} is not a
 *       comparison against a literal</li>
 *   <li>{@code for (init; cond; step)} where {@code cond} is missing or not a literal-bounded
 *       comparison</li>
 * </ul>
 *
 * <p>Detection is deliberately syntactic. A more precise analysis would consult the bounds
 * lattice but would couple this pre-pass to {@code BoundsCheckPass}'s output. Users can
 * suppress with {@code @SuppressBPFWarning("bounds.unbounded-loop")} when they know the loop
 * is bounded by an external invariant the syntactic check cannot see.
 *
 * <p>Category: {@code bounds.unbounded-loop}.
 */
public final class UnboundedLoopPass {

    /** A single detected unbounded loop. */
    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public UnboundedLoopPass(CompilerPlugin compilerPlugin,
                             TypedTreePath<MethodTree> methodPath,
                             AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var body = methodPath.leaf().getBody();
        if (body == null) return;
        for (var d : detect(body)) {
            if (ctx.isSuppressed(d.at(), d.category())) continue;
            compilerPlugin.logWarning(methodPath, d.at(), d.message());
        }
    }

    /** Pure detection. */
    public static List<Detection> detect(Tree subtree) {
        var out = new ArrayList<Detection>();
        new Visitor(out).scan(subtree, null);
        return out;
    }

    /**
     * A condition is "literal-bounded" if it's a comparison ({@code <}, {@code <=}, {@code !=})
     * against a numeric literal — the cheapest form the verifier handles cleanly.
     */
    static boolean isLiteralBoundedCondition(ExpressionTree cond) {
        if (cond == null) return false;
        if (cond instanceof ParenthesizedTree p) return isLiteralBoundedCondition(p.getExpression());
        if (cond instanceof BinaryTree bt) {
            var k = bt.getKind();
            if (k == Tree.Kind.LESS_THAN || k == Tree.Kind.LESS_THAN_EQUAL
                    || k == Tree.Kind.GREATER_THAN || k == Tree.Kind.GREATER_THAN_EQUAL
                    || k == Tree.Kind.NOT_EQUAL_TO) {
                return isNumericLiteral(bt.getLeftOperand()) || isNumericLiteral(bt.getRightOperand());
            }
            if (k == Tree.Kind.CONDITIONAL_AND) {
                return isLiteralBoundedCondition(bt.getLeftOperand())
                        || isLiteralBoundedCondition(bt.getRightOperand());
            }
        }
        return false;
    }

    private static boolean isNumericLiteral(ExpressionTree e) {
        if (e instanceof ParenthesizedTree p) return isNumericLiteral(p.getExpression());
        if (e instanceof UnaryTree u
                && (u.getKind() == Tree.Kind.UNARY_MINUS || u.getKind() == Tree.Kind.UNARY_PLUS)) {
            return isNumericLiteral(u.getExpression());
        }
        return e instanceof LiteralTree lit && lit.getValue() instanceof Number;
    }

    private static String message(String shape) {
        return message(shape, null, null);
    }

    /**
     * Build the 4-part diagnostic. When {@code boundExpr} is non-null, append a concrete
     * {@code BPFJ.bpfLoop(N, i -> ...)} fix-it using {@code N = boundExpr} and
     * {@code i = counterName}.
     */
    private static String message(String shape, String boundExpr, String counterName) {
        var fix = new StringBuilder("Fix: rewrite as 'for (int i = 0; i < N; i++)' with a "
                + "compile-time literal N");
        if (boundExpr != null) {
            var counter = counterName != null ? counterName : "i";
            fix.append(", or use 'BPFJ.bpfLoop(").append(boundExpr).append(", ")
               .append(counter).append(" -> { ... })' to bound the loop at runtime");
        } else {
            fix.append(", or use 'bpf_for_each_map_elem' / 'bpf_for' helpers for collections");
        }
        fix.append(".\n");
        return "Loop with no compile-time-bounded condition: " + shape + ".\n"
             + "Why: the BPF verifier rejects any loop whose iteration count it cannot prove "
             + "to be bounded. The eBPF runtime caps total instructions at ~1M (~8M with "
             + "bounded-loops); an unbounded loop will not load.\n"
             + fix
             + "See: cookbook §Loops";
    }

    /**
     * Try to extract the bound expression from a {@code for (int i = 0; i < n; i++)}-shaped loop.
     * Returns {@code [bound, counter]} when the condition is a single comparison whose left-hand
     * side is the for-loop's counter and whose right-hand side is non-literal; otherwise null.
     */
    static String[] extractBpfLoopFixIt(ForLoopTree node) {
        var cond = unwrapParens(node.getCondition());
        if (!(cond instanceof BinaryTree bt)) return null;
        var k = bt.getKind();
        if (k != Tree.Kind.LESS_THAN && k != Tree.Kind.LESS_THAN_EQUAL) return null;

        // counter = single integer var initialised by the for-init; refuse if more than one
        if (node.getInitializer() == null || node.getInitializer().size() != 1) return null;
        var init = node.getInitializer().get(0);
        if (!(init instanceof VariableTree vt)) return null;
        String counter = vt.getName().toString();

        var lhs = unwrapParens(bt.getLeftOperand());
        var rhs = unwrapParens(bt.getRightOperand());
        if (!(lhs instanceof IdentifierTree lhsId)) return null;
        if (!lhsId.getName().contentEquals(counter)) return null;
        if (isNumericLiteral(rhs)) return null; // literal bound — no fix-it needed
        return new String[] { rhs.toString(), counter };
    }

    private static ExpressionTree unwrapParens(ExpressionTree e) {
        while (e instanceof ParenthesizedTree p) e = p.getExpression();
        return e;
    }

    private static final class Visitor extends TreeScanner<Void, Void> {
        private final List<Detection> out;

        Visitor(List<Detection> out) { this.out = out; }

        @Override
        public Void visitWhileLoop(WhileLoopTree node, Void unused) {
            var cond = node.getCondition();
            if (cond instanceof ParenthesizedTree p) cond = p.getExpression();
            if (cond instanceof LiteralTree lit && Boolean.TRUE.equals(lit.getValue())) {
                out.add(new Detection(node, "bounds.unbounded-loop", message("while (true)")));
            } else if (!isLiteralBoundedCondition(node.getCondition())) {
                out.add(new Detection(node, "bounds.unbounded-loop", message("while (<non-literal>)")));
            }
            return super.visitWhileLoop(node, unused);
        }

        @Override
        public Void visitDoWhileLoop(DoWhileLoopTree node, Void unused) {
            if (!isLiteralBoundedCondition(node.getCondition())) {
                out.add(new Detection(node, "bounds.unbounded-loop", message("do-while (<non-literal>)")));
            }
            return super.visitDoWhileLoop(node, unused);
        }

        @Override
        public Void visitForLoop(ForLoopTree node, Void unused) {
            // for(;;)  or  for(init;;step)  → no condition at all
            if (node.getCondition() == null) {
                out.add(new Detection(node, "bounds.unbounded-loop", message("for (;;)")));
            } else if (!isLiteralBoundedCondition(node.getCondition())) {
                // Suppress if the init variable is annotated with @BoundedBy — the
                // Translator will rewrite the loop bound to a compile-time constant.
                if (hasBoundedByAnnotation(node)) return super.visitForLoop(node, unused);
                var fixit = extractBpfLoopFixIt(node);
                if (fixit != null) {
                    out.add(new Detection(node, "bounds.unbounded-loop",
                            message("for (...; <non-literal>; ...)", fixit[0], fixit[1])));
                } else {
                    out.add(new Detection(node, "bounds.unbounded-loop",
                            message("for (...; <non-literal>; ...)")));
                }
            }
            return super.visitForLoop(node, unused);
        }

        private static boolean hasBoundedByAnnotation(ForLoopTree node) {
            var inits = node.getInitializer();
            if (inits == null || inits.size() != 1) return false;
            if (!(inits.get(0) instanceof VariableTree vt)) return false;
            for (var ann : vt.getModifiers().getAnnotations()) {
                var name = ann.getAnnotationType().toString();
                var simple = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : name;
                if (simple.equals("BoundedBy")) return true;
            }
            return false;
        }

        @Override
        public Void visitEnhancedForLoop(EnhancedForLoopTree node, Void unused) {
            // for-each over a collection: rejecting all of these would be too noisy. The
            // translator lowers fixed-size arrays into bounded loops; collections without a
            // statically known size are caught later by BoundsCheckPass.
            return super.visitEnhancedForLoop(node, unused);
        }
    }
}
