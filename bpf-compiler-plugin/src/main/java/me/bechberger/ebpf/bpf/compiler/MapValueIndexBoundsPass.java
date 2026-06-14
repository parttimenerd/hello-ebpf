package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;
import me.bechberger.ebpf.bpf.compiler.flow.ConstantValue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Stage 7 — D5 sub-check #1: rejects array indexing whose index is a propagated constant
 * that exceeds the array's declared {@code @Size(N)}.
 *
 * <p>Limited to the cheap, syntactic case the verifier flags loudest: a local array declared
 * with a literal {@code @Size(N)} indexed by an expression that {@link ConstantPropagator}
 * has folded to a constant {@code i ∉ [0, N)}.
 *
 * <p>Symbolic indices and runtime-bounded ones are out of scope here — they're handled by
 * Stage 1's region/null analysis (MAP_VALUE deref → null check) and the verifier itself.
 *
 * <p>Category: {@code bounds.array-index-out-of-range}. Severity: error (always wrong).
 */
public final class MapValueIndexBoundsPass {

    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public MapValueIndexBoundsPass(CompilerPlugin compilerPlugin,
                                   TypedTreePath<MethodTree> methodPath,
                                   AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var body = methodPath.leaf().getBody();
        if (body == null) return;
        for (var d : detect(body, ctx)) {
            if (ctx.isSuppressed(d.at(), d.category())) continue;
            compilerPlugin.logError(methodPath, d.at(), d.message());
        }
    }

    /** Pure detection: walks {@code subtree}, returns each out-of-range constant index. */
    public static List<Detection> detect(Tree subtree, AnalysisContext ctx) {
        var sizes = collectArraySizes(subtree);
        var out = new ArrayList<Detection>();
        new Visitor(sizes, ctx, out).scan(subtree, null);
        return out;
    }

    /** Map local-variable name → declared {@code @Size(N)} for arrays / strings. */
    private static Map<String, Integer> collectArraySizes(Tree subtree) {
        var sizes = new HashMap<String, Integer>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(VariableTree node, Void unused) {
                var n = SizeInference.inferSize(node);
                if (n.isPresent() && n.getAsInt() >= 0) {
                    sizes.put(node.getName().toString(), n.getAsInt());
                }
                return super.visitVariable(node, unused);
            }
        }.scan(subtree, null);
        return sizes;
    }

    private static String message(String name, long index, int size) {
        return "Array index " + index + " is out of range for '" + name
                + "' (declared @Size(" + size + ")).\n"
             + "Why: the BPF verifier rejects loads/stores past the end of a fixed-size buffer; "
             + "indices folded to compile-time constants must be in [0, " + size + ").\n"
             + "Fix: either widen the @Size annotation, or check the index against the size at "
             + "runtime: 'if (i >= 0 && i < " + size + ") { ... }'.\n"
             + "See: cookbook §Bounds";
    }

    private static final class Visitor extends TreeScanner<Void, Void> {
        private final Map<String, Integer> sizes;
        private final AnalysisContext ctx;
        private final List<Detection> out;

        Visitor(Map<String, Integer> sizes, AnalysisContext ctx, List<Detection> out) {
            this.sizes = sizes;
            this.ctx = ctx;
            this.out = out;
        }

        @Override
        public Void visitArrayAccess(ArrayAccessTree node, Void unused) {
            if (node.getExpression() instanceof IdentifierTree id) {
                var name = id.getName().toString();
                var size = sizes.get(name);
                if (size != null) {
                    var v = literalLong(node.getIndex());
                    if (v == null) {
                        var idx = ctx.get(ConstantPropagator.CONST, node.getIndex());
                        if (idx != null && idx.isConstant()) v = idx.asLong();
                    }
                    if (v != null && (v < 0 || v >= size)) {
                        out.add(new Detection(node,
                                "bounds.array-index-out-of-range",
                                message(name, v, size)));
                    }
                }
            }
            return super.visitArrayAccess(node, unused);
        }
    }

    /** Recognise a literal-integer index — handles parens and unary +/-. */
    static Long literalLong(ExpressionTree e) {
        if (e instanceof ParenthesizedTree p) return literalLong(p.getExpression());
        if (e instanceof UnaryTree u) {
            if (u.getKind() == Tree.Kind.UNARY_PLUS) return literalLong(u.getExpression());
            if (u.getKind() == Tree.Kind.UNARY_MINUS) {
                var inner = literalLong(u.getExpression());
                return inner == null ? null : -inner;
            }
        }
        if (e instanceof LiteralTree lit && lit.getValue() instanceof Number n) {
            return n.longValue();
        }
        return null;
    }
}
