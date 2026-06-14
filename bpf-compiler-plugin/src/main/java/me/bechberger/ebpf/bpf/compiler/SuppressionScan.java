package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.HashSet;
import java.util.Set;

/**
 * Pre-pass that records {@code @SuppressBPFWarning("category")} annotations.
 *
 * <p>Walks the method tree once and populates {@link AnalysisContext#suppressionsAt} so that
 * later passes can call {@link AnalysisContext#isSuppressed(com.sun.source.tree.Tree, String)}
 * without re-walking the AST.
 *
 * <p>Suppression cascades downward through the tree: a {@code @SuppressBPFWarning} on a method
 * silences the named categories for every nested expression. The implementation flattens this
 * by associating the suppression set with each enclosed tree, so {@code isSuppressed} is an
 * O(1) lookup at the diagnostic site.
 */
public final class SuppressionScan {

    private static final String SUPPRESS_ANNOTATION = "SuppressBPFWarning";

    private final AnalysisContext ctx;

    public SuppressionScan(AnalysisContext ctx) {
        this.ctx = ctx;
    }

    public void scan(MethodTree method) {
        new Scanner().scan(method, currentSetOrEmpty(method));
    }

    private Set<String> currentSetOrEmpty(MethodTree method) {
        var top = extractCategories(method.getModifiers());
        return top.isEmpty() ? Set.of() : Set.copyOf(top);
    }

    private static Set<String> extractCategories(ModifiersTree mods) {
        var out = new HashSet<String>();
        if (mods == null) return out;
        for (var ann : mods.getAnnotations()) {
            var name = ann.getAnnotationType().toString();
            var simple = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : name;
            if (!simple.equals(SUPPRESS_ANNOTATION)) continue;
            for (var arg : ann.getArguments()) {
                addLiteral(arg, out);
            }
        }
        return out;
    }

    private static void addLiteral(ExpressionTree e, Set<String> out) {
        if (e == null) return;
        switch (e) {
            case AssignmentTree a -> addLiteral(a.getExpression(), out);
            case LiteralTree lit -> { if (lit.getValue() instanceof String s) out.add(s); }
            case NewArrayTree na -> {
                if (na.getInitializers() != null) {
                    for (var x : na.getInitializers()) addLiteral(x, out);
                }
            }
            default -> { /* ignore other shapes */ }
        }
    }

    private final class Scanner extends TreeScanner<Void, Set<String>> {

        @Override
        public Void scan(Tree node, Set<String> active) {
            if (node == null) return null;
            if (!active.isEmpty()) ctx.suppressionsAt.put(node, active);
            return super.scan(node, active);
        }

        @Override
        public Void visitVariable(VariableTree node, Set<String> active) {
            var local = extractCategories(node.getModifiers());
            if (!local.isEmpty()) {
                var merged = new HashSet<>(active);
                merged.addAll(local);
                ctx.suppressionsAt.put(node, Set.copyOf(merged));
                return super.visitVariable(node, Set.copyOf(merged));
            }
            return super.visitVariable(node, active);
        }

        @Override
        public Void visitClass(ClassTree node, Set<String> active) {
            var local = extractCategories(node.getModifiers());
            if (!local.isEmpty()) {
                var merged = new HashSet<>(active);
                merged.addAll(local);
                return super.visitClass(node, Set.copyOf(merged));
            }
            return super.visitClass(node, active);
        }
    }
}
