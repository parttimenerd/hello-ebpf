package me.bechberger.ebpf.bpf.compiler.util;

import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.ReturnTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.Trees;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.ExecutableElement;
import java.util.Optional;

/**
 * Compile-time constant extraction from method bodies via the Trees API.
 *
 * <p>Used by struct_ops synthesis (and any other consumer that needs to
 * fold a trivial {@code return "literal"} body into a compile-time
 * constant). Kept in its own class because the Trees dependency is
 * intentionally narrow — most of the plugin talks to
 * {@code javax.lang.model} only.
 */
public final class TreeConstants {

    private TreeConstants() {}

    /**
     * If the method body is exactly {@code return "literal";}, returns the
     * literal string. Any other shape (empty body, multiple statements,
     * non-literal return, concatenation, method call, etc.) yields
     * {@link Optional#empty()}. Callers can then emit a targeted diagnostic
     * pointing at the method.
     *
     * <p>Requires a {@link Trees} instance from the enclosing javac task,
     * obtained via {@code Trees.instance(task)} in the plugin's {@code init()}.
     * Using {@code Trees.instance(env)} (annotation-processor round) fails for
     * methods compiled in earlier rounds because the round-env trees are
     * discarded; the task-level trees span the full compilation.
     */
    public static Optional<String> stringReturnLiteral(Trees trees, ExecutableElement m) {
        var mt = trees.getTree(m);
        if (mt == null || mt.getBody() == null) return Optional.empty();
        var stmts = mt.getBody().getStatements();
        if (stmts.size() != 1) return Optional.empty();
        if (!(stmts.get(0) instanceof ReturnTree rt)) return Optional.empty();
        if (!(rt.getExpression() instanceof LiteralTree lit)) return Optional.empty();
        if (lit.getKind() != Tree.Kind.STRING_LITERAL) return Optional.empty();
        return Optional.of((String) lit.getValue());
    }

    /**
     * {@link ProcessingEnvironment}-based overload for callers that don't have access to the
     * javac task's {@link Trees}. Note: returns {@link Optional#empty()} for methods compiled
     * in prior annotation-processing rounds because round-env trees are discarded by javac.
     * Prefer {@link #stringReturnLiteral(Trees, ExecutableElement)} when the plugin's task
     * trees are available.
     */
    public static Optional<String> stringReturnLiteral(
            ProcessingEnvironment env, ExecutableElement m) {
        Trees trees;
        try {
            trees = Trees.instance(env);
        } catch (IllegalArgumentException e) {
            // Non-javac processing environment: Trees not available.
            return Optional.empty();
        }
        return stringReturnLiteral(trees, m);
    }

    /**
     * If the method body is exactly {@code return <int-literal>;}, returns the
     * literal as a Long. Any other shape yields {@link Optional#empty()}.
     * Used by struct_ops synthesis for int-typed data fields (e.g.
     * {@code hid_bpf_ops.hid_id}).
     *
     * <p>Uses the javac task's {@link Trees} which span all compilation rounds.
     */
    public static Optional<Long> integerReturnLiteral(Trees trees, ExecutableElement m) {
        var mt = trees.getTree(m);
        if (mt == null || mt.getBody() == null) return Optional.empty();
        var stmts = mt.getBody().getStatements();
        if (stmts.size() != 1) return Optional.empty();
        if (!(stmts.get(0) instanceof ReturnTree rt)) return Optional.empty();
        if (!(rt.getExpression() instanceof LiteralTree lit)) return Optional.empty();
        return switch (lit.getKind()) {
            case INT_LITERAL, LONG_LITERAL -> Optional.of(((Number) lit.getValue()).longValue());
            default -> Optional.empty();
        };
    }

    /**
     * {@link ProcessingEnvironment}-based overload. Prefer
     * {@link #integerReturnLiteral(Trees, ExecutableElement)} when the plugin's task trees
     * are available.
     */
    public static Optional<Long> integerReturnLiteral(
            ProcessingEnvironment env, ExecutableElement m) {
        Trees trees;
        try {
            trees = Trees.instance(env);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        return integerReturnLiteral(trees, m);
    }
}
