package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;

import java.util.Optional;
import java.util.OptionalInt;

/**
 * Stage 11 helpers: derive {@code @Size(N)} from buffer / typedef declarations so users do not
 * have to repeat the size on every local variable.
 *
 * <p>This is a syntactic helper (works on AST shapes, not symbols). The full version that walks
 * typedef inheritance lives in the type-processor; this helper is the cheap form used by passes
 * that already have the {@link VariableTree} in hand and need a hint about the array's size.
 *
 * <h2>Patterns recognized</h2>
 * <ul>
 *   <li>Direct annotation: {@code @Size(16) String comm} → 16</li>
 *   <li>Type-use annotation on a generic parameter: {@code BPFHashMap<@Size(N) String, V>} —
 *       extracted from the field's generic argument list</li>
 *   <li>Sizes on the variable's type (e.g. {@code @Size(10) int[] x})</li>
 * </ul>
 *
 * <p>Symbolic constants (e.g. {@code @Size(TASK_COMM_LEN)}) are not resolved here; the helper
 * only returns sizes that are integer literals. A caller wanting symbolic resolution must
 * consult {@code TreePath} / {@code Trees} themselves.
 */
public final class SizeInference {

    private static final String SIZE_SIMPLE_NAME = "Size";

    private SizeInference() {}

    /**
     * Look for an integer-literal {@code @Size(N)} on the variable's modifiers or its type.
     * Returns the first match, or empty if none found / if the size argument is not a literal.
     */
    public static OptionalInt inferSize(VariableTree var) {
        if (var == null) return OptionalInt.empty();
        var fromMods = sizeFromAnnotations(var.getModifiers());
        if (fromMods.isPresent()) return fromMods;
        return sizeFromType(var.getType());
    }

    /** Extract {@code @Size(N)} from a {@code ModifiersTree} (variable / parameter / field). */
    public static OptionalInt sizeFromAnnotations(ModifiersTree mods) {
        if (mods == null) return OptionalInt.empty();
        for (var ann : mods.getAnnotations()) {
            var size = readSize(ann);
            if (size.isPresent()) return size;
        }
        return OptionalInt.empty();
    }

    /**
     * Extract {@code @Size(N)} from a type expression — handles annotated types, generic type
     * arguments, and array types. Returns the first literal size encountered in a left-to-right
     * walk.
     */
    public static OptionalInt sizeFromType(Tree type) {
        if (type == null) return OptionalInt.empty();
        return switch (type) {
            case AnnotatedTypeTree at -> {
                for (var ann : at.getAnnotations()) {
                    var size = readSize(ann);
                    if (size.isPresent()) yield size;
                }
                yield sizeFromType(at.getUnderlyingType());
            }
            case ParameterizedTypeTree pt -> {
                for (var arg : pt.getTypeArguments()) {
                    var size = sizeFromType(arg);
                    if (size.isPresent()) yield size;
                }
                yield OptionalInt.empty();
            }
            case ArrayTypeTree at -> sizeFromType(at.getType());
            default -> OptionalInt.empty();
        };
    }

    /** Returns the integer-literal value of a {@code @Size(N)} annotation, if any. */
    static OptionalInt readSize(AnnotationTree ann) {
        if (!isSizeAnnotation(ann)) return OptionalInt.empty();
        for (var arg : ann.getArguments()) {
            // Either @Size(16) or @Size(value=16)
            ExpressionTree expr = arg;
            if (arg instanceof AssignmentTree a) expr = a.getExpression();
            var lit = literalIntValue(expr);
            if (lit.isPresent()) return lit;
        }
        return OptionalInt.empty();
    }

    private static boolean isSizeAnnotation(AnnotationTree ann) {
        var name = ann.getAnnotationType().toString();
        var simple = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : name;
        return simple.equals(SIZE_SIMPLE_NAME);
    }

    private static OptionalInt literalIntValue(ExpressionTree e) {
        if (e instanceof ParenthesizedTree p) return literalIntValue(p.getExpression());
        if (e instanceof UnaryTree u) {
            if (u.getKind() == Tree.Kind.UNARY_PLUS) return literalIntValue(u.getExpression());
            if (u.getKind() == Tree.Kind.UNARY_MINUS) {
                var inner = literalIntValue(u.getExpression());
                return inner.isPresent() ? OptionalInt.of(-inner.getAsInt()) : OptionalInt.empty();
            }
        }
        if (e instanceof LiteralTree lit && lit.getValue() instanceof Number n) {
            return OptionalInt.of(n.intValue());
        }
        return OptionalInt.empty();
    }

    /** Convenience: returns whether any {@code @Size} (literal or not) appears on the variable. */
    public static boolean hasAnySize(VariableTree var) {
        return hasSizeRecursive(var.getModifiers()) || hasSizeRecursive(var.getType());
    }

    private static boolean hasSizeRecursive(ModifiersTree mods) {
        if (mods == null) return false;
        for (var ann : mods.getAnnotations()) {
            if (isSizeAnnotation(ann)) return true;
        }
        return false;
    }

    private static boolean hasSizeRecursive(Tree type) {
        if (type == null) return false;
        return switch (type) {
            case AnnotatedTypeTree at -> {
                for (var ann : at.getAnnotations()) if (isSizeAnnotation(ann)) yield true;
                yield hasSizeRecursive(at.getUnderlyingType());
            }
            case ParameterizedTypeTree pt -> {
                for (var arg : pt.getTypeArguments()) if (hasSizeRecursive(arg)) yield true;
                yield false;
            }
            case ArrayTypeTree at -> hasSizeRecursive(at.getType());
            default -> false;
        };
    }

    /**
     * Wrap the integer in an {@code Optional<Integer>} (some callers want Optional rather than
     * OptionalInt). Convenience adaptor.
     */
    public static Optional<Integer> inferSizeBoxed(VariableTree var) {
        var s = inferSize(var);
        return s.isPresent() ? Optional.of(s.getAsInt()) : Optional.empty();
    }
}
