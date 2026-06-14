package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.Tree;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Pure helpers for translating Java {@code String} concatenation in BPF programs.
 *
 * <h2>Two paths</h2>
 * <ol>
 *   <li><b>Literal fold</b>: when every operand of a {@code +}-chain is a string literal, the
 *       chain folds to a single literal at compile time.</li>
 *   <li><b>Runtime snprintf</b>: when the concat result is assigned to an {@code @Size(N) String}
 *       destination, the Translator emits {@code BPF_SNPRINTF(dst, sizeof(dst), "%s%s...", a, b, ...)}.</li>
 * </ol>
 *
 * <p>Anything else (e.g. {@code f(a + b)}, returning a concat) is rejected with a 4-part error.
 */
public final class StringConcatSupport {

    private StringConcatSupport() {}

    /** Strip enclosing {@code (...)}. Used because Javac wraps operands in {@code ParenthesizedTree}. */
    public static ExpressionTree unparen(ExpressionTree e) {
        while (e instanceof ParenthesizedTree p) e = p.getExpression();
        return e;
    }

    /**
     * Flatten a left-associative {@code a + b + c} chain into {@code [a, b, c]}. The classifier
     * for "is this a concat sub-tree" is supplied by the caller (it needs javac type info).
     */
    public static List<ExpressionTree> flatten(ExpressionTree expr,
                                                java.util.function.Predicate<BinaryTree> isStringPlus) {
        var out = new ArrayList<ExpressionTree>();
        flattenInto(expr, isStringPlus, out);
        return out;
    }

    private static void flattenInto(ExpressionTree expr,
                                     java.util.function.Predicate<BinaryTree> isStringPlus,
                                     List<ExpressionTree> out) {
        var e = unparen(expr);
        if (e instanceof BinaryTree b
                && b.getKind() == Tree.Kind.PLUS
                && isStringPlus.test(b)) {
            flattenInto(b.getLeftOperand(), isStringPlus, out);
            flattenInto(b.getRightOperand(), isStringPlus, out);
        } else {
            out.add(e);
        }
    }

    /**
     * If every operand is a string literal, return the concatenated value. Otherwise empty.
     * The result is the raw string content (caller wraps it in a {@code "..."} literal as needed).
     */
    public static Optional<String> tryFold(List<ExpressionTree> operands) {
        var sb = new StringBuilder();
        for (var op : operands) {
            var u = unparen(op);
            if (!(u instanceof LiteralTree lit) || !(lit.getValue() instanceof String s)) {
                return Optional.empty();
            }
            sb.append(s);
        }
        return Optional.of(sb.toString());
    }

    /** Build a {@code "%s%s...%s"} format with one {@code %s} per operand. */
    public static String formatStringFor(int n) {
        return "%s".repeat(n);
    }

    /** Escape a string for embedding inside a C double-quoted literal. */
    public static String escapeForC(String s) {
        var sb = new StringBuilder(s.length() + 2);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\0' -> sb.append("\\0");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        sb.append(String.format("\\x%02x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
