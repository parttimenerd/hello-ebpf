package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link StringConcatSupport}. */
class StringConcatSupportTest {

    /** Pull the RHS expression of {@code String x = ...} from a parsed method body. */
    private static ExpressionTree rhsOfStringDecl(String source) {
        var m = JavacTestSupport.parseMethod(source, "f");
        var holder = new ArrayList<ExpressionTree>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(com.sun.source.tree.VariableTree node, Void unused) {
                if (holder.isEmpty() && node.getInitializer() != null) {
                    holder.add(node.getInitializer());
                }
                return super.visitVariable(node, unused);
            }
        }.scan(m.getBody(), null);
        return holder.get(0);
    }

    @Test
    void unparenStripsParentheses() {
        var rhs = rhsOfStringDecl("class T { void f() { String x = ((\"a\")); } }");
        var unparened = StringConcatSupport.unparen(rhs);
        assertTrue(unparened instanceof LiteralTree);
    }

    @Test
    void flattenSingleLiteralProducesOneOperand() {
        var rhs = rhsOfStringDecl("class T { void f() { String x = \"hi\"; } }");
        var flat = StringConcatSupport.flatten(rhs, b -> true);
        assertEquals(1, flat.size());
    }

    @Test
    void flattenLeftAssociativeChain() {
        // Note: javac folds adjacent string literals during parse, so each operand needs to be
        // a non-literal expression (parameter / identifier) to keep the BinaryTree shape.
        // s + t + u → ((s + t) + u) → 3 operands.
        var rhs = rhsOfStringDecl("class T { void f(String s, String t, String u) { String x = s + t + u; } }");
        var flat = StringConcatSupport.flatten(rhs, b -> b.getKind() == Tree.Kind.PLUS);
        assertEquals(3, flat.size());
    }

    @Test
    void flattenRespectsPredicate() {
        // If predicate returns false, no flattening happens.
        var rhs = rhsOfStringDecl("class T { void f(String s) { String x = s + \"b\"; } }");
        var flat = StringConcatSupport.flatten(rhs, b -> false);
        assertEquals(1, flat.size()); // the whole BinaryTree as a single operand
    }

    @Test
    void flattenWithParenthesizedSubExpression() {
        // (s + t) + u — parens around inner concat shouldn't block flattening.
        var rhs = rhsOfStringDecl("class T { void f(String s, String t, String u) { String x = (s + t) + u; } }");
        var flat = StringConcatSupport.flatten(rhs, b -> b.getKind() == Tree.Kind.PLUS);
        assertEquals(3, flat.size());
    }

    @Test
    void tryFoldAllLiterals() {
        // Synthesize the operand list directly via flatten on a non-literal chain, then verify
        // tryFold rejects it (because the chain has a parameter). The all-literals case is
        // exercised in tryFoldEmptyOperandsYieldsEmptyString and via the single-literal path.
        var rhs = rhsOfStringDecl("class T { void f() { String x = \"abc\"; } }");
        // Single literal — flatten yields one operand, fold succeeds.
        var flat = StringConcatSupport.flatten(rhs, b -> b.getKind() == Tree.Kind.PLUS);
        var folded = StringConcatSupport.tryFold(flat);
        assertTrue(folded.isPresent());
        assertEquals("abc", folded.get());
    }

    @Test
    void tryFoldEmptyOperandsYieldsEmptyString() {
        var folded = StringConcatSupport.tryFold(List.of());
        assertTrue(folded.isPresent());
        assertEquals("", folded.get());
    }

    @Test
    void tryFoldRejectsNonLiteralOperand() {
        var rhs = rhsOfStringDecl("class T { void f(String s) { String x = s + \"a\"; } }");
        var flat = StringConcatSupport.flatten(rhs, b -> b.getKind() == Tree.Kind.PLUS);
        var folded = StringConcatSupport.tryFold(flat);
        assertTrue(folded.isEmpty());
    }

    @Test
    void formatStringForCounts() {
        assertEquals("", StringConcatSupport.formatStringFor(0));
        assertEquals("%s", StringConcatSupport.formatStringFor(1));
        assertEquals("%s%s%s", StringConcatSupport.formatStringFor(3));
    }

    @Test
    void escapeForCHandlesQuotesAndBackslashes() {
        assertEquals("hello", StringConcatSupport.escapeForC("hello"));
        assertEquals("a\\\"b", StringConcatSupport.escapeForC("a\"b"));
        assertEquals("a\\\\b", StringConcatSupport.escapeForC("a\\b"));
        assertEquals("a\\nb", StringConcatSupport.escapeForC("a\nb"));
        assertEquals("a\\tb", StringConcatSupport.escapeForC("a\tb"));
    }

    @Test
    void escapeForCEscapesNonPrintable() {
        var escaped = StringConcatSupport.escapeForC("");
        assertEquals("\\x01", escaped);
    }
}
