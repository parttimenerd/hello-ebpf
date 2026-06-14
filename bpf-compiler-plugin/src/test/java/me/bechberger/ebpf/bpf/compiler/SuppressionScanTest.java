package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.MethodTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link SuppressionScan} — the pre-pass that populates ctx.suppressionsAt. */
class SuppressionScanTest {

    @Test
    void methodLevelSuppressionAppliesToAllNestedTrees() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    @interface SuppressBPFWarning { String[] value(); }
                    @SuppressBPFWarning("region.user-deref")
                    void f(Object x) {
                        Object y = x;
                    }
                }
                """, "f");
        var ctx = new AnalysisContext();
        new SuppressionScan(ctx).scan(m);
        // The body's VariableTree should inherit the method's suppression.
        var locals = collectLocals(m);
        assertEquals(1, locals.size());
        assertTrue(ctx.isSuppressed(locals.get(0), "region.user-deref"),
                "method-level @SuppressBPFWarning must cascade to nested locals");
    }

    @Test
    void localLevelSuppressionAppliesToInitializerOnly() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    @interface SuppressBPFWarning { String[] value(); }
                    void f(Object x) {
                        @SuppressBPFWarning("region.mixing") Object y = x;
                        Object z = x;
                    }
                }
                """, "f");
        var ctx = new AnalysisContext();
        new SuppressionScan(ctx).scan(m);
        var locals = collectLocals(m);
        assertEquals(2, locals.size());
        assertTrue(ctx.isSuppressed(locals.get(0), "region.mixing"));
        assertFalse(ctx.isSuppressed(locals.get(1), "region.mixing"),
                "sibling local must not inherit the suppression");
    }

    @Test
    void multipleCategoriesAreAllRecorded() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    @interface SuppressBPFWarning { String[] value(); }
                    @SuppressBPFWarning({"region.user-deref", "bounds.unguarded"})
                    void f() {
                        int x = 1;
                    }
                }
                """, "f");
        var ctx = new AnalysisContext();
        new SuppressionScan(ctx).scan(m);
        var locals = collectLocals(m);
        assertTrue(ctx.isSuppressed(locals.get(0), "region.user-deref"));
        assertTrue(ctx.isSuppressed(locals.get(0), "bounds.unguarded"));
        assertFalse(ctx.isSuppressed(locals.get(0), "helper.context"));
    }

    @Test
    void allSpecialKeywordSuppressesEverything() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    @interface SuppressBPFWarning { String[] value(); }
                    @SuppressBPFWarning("all")
                    void f() {
                        int x = 1;
                    }
                }
                """, "f");
        var ctx = new AnalysisContext();
        new SuppressionScan(ctx).scan(m);
        var locals = collectLocals(m);
        // "all" should suppress arbitrary categories.
        assertTrue(ctx.isSuppressed(locals.get(0), "anything-here"));
        assertTrue(ctx.isSuppressed(locals.get(0), "region.user-deref"));
    }

    @Test
    void unannotatedMethodHasNoSuppressions() {
        var m = JavacTestSupport.parseMethod("""
                class T {
                    void f(Object x) {
                        Object y = x;
                    }
                }
                """, "f");
        var ctx = new AnalysisContext();
        new SuppressionScan(ctx).scan(m);
        assertTrue(ctx.suppressionsAt.isEmpty(), "no annotation → no entries");
        var locals = collectLocals(m);
        assertFalse(ctx.isSuppressed(locals.get(0), "region.user-deref"));
    }

    @Test
    void enclosingClassAnnotationDoesNotCascadeWhenScanningOnlyTheMethod() {
        // KNOWN SCOPE: SuppressionScan.scan(method) starts at the method tree, so an annotation
        // on the *enclosing class* is invisible to the cascade. Document this so we don't
        // accidentally regress when refactoring.
        var m = JavacTestSupport.parseMethod("""
                @interface SuppressBPFWarning { String[] value(); }
                @SuppressBPFWarning("region.user-deref")
                class T {
                    void f(Object x) {
                        Object y = x;
                    }
                }
                """, "f");
        var ctx = new AnalysisContext();
        new SuppressionScan(ctx).scan(m);
        var locals = collectLocals(m);
        assertEquals(1, locals.size());
        // The enclosing-class annotation does NOT propagate when scanning only the method.
        assertFalse(ctx.isSuppressed(locals.get(0), "region.user-deref"),
                "scan(method) is method-scoped — enclosing class annotations don't cascade");
    }

    @Test
    void namedValueAttributeWithArrayIsRecognised() {
        // @SuppressBPFWarning(value = {"a", "b"}) — explicit attribute name and array literal.
        var m = JavacTestSupport.parseMethod("""
                class T {
                    @interface SuppressBPFWarning { String[] value(); }
                    @SuppressBPFWarning(value = {"region.mixing", "bounds.unguarded"})
                    void f() { int x = 1; }
                }
                """, "f");
        var ctx = new AnalysisContext();
        new SuppressionScan(ctx).scan(m);
        var locals = collectLocals(m);
        assertTrue(ctx.isSuppressed(locals.get(0), "region.mixing"));
        assertTrue(ctx.isSuppressed(locals.get(0), "bounds.unguarded"));
    }

    private static List<VariableTree> collectLocals(MethodTree m) {
        var out = new ArrayList<VariableTree>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(VariableTree node, Void unused) {
                // Skip method parameters (they're at the MethodTree level, not in the body).
                if (m.getParameters().contains(node)) return super.visitVariable(node, unused);
                out.add(node);
                return super.visitVariable(node, unused);
            }
        }.scan(m, null);
        return out;
    }
}
