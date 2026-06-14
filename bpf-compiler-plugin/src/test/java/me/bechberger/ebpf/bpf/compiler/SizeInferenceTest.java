package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.MethodTree;
import com.sun.source.tree.VariableTree;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.OptionalInt;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link SizeInference}. */
class SizeInferenceTest {

    private static VariableTree firstLocal(String src, String methodName) {
        MethodTree m = JavacTestSupport.parseMethod(src, methodName);
        // Pull the first VariableTree inside the body.
        var body = m.getBody();
        for (var stmt : body.getStatements()) {
            if (stmt instanceof VariableTree v) return v;
        }
        throw new AssertionError("no local variable found");
    }

    private static VariableTree firstParam(String src, String methodName) {
        return JavacTestSupport.parseMethod(src, methodName).getParameters().get(0);
    }

    @Test
    void directSizeAnnotationOnLocalIsReadable() {
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    void f() {
                        @Size(16) String s = "";
                    }
                }
                """, "f");
        assertEquals(OptionalInt.of(16), SizeInference.inferSize(v));
    }

    @Test
    void sizeOnParameterTypeIsReadable() {
        // @Size(8) byte[] x — annotation on the type, not the variable's modifiers.
        var p = firstParam("""
                class T {
                    @interface Size { int value(); }
                    void f(@Size(8) byte[] x) { }
                }
                """, "f");
        assertEquals(OptionalInt.of(8), SizeInference.inferSize(p));
    }

    @Test
    void sizeInGenericTypeArgumentIsReadable() {
        // The Map's key has @Size(64) — inference should pull it out.
        var p = firstParam("""
                class T {
                    @interface Size { int value(); }
                    interface Map<K, V> {}
                    void f(Map<@Size(64) String, Integer> m) { }
                }
                """, "f");
        assertEquals(OptionalInt.of(64), SizeInference.inferSize(p));
    }

    @Test
    void sizeWithExplicitValueArgumentIsReadable() {
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    void f() {
                        @Size(value = 32) String s = "";
                    }
                }
                """, "f");
        assertEquals(OptionalInt.of(32), SizeInference.inferSize(v));
    }

    @Test
    void noSizeYieldsEmpty() {
        var v = firstLocal("""
                class T {
                    void f() {
                        String s = "";
                    }
                }
                """, "f");
        assertEquals(OptionalInt.empty(), SizeInference.inferSize(v));
    }

    @Test
    void symbolicConstantSizeYieldsEmpty() {
        // @Size(TASK_COMM_LEN) — not a literal, so not resolvable here. The point: never lie
        // about the size; emit empty so the caller falls back to whatever it does normally.
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    static final int TASK_COMM_LEN = 16;
                    void f() {
                        @Size(TASK_COMM_LEN) String s = "";
                    }
                }
                """, "f");
        assertEquals(OptionalInt.empty(), SizeInference.inferSize(v),
                "symbolic constants are out of scope for the syntactic helper");
    }

    @Test
    void hasAnySizeReportsSymbolicSizeToo() {
        // Even though we can't resolve TASK_COMM_LEN to an int, hasAnySize should still report
        // that *a* @Size annotation is present. This lets callers say "the user remembered to
        // annotate; trust them" without committing to a specific number.
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    static final int TASK_COMM_LEN = 16;
                    void f() {
                        @Size(TASK_COMM_LEN) String s = "";
                    }
                }
                """, "f");
        assertTrue(SizeInference.hasAnySize(v));
    }

    @Test
    void hasAnySizeIsFalseWhenAbsent() {
        var v = firstLocal("""
                class T {
                    void f() { String s = ""; }
                }
                """, "f");
        assertFalse(SizeInference.hasAnySize(v));
    }

    @Test
    void boxedFormReturnsSameValue() {
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    void f() { @Size(7) String s = ""; }
                }
                """, "f");
        assertEquals(7, SizeInference.inferSizeBoxed(v).orElseThrow());
    }

    @Test
    void typeParameterSizeBeatsPlainTypeArgWhenBothPresent() {
        // First match wins — left-to-right scan. The first @Size encountered should be 5,
        // not 9.
        var p = firstParam("""
                class T {
                    @interface Size { int value(); }
                    interface Map<K, V> {}
                    void f(Map<@Size(5) String, @Size(9) Integer> m) { }
                }
                """, "f");
        assertEquals(OptionalInt.of(5), SizeInference.inferSize(p));
    }

    @Test
    void arrayTypeSizeIsReadable() {
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    void f() { @Size(10) int[] a = null; }
                }
                """, "f");
        assertEquals(OptionalInt.of(10), SizeInference.inferSize(v));
    }

    @Test
    void parenthesizedSizeIsReadable() {
        // @Size((16)) — parens around the literal must not defeat extraction.
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    void f() { @Size((16)) String s = ""; }
                }
                """, "f");
        assertEquals(OptionalInt.of(16), SizeInference.inferSize(v));
    }

    @Test
    void unaryPlusSizeIsReadable() {
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    void f() { @Size(+12) String s = ""; }
                }
                """, "f");
        assertEquals(OptionalInt.of(12), SizeInference.inferSize(v));
    }

    @Test
    void zeroSizeIsReadableButCallerShouldRejectIt() {
        // The helper itself doesn't validate "size > 0". It only extracts what's there.
        // Document this so callers know to guard themselves.
        var v = firstLocal("""
                class T {
                    @interface Size { int value(); }
                    void f() { @Size(0) String s = ""; }
                }
                """, "f");
        assertEquals(OptionalInt.of(0), SizeInference.inferSize(v),
                "extractor returns the literal as-is — callers must guard against 0/negative");
    }
}
