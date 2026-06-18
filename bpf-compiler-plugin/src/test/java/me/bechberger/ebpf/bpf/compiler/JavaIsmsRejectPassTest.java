package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link JavaIsmsRejectPass#detect(com.sun.source.tree.Tree)} — the pure detection
 * function used by the pass. The category-tagged messages and the AST patterns that produce them
 * are the user-facing contract; suppression is tested separately in {@link SuppressionScanTest}.
 */
class JavaIsmsRejectPassTest {

    private static List<JavaIsmsRejectPass.Detection> detect(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        return JavaIsmsRejectPass.detect(m.getBody());
    }

    private static void assertSingle(List<JavaIsmsRejectPass.Detection> detections, String category) {
        assertEquals(1, detections.size(),
                "expected exactly one detection of category " + category + ", got " + detections);
        assertEquals(category, detections.get(0).category());
        // 4-part message contract: at minimum a "Why:" and "Fix:" line.
        var msg = detections.get(0).message();
        assertTrue(msg.contains("Why:"), "missing 'Why:' in: " + msg);
        assertTrue(msg.contains("Fix:"), "missing 'Fix:' in: " + msg);
    }

    @Test
    void throwStatementIsRejected() {
        var d = detect("""
                class T {
                    void f() { throw new RuntimeException("x"); }
                }
                """, "f");
        assertSingle(d, "java-isms.throw");
    }

    @Test
    void assertStatementIsRejected() {
        var d = detect("""
                class T {
                    void f(int x) { assert x > 0; }
                }
                """, "f");
        assertSingle(d, "java-isms.assert");
    }

    @Test
    void stringFormatIsRejected() {
        var d = detect("""
                class T {
                    void f() { String.format("%d", 1); }
                }
                """, "f");
        assertSingle(d, "java-isms.string-concat");
    }

    @Test
    void optionalUsageIsRejected() {
        var d = detect("""
                class T {
                    void f() { Optional.empty(); }
                }
                """, "f");
        assertSingle(d, "java-isms.optional");
    }

    @Test
    void mathRandomIsRejected() {
        var d = detect("""
                class T {
                    void f() { Math.random(); }
                }
                """, "f");
        assertSingle(d, "java-isms.random");
    }

    @Test
    void threadSleepIsRejected() {
        var d = detect("""
                class T {
                    void f() { Thread.sleep(100); }
                }
                """, "f");
        assertSingle(d, "java-isms.thread");
    }

    @Test
    void systemOutPrintlnIsRejected() {
        var d = detect("""
                class T {
                    void f() { System.out.println("x"); }
                }
                """, "f");
        assertSingle(d, "java-isms.system-out");
    }

    @Test
    void systemErrPrintlnIsRejected() {
        var d = detect("""
                class T {
                    void f() { System.err.println("x"); }
                }
                """, "f");
        assertSingle(d, "java-isms.system-out");
    }

    @Test
    void newArrayWithNonConstantSizeIsRejected() {
        var d = detect("""
                class T {
                    void f(int n) { int[] a = new int[n]; }
                }
                """, "f");
        assertEquals(1, d.size());
        assertEquals("java-isms.heap-array", d.get(0).category());
    }

    @Test
    void newArrayWithLiteralSizeIsAllowed() {
        var d = detect("""
                class T {
                    void f() { int[] a = new int[16]; }
                }
                """, "f");
        assertTrue(d.isEmpty(), "literal-sized arrays should not trigger heap-array: " + d);
    }

    @Test
    void newArrayWithUnaryNegativeLiteralIsAllowed() {
        // Unusual but the helper accepts it; document the behavior.
        var d = detect("""
                class T {
                    void f() { int[] a = new int[+8]; }
                }
                """, "f");
        assertTrue(d.isEmpty(), "+literal-sized arrays should not trigger heap-array: " + d);
    }

    @Test
    void cleanMethodHasNoDetections() {
        var d = detect("""
                class T {
                    int f(int x) { return x + 1; }
                }
                """, "f");
        assertTrue(d.isEmpty(), "clean method should have zero detections, got: " + d);
    }

    @Test
    void multipleViolationsAllReported() {
        var d = detect("""
                class T {
                    void f() {
                        String.format("%d", 1);
                        Math.random();
                        throw new RuntimeException();
                    }
                }
                """, "f");
        assertEquals(3, d.size(), "all three violations should be reported: " + d);
    }

    @Test
    void stringPlusOperatorIsCurrentlyNotFlagged() {
        // KNOWN GAP: the doc on JavaIsmsRejectPass.java mentions "a" + "b" for the
        // java-isms.string-concat category, but the visitor only catches String.format,
        // not BinaryTree string concatenation. Pin the current behavior so we notice
        // when this is tightened up.
        var d = detect("""
                class T {
                    String f(String name) { return "hello " + name; }
                }
                """, "f");
        assertTrue(d.isEmpty(),
                "string '+' is currently a known gap — Translator catches it later: " + d);
    }

    @Test
    void newRandomConstructorIsRejected() {
        // Constructor calls land in visitNewClass; the static `Math.random()` path is
        // covered by mathRandomIsRejected.
        var d = detect("""
                class T {
                    void f() { Object r = new java.util.Random(); }
                }
                """, "f");
        assertSingle(d, "java-isms.random");
    }

    @Test
    void integerValueOfIsRejected() {
        var d = detect("""
                class T {
                    Object f() { return Integer.valueOf(7); }
                }
                """, "f");
        assertSingle(d, "java-isms.autobox");
    }

    @Test
    void longValueOfIsRejected() {
        var d = detect("""
                class T {
                    Object f() { return Long.valueOf(7L); }
                }
                """, "f");
        assertSingle(d, "java-isms.autobox");
    }

    @Test
    void integerParseIntIsNotAutoboxFlagged() {
        // valueOf is the autobox primitive; parseInt returns int — must not be flagged.
        var d = detect("""
                class T {
                    int f(String s) { return Integer.parseInt(s); }
                }
                """, "f");
        assertTrue(d.isEmpty(), "Integer.parseInt is not an autobox: " + d);
    }

    @Test
    void qualifiedOptionalReceiverIsCaught() {
        // The pass uses receiver.endsWith(".Optional") for fully-qualified references.
        var d = detect("""
                class T {
                    void f() { java.util.Optional.empty(); }
                }
                """, "f");
        assertSingle(d, "java-isms.optional");
    }

    @Test
    void newArrayWithNamedConstantIsConservativelyRejected() {
        // KNOWN: even a `final int N = 16; new int[N]` is rejected because the helper
        // can't see across symbols. Pin the current conservative behavior — users can
        // suppress with @SuppressBPFWarning("java-isms.heap-array") or use a literal.
        var d = detect("""
                class T {
                    void f() {
                        final int N = 16;
                        int[] a = new int[N];
                    }
                }
                """, "f");
        assertEquals(1, d.size(),
                "even compile-time-final symbols are flagged (conservative): " + d);
        assertEquals("java-isms.heap-array", d.get(0).category());
    }
}
