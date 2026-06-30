package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;

import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TDD tests for generalising {@code @BPFJavaInline} beyond {@code @BPFAbstraction} classes.
 *
 * <p>Tests 1, 2, and 4 are RED on the current codebase because
 * {@code Translator.tryInlineAbstractionMethod} short-circuits at the
 * {@code @BPFAbstraction} gate (Translator.java:2409) and never inlines
 * methods on plain (non-abstraction) classes.
 *
 * <p>Test 3 is the control: the existing {@code @BPFAbstraction} + {@code @BPFJavaInline}
 * behaviour must continue to work unchanged after Task 3.
 */
class BPFJavaInlineGeneralisationTest {

    // ── helpers ───────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    static String codeOf(Class<?> cls) {
        return BPFProgram.getCode((Class<? extends BPFProgram>) cls);
    }

    static String stripped(String code) {
        return code.lines()
                .filter(l -> !l.trim().startsWith("#line "))
                .map(l -> l.replace("__always_inline ", ""))
                .collect(Collectors.joining("\n"));
    }

    // ── Test 1: @BPFJavaInline works on a non-@BPFAbstraction class ──────────
    //
    // The @BPF program class itself is not @BPFAbstraction.  The method
    // 'multiStep' is annotated @BPFJavaInline with a multi-statement body.
    // Pre-Task-3: the @BPFAbstraction gate blocks inlining; the fallback
    // @BuiltinBPFFunction("$arg1") is used instead — no GNU statement
    // expression appears.
    // Post-Task-3: the body is inlined into a ({ ... }) block.

    @BPF(license = "GPL")
    public static abstract class NonAbstractionInlineTest extends BPFProgram {

        /** Multi-statement body; the fallback template just forwards the argument. */
        @BPFJavaInline
        @NotUsableInJava
        @BuiltinBPFFunction("$arg1")
        public long multiStep(long x) {
            long doubled = x * 2L;
            return doubled + 1L;
        }

        @BPFFunction
        public long invokeMultiStep(long x) {
            return this.multiStep(x);
        }
    }

    @Test
    void javaInlineWorksOnNonAbstractionClass() {
        String code = stripped(codeOf(NonAbstractionInlineTest.class));
        // Pre-Task-3: fallback $arg1 is used; no GNU statement expression emitted.
        // Post-Task-3: multi-statement body is inlined as ({ long doubled = x * 2L; doubled + 1L }).
        assertTrue(code.contains("({"),
                "Expected GNU statement expression from inlined multi-step body; got:\n" + code);
    }

    // ── Test 2: field reference in @BPFJavaInline body on non-abstraction ────
    //
    // On a @BPFAbstraction class the single instance field is substituted by the
    // carrier expression.  On a non-@BPFAbstraction class the field must NOT be
    // carrier-substituted: it must appear as its own name in the inlined C.
    //
    // Pre-Task-3: gate blocks inlining; fallback "0" is used — STEP never appears.
    // Post-Task-3: body is inlined and STEP appears verbatim in the ({ ... }).

    @BPF(license = "GPL")
    public static abstract class NonAbstractionFieldTest extends BPFProgram {

        private static final long STEP = 7L;

        /** Body references the static constant STEP; fallback always returns 0. */
        @BPFJavaInline
        @NotUsableInJava
        @BuiltinBPFFunction("0")
        public long addStep(long x) {
            long base = STEP;
            return base + x;
        }

        @BPFFunction
        public long invokeAddStep(long x) {
            return this.addStep(x);
        }
    }

    @Test
    void javaInlineFieldSubstitutionStillRequiresAbstraction() {
        String code = stripped(codeOf(NonAbstractionFieldTest.class));
        // Pre-Task-3: fallback "0" is used; STEP never appears in C output.
        // Post-Task-3: body is inlined; STEP (a #define) appears in the GNU stmt expr.
        assertTrue(code.contains("STEP"),
                "Expected field/constant name STEP to appear in inlined body; got:\n" + code);
        assertTrue(code.contains("({"),
                "Expected GNU statement expression from inlined body; got:\n" + code);
    }

    // ── Test 3 (control): @BPFAbstraction + @BPFJavaInline carrier substitution
    //
    // This mirrors BPFAbstractionTest Test 12 (Counter + ReturnValueTest).
    // It PASSES on the current codebase and must continue to pass after Task 3.

    @BPFAbstraction(constructorPrependTo = "")
    public static final class SmallCounter {

        @NotUsableInJava
        private final int count = 0;

        @BuiltinBPFFunction(value = "", carrier = "$arg1")
        @NotUsableInJava
        public static SmallCounter of(int count) { throw new MethodIsBPFRelatedFunction(); }

        /** Returns the carrier value doubled. */
        @BPFJavaInline
        @NotUsableInJava
        public int doubled() { return count * 2; }
    }

    @BPF(license = "GPL")
    public static abstract class CarrierControlTest extends BPFProgram {

        @BPFFunction
        public int getDoubled(int n) {
            SmallCounter c = SmallCounter.of(n);
            return c.doubled();
        }
    }

    @Test
    void javaInlineCarrierSubstitutionStillWorksOnAbstraction() {
        String code = stripped(codeOf(CarrierControlTest.class));
        // doubled() body is "return count * 2;" where count = carrier = n.
        // GNU statement expression must NOT contain "return " — last stmt → bare expr.
        long returnInGnuStmt = code.lines()
                .filter(l -> l.contains("({") && l.contains("return "))
                .count();
        assertTrue(returnInGnuStmt == 0,
                "GNU statement expression must not contain 'return'; got\n" + code);
        assertTrue(code.contains("* 2"),
                "doubled() expression 'n * 2' or similar must appear\n" + code);
    }

    // ── Test 4: 'this' in @BPFJavaInline body must be substituted ────────────
    //
    // This tests a secondary bug: even on @BPFAbstraction classes (where inlining
    // already fires today), a bare 'this' in the body is emitted verbatim as the
    // C identifier "this" because Translator.java:598 short-circuits 'this' before
    // checking localCarrierMap.
    //
    // Pre-Task-3: @BPFAbstraction inlining fires; body contains 'this' passed as
    //   an argument to @BuiltinBPFFunction("($arg1)") → C emits "(this)".
    //   assertFalse(c.contains("this")) FAILS.
    // Post-Task-3: 'this' is routed through localCarrierMap → substituted with the
    //   carrier expression (e.g. "v") → no literal "this" in emitted C.
    //   assertFalse(c.contains("this")) PASSES.

    @BPFAbstraction(constructorPrependTo = "")
    public static final class TWrapper {

        @NotUsableInJava
        private final int val = 0;

        @BuiltinBPFFunction(value = "", carrier = "$arg1")
        @NotUsableInJava
        public static TWrapper of(int val) { throw new MethodIsBPFRelatedFunction(); }

        /** Body explicitly references 'this' as an argument — the key test vector. */
        @BPFJavaInline
        @NotUsableInJava
        public int passThrough() {
            return doPassThrough(this);
        }

        /** Identity function: returns arg1 verbatim. */
        @BuiltinBPFFunction("($arg1)")
        @NotUsableInJava
        static int doPassThrough(TWrapper tw) { throw new MethodIsBPFRelatedFunction(); }
    }

    @BPF(license = "GPL")
    public static abstract class ThisSubstitutionTest extends BPFProgram {

        @BPFFunction
        public int getPassThrough(int v) {
            TWrapper w = TWrapper.of(v);
            return w.passThrough();
        }
    }

    @Test
    void javaInlineThisSubstitution() {
        String code = stripped(codeOf(ThisSubstitutionTest.class));
        // Pre-Task-3: inlining fires (TWrapper is @BPFAbstraction) but 'this' in
        //   the inner body is emitted verbatim → C contains "this" → assertFalse fails.
        // Post-Task-3: 'this' is substituted with the carrier expression → no literal
        //   "this" appears in the emitted C → assertFalse passes.
        assertFalse(code.contains("this"),
                "Java 'this' must not appear in emitted C after inlining; got:\n" + code);
    }
}
