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

    // ── Test 4: 'this' as a bare argument in @BPFJavaInline body ─────────────
    //
    // Strategy: 'this' is passed as an argument to a @BuiltinBPFFunction whose
    // template substitutes $arg1 directly.  The Translator must look up 'this'
    // in localCarrierMap to produce the receiver carrier expression.  If the
    // short-circuit at Translator.java:598 fires instead (returning "this"
    // literally), the second assertion catches it.
    //
    // This is stronger than the previous fixture (this.doubleIt(x)), where the
    // @BPFFunction dispatcher strips the receiver before 'this' can be evaluated.
    //
    // Pre-Task-3 (current state): the @BPFAbstraction gate blocks inlining for
    //   non-abstraction classes entirely; the fallback @BuiltinBPFFunction("0")
    //   is used.  No GNU statement expression ({ ... }) appears in the output.
    //   assertFalse(inlinedBlocks.isEmpty()) FAILS — the test is RED.
    //
    // Post-Task-3 (gate lifted + this-substitution reordered):
    //   1. The body is inlined into a ({ ... }) block — first assertion passes.
    //   2. 'this' resolves to the receiver carrier expression (not the literal C
    //      identifier "this") — second assertion passes.  GREEN.
    //
    // If the gate is lifted but Translator.java:598 is NOT reordered, the inlined
    // block appears but contains a bare "this" token — the second assertion fails,
    // catching the regression.

    @BPF(license = "GPL")
    public static abstract class ThisSubstitutionTest extends BPFProgram {

        /**
         * Passes {@code this} as a bare value to a @BuiltinBPFFunction.
         * The template "(long)($arg1)" substitutes the translated argument
         * expression for $arg1.  If 'this' flows through localCarrierMap the
         * result is the carrier expression; if the short-circuit fires first,
         * the result is the literal C identifier "this".
         * The fallback "0" is used pre-Task-3 when inlining is blocked.
         */
        @BPFJavaInline
        @NotUsableInJava
        @BuiltinBPFFunction("0")
        public long passSelf() {
            long pre = 0;  // dummy intermediate statement to force multi-stmt body and ({}) wrapper
            return identityArg(this);
        }

        /**
         * Identity template: $arg1 is substituted with the translated argument
         * expression.  Static so it has no receiver of its own.
         */
        @BuiltinBPFFunction("(long)($arg1)")
        @NotUsableInJava
        static long identityArg(Object self) { throw new MethodIsBPFRelatedFunction(); }

        @BPFFunction
        public long invokePassSelf() {
            return passSelf();
        }
    }

    @Test
    void javaInlineThisSubstitution() {
        String code = stripped(codeOf(ThisSubstitutionTest.class));
        // Collect all lines that contain an inlined GNU statement expression block.
        var inlinedBlocks = code.lines()
                .filter(l -> l.contains("({") && l.contains("})"))
                .toList();
        // Pre-Task-3: no inlining happens at all — the ({ ... }) block is absent.
        assertFalse(inlinedBlocks.isEmpty(),
                "Expected @BPFJavaInline body to be inlined at call site as a GNU "
                + "statement expression ({ ... }); got:\n" + code);
        // Post-Task-3: the inlined block must NOT contain a bare 'this' token.
        // 'this' must have been replaced with the receiver carrier expression.
        var hasBareThis = inlinedBlocks.stream()
                .anyMatch(l -> l.matches(".*\\bthis\\b.*"));
        assertFalse(hasBareThis,
                "'this' inside @BPFJavaInline body must resolve to the receiver "
                + "carrier expression, not the literal C identifier 'this'; "
                + "got inlined blocks:\n" + String.join("\n", inlinedBlocks));
    }
}
