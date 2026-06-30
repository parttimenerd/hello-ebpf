package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.type.Struct;
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

    // ── Test 4: 'this' substitution in @BPFJavaInline body — non-@BPFAbstraction class ──
    //
    // Strategy: define a @Type struct class Plain (NOT @BPFAbstraction) that has a
    // @BPFJavaInline instance method passThrough() which passes 'this' as an argument
    // to a @BuiltinBPFFunction.  The call site in invokePassThrough(Plain p) receives
    // a Plain parameter 'p' and calls p.passThrough().
    //
    // When translating p.passThrough():
    //   - receiverExpr = JCIdent for 'p' (a method parameter)
    //   - translate(p) → C identifier "p" (parameter's enclosing element is the method,
    //     not a class, so the default-return path fires)
    //   - carrierExpr = "p"
    //   - innerCarrierMap.put("this", "p") ← the line Task 3 added
    //
    // Inside the inlined body:
    //   - 'this' IdentifierTree → localCarrierMap.get("this") = "p"  ← Task 3 IdentifierTree reorder
    //   - fieldN(this) → @BuiltinBPFFunction("($arg1).n") with $arg1="p" → "(p).n"
    //   - The dummy 'long pre' forces 2 non-blank statements, so the ({...}) wrapper fires.
    //
    // Post-Task-3: GNU statement expression is emitted; 'this' does NOT appear inside it.
    //
    // Regression guard:
    //   Removing innerCarrierMap.put("this", carrierExpr) → 'this' stays in inlined body → RED
    //   Removing the IdentifierTree carrier-map reorder   → 'this' emitted verbatim → RED
    //   Removing tryInlineJavaInlineMethod gate-lift      → fallback BuiltinBPFFunction
    //                                                       used (no ({}) wrapper) → RED

    @BPF(license = "GPL")
    public static abstract class ThisSubstitutionTest extends BPFProgram {

        /**
         * Plain BPF struct (NOT @BPFAbstraction), nested inside the @BPF program so
         * that its C struct definition is emitted by the annotation processor.
         * Its @BPFJavaInline method references {@code this} — which must resolve to
         * the caller's receiver expression, not the literal C identifier {@code this}.
         */
        @Type
        public static class Plain extends Struct {
            long n;

            /**
             * Passes {@code this} as a bare argument to a @BuiltinBPFFunction.
             * The dummy {@code long pre} forces a multi-statement body so the
             * ({@code {...}}) wrapper is always emitted, making the inlined block
             * detectable by the test.
             */
            @BPFJavaInline
            @NotUsableInJava
            public long passThrough() {
                long pre = 0L;
                return fieldN(this);
            }

            /**
             * Reads field 'n' of the struct argument.
             * ($arg1).n is valid C for both struct value and struct Plain arguments.
             * When 'this' substitution works, $arg1 becomes "p" → (p).n.
             * When 'this' substitution is broken, $arg1 stays "this" → (this).n.
             */
            @BuiltinBPFFunction("($arg1).n")
            @NotUsableInJava
            static long fieldN(Object self) { throw new MethodIsBPFRelatedFunction(); }
        }

        /**
         * 'p' is a method parameter of struct type Plain.  When p.passThrough() is
         * translated, the receiver expression is the C identifier "p" (not "this").
         * Inside the inlined body, 'this' must resolve to "p".
         */
        @BPFFunction
        public long invokePassThrough(Plain p) {
            return p.passThrough();
        }
    }

    @Test
    void javaInlineThisSubstitution() {
        String code = stripped(codeOf(ThisSubstitutionTest.class));
        // Collect all lines that contain an inlined GNU statement expression block.
        var inlinedBlocks = code.lines()
                .filter(l -> l.contains("({") && l.contains("})"))
                .toList();
        // The ({}) wrapper must appear — passThrough() has a multi-statement body.
        assertFalse(inlinedBlocks.isEmpty(),
                "Expected @BPFJavaInline body to be inlined as a GNU statement "
                + "expression ({ ... }); got:\n" + code);
        // Post-Task-3: 'this' inside the inlined body must NOT appear as the literal
        // C identifier 'this'.  It must have been substituted with the receiver carrier ("p").
        var hasBareThis = inlinedBlocks.stream()
                .anyMatch(l -> l.matches(".*\\bthis\\b.*"));
        assertFalse(hasBareThis,
                "'this' inside @BPFJavaInline body must resolve to the carrier "
                + "expression, not the literal C identifier 'this'; "
                + "got inlined blocks:\n" + String.join("\n", inlinedBlocks));
    }
}
