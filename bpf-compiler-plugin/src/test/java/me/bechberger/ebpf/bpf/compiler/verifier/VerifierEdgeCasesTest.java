package me.bechberger.ebpf.bpf.compiler.verifier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Additional unit tests for the verifier infrastructure, covering gaps in the existing suites:
 * <ul>
 *   <li>{@link VerifierLogParser#classify} for {@code UNREACHABLE_INSTRUCTION} and
 *       {@code UNRESOLVED_FUNC} error classes</li>
 *   <li>{@link VerifierLogParser#isBookkeeping} directly</li>
 *   <li>{@link VerifierFixSuggester#formatHumane} for all remaining error classes</li>
 *   <li>End-to-end integration: parse → classify → format</li>
 * </ul>
 */
class VerifierEdgeCasesTest {

    // ── VerifierLogParser.classify: UNREACHABLE_INSTRUCTION ─────────────────

    @Test
    void classifyUnreachableInsn() {
        assertEquals(VerifierLogParser.ErrorClass.UNREACHABLE_INSTRUCTION,
                VerifierLogParser.classify("unreachable insn 5"),
                "bare 'unreachable insn' should classify as UNREACHABLE_INSTRUCTION");
    }

    @Test
    void classifyDeadCode() {
        assertEquals(VerifierLogParser.ErrorClass.UNREACHABLE_INSTRUCTION,
                VerifierLogParser.classify("dead code at insn 12"),
                "'dead code' should classify as UNREACHABLE_INSTRUCTION");
    }

    @Test
    void classifyJumpOutOfRange() {
        assertEquals(VerifierLogParser.ErrorClass.UNREACHABLE_INSTRUCTION,
                VerifierLogParser.classify("jump out of range from insn 3 to 200"),
                "'jump out of range' should classify as UNREACHABLE_INSTRUCTION");
    }

    // ── VerifierLogParser.classify: UNRESOLVED_FUNC ─────────────────────────

    @Test
    void classifyUnknownOpcode() {
        assertEquals(VerifierLogParser.ErrorClass.UNRESOLVED_FUNC,
                VerifierLogParser.classify("unknown opcode 0x25"),
                "'unknown opcode' should classify as UNRESOLVED_FUNC");
    }

    @Test
    void classifyCallToNotAllowed() {
        assertEquals(VerifierLogParser.ErrorClass.UNRESOLVED_FUNC,
                VerifierLogParser.classify("call to 'bpf_send_signal_thread' is not allowed"),
                "'call to X is not allowed' should classify as UNRESOLVED_FUNC");
    }

    @Test
    void classifyUnsupportedFunction() {
        assertEquals(VerifierLogParser.ErrorClass.UNRESOLVED_FUNC,
                VerifierLogParser.classify("unsupported function id 255"),
                "'unsupported function' should classify as UNRESOLVED_FUNC");
    }

    @Test
    void classifyKernelSubsystemMisconfigured() {
        assertEquals(VerifierLogParser.ErrorClass.UNRESOLVED_FUNC,
                VerifierLogParser.classify("kernel subsystem misconfigured func 100"),
                "'kernel subsystem misconfigured func' should classify as UNRESOLVED_FUNC");
    }

    // ── VerifierLogParser.isBookkeeping ─────────────────────────────────────

    @Test
    void blankLineIsBookkeeping() {
        assertTrue(VerifierLogParser.isBookkeeping(""),
                "blank line should be bookkeeping");
        assertTrue(VerifierLogParser.isBookkeeping("   "),
                "whitespace-only line should be bookkeeping");
    }

    @Test
    void processedLineIsBookkeeping() {
        assertTrue(VerifierLogParser.isBookkeeping(
                "processed 123 insns (limit 1000000) max_states_per_insn 0"),
                "'processed N insns' line should be bookkeeping");
    }

    @Test
    void verificationTimeIsBookkeeping() {
        assertTrue(VerifierLogParser.isBookkeeping("verification time 12 usec"));
    }

    @Test
    void stackDepthIsBookkeeping() {
        assertTrue(VerifierLogParser.isBookkeeping("stack depth 128"));
    }

    @Test
    void registerStateDumpIsBookkeeping() {
        // Lines starting with R#_w= or R#= with underscore-w suffix are bookkeeping.
        assertTrue(VerifierLogParser.isBookkeeping("R0_w=inv"),
                "R0_w=inv register-state dump should be bookkeeping");
        assertTrue(VerifierLogParser.isBookkeeping("R1_w=ptr_or_null(id=3)"),
                "R1_w=ptr... register-state dump should be bookkeeping");
        // Instruction-prefixed register dump: "N: R#(_w)?=..."
        assertTrue(VerifierLogParser.isBookkeeping("0: R1=ctx() R10=fp0"),
                "instruction-prefixed register dump should be bookkeeping");
    }

    @Test
    void fromToEdgeTraceIsBookkeeping() {
        assertTrue(VerifierLogParser.isBookkeeping("from 5 to 12: R0=inv"),
                "'from X to Y' edge trace should be bookkeeping");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "last_idx 5 first_idx 0",
        "frame0:",
        "caller: R0=inv",
        "callee: R0_w=inv",
        "the sequence of 8 jumps is too complex",
        "; int x = 1;",
        "libbpf: failed to load BPF",
        "-- BEGIN LOG --",
        "-- END LOG --",
        "======",
        "0: R1=ctx() R10=fp0"
    })
    void miscBookkeepingLines(String line) {
        assertTrue(VerifierLogParser.isBookkeeping(line),
                "expected bookkeeping for: " + line);
    }

    @Test
    void realErrorLineIsNotBookkeeping() {
        assertFalse(VerifierLogParser.isBookkeeping("R1 invalid mem access 'inv'"),
                "real error should not be bookkeeping");
        assertFalse(VerifierLogParser.isBookkeeping("unreachable insn 5"),
                "real error should not be bookkeeping");
    }

    // ── VerifierFixSuggester.formatHumane for remaining error classes ────────

    private static String humaneForClass(VerifierLogParser.ErrorClass ec) {
        var err = new VerifierLogParser.VerifierError("test error", ec, Optional.of(42), Optional.empty());
        return VerifierFixSuggester.formatHumane(
                new VerifierLogParser.ParseResult(java.util.List.of(), Optional.of(err), Optional.empty()));
    }

    @Test
    void formatHumaneForUnreachableInstruction() {
        var h = humaneForClass(VerifierLogParser.ErrorClass.UNREACHABLE_INSTRUCTION);
        assertTrue(h.contains("Why:"), "UNREACHABLE_INSTRUCTION humane output must contain Why:");
        assertTrue(h.contains("Fix:"), "UNREACHABLE_INSTRUCTION humane output must contain Fix:");
        assertTrue(h.contains("See:"), "UNREACHABLE_INSTRUCTION humane output must contain See:");
        assertTrue(h.contains("unreachable") || h.contains("dead code") || h.contains("control"),
                "UNREACHABLE_INSTRUCTION hint should mention dead code / control flow: " + h);
    }

    @Test
    void formatHumaneForUnresolvedFunc() {
        var h = humaneForClass(VerifierLogParser.ErrorClass.UNRESOLVED_FUNC);
        assertTrue(h.contains("Why:"));
        assertTrue(h.contains("Fix:"));
        assertTrue(h.contains("See:"));
        assertTrue(h.contains("helper") || h.contains("function") || h.contains("bpftool"),
                "UNRESOLVED_FUNC hint should mention helper or bpftool: " + h);
    }

    @Test
    void formatHumaneForTypeMismatch() {
        var h = humaneForClass(VerifierLogParser.ErrorClass.TYPE_MISMATCH);
        assertTrue(h.contains("Why:"));
        assertTrue(h.contains("Fix:"));
        assertTrue(h.contains("See:"));
    }

    @Test
    void formatHumaneForOther() {
        var h = humaneForClass(VerifierLogParser.ErrorClass.OTHER);
        assertTrue(h.contains("Why:"));
        assertTrue(h.contains("Fix:"));
        assertTrue(h.contains("See:"));
        assertTrue(h.contains("pattern") || h.contains("verifier"),
                "OTHER hint should mention verifier or pattern: " + h);
    }

    @Test
    void formatHumaneIncludesErrorClassLabel() {
        for (var ec : VerifierLogParser.ErrorClass.values()) {
            var h = humaneForClass(ec);
            assertTrue(h.contains(ec.name()),
                    "formatHumane should include the ErrorClass name for " + ec + ": " + h);
        }
    }

    @Test
    void formatHumaneIncludesInstructionOffset() {
        var err = new VerifierLogParser.VerifierError("test error",
                VerifierLogParser.ErrorClass.OTHER, Optional.of(99), Optional.empty());
        var h = VerifierFixSuggester.formatHumane(
                new VerifierLogParser.ParseResult(java.util.List.of(), Optional.of(err), Optional.empty()));
        assertTrue(h.contains("99"), "humane output should include instruction offset 99");
    }

    // ── End-to-end: parse → classify → format ───────────────────────────────

    @Test
    void endToEndUnreachableInstruction() {
        var log = """
                0: (b7) r0 = 0
                1: (95) exit
                unreachable insn 2
                processed 2 insns
                """;
        var result = VerifierLogParser.parse(log);
        var err = result.error().orElseThrow(() -> new AssertionError("expected error"));
        assertEquals(VerifierLogParser.ErrorClass.UNREACHABLE_INSTRUCTION, err.errorClass());
        var humane = VerifierFixSuggester.formatHumane(result);
        assertTrue(humane.contains("UNREACHABLE_INSTRUCTION"));
        assertTrue(humane.contains("Fix:"));
    }

    @Test
    void endToEndUnresolvedFunc() {
        var log = """
                5: (85) call unknown#999
                unknown opcode 0x85
                processed 5 insns
                """;
        var result = VerifierLogParser.parse(log);
        var err = result.error().orElseThrow(() -> new AssertionError("expected error"));
        assertEquals(VerifierLogParser.ErrorClass.UNRESOLVED_FUNC, err.errorClass());
        var humane = VerifierFixSuggester.formatHumane(result);
        assertTrue(humane.contains("UNRESOLVED_FUNC"));
        assertTrue(humane.contains("Fix:"));
    }

    @Test
    void bookkeepingOnlyLogProducesNoError() {
        var log = """
                processed 0 insns (limit 1000000) max_states_per_insn 0
                verification time 1 usec
                stack depth 0
                """;
        var result = VerifierLogParser.parse(log);
        assertTrue(result.error().isEmpty(),
                "bookkeeping-only log should produce no error: " + result.error());
    }

    @Test
    void classifyIsCaseInsensitive() {
        assertEquals(VerifierLogParser.ErrorClass.UNREACHABLE_INSTRUCTION,
                VerifierLogParser.classify("UNREACHABLE INSN 5"));
        assertEquals(VerifierLogParser.ErrorClass.UNRESOLVED_FUNC,
                VerifierLogParser.classify("UNKNOWN OPCODE 0x25"));
    }
}
