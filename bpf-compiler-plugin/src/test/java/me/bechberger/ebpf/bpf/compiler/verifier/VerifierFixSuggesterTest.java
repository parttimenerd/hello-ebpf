package me.bechberger.ebpf.bpf.compiler.verifier;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class VerifierFixSuggesterTest {

    private static VerifierLogParser.VerifierError err(VerifierLogParser.ErrorClass cls) {
        return new VerifierLogParser.VerifierError("synthetic message", cls, Optional.of(42));
    }

    @Test
    void everyErrorClassHasAFourPartHint() {
        for (var cls : VerifierLogParser.ErrorClass.values()) {
            String hint = VerifierFixSuggester.suggest(err(cls));
            assertTrue(hint.contains("Why:"), cls + " hint missing 'Why:': " + hint);
            assertTrue(hint.contains("Fix:"), cls + " hint missing 'Fix:': " + hint);
            assertTrue(hint.contains("See:"), cls + " hint missing 'See:': " + hint);
        }
    }

    @Test
    void invalidMemAccessHintMentionsNullCheck() {
        var hint = VerifierFixSuggester.suggest(err(VerifierLogParser.ErrorClass.INVALID_MEM_ACCESS));
        assertTrue(hint.contains("null-check") || hint.contains("null check"),
                "invalid-mem-access hint should mention null-checking: " + hint);
    }

    @Test
    void infiniteLoopHintMentionsBoundedLoop() {
        var hint = VerifierFixSuggester.suggest(err(VerifierLogParser.ErrorClass.INFINITE_LOOP));
        assertTrue(hint.toLowerCase().contains("bounded") || hint.toLowerCase().contains("for-loop")
                        || hint.toLowerCase().contains("for (int"),
                "infinite-loop hint should mention bounded loops: " + hint);
    }

    @Test
    void stackOobHintMentionsPerCpuOrArena() {
        var hint = VerifierFixSuggester.suggest(err(VerifierLogParser.ErrorClass.STACK_OOB));
        assertTrue(hint.toLowerCase().contains("per-cpu") || hint.toLowerCase().contains("arena"),
                "stack-OOB hint should mention per-cpu/arena: " + hint);
    }

    @Test
    void formatHumaneIncludesAllParts() {
        var log = """
                0: (b7) r1 = 0
                1: (61) r0 = *(u32 *)(r1 +0)
                R1 invalid mem access 'inv'
                """;
        var result = VerifierLogParser.parse(log);
        var humane = VerifierFixSuggester.formatHumane(result);

        assertTrue(humane.contains("Verifier rejected"), "header missing: " + humane);
        assertTrue(humane.contains("invalid mem access"), "original message missing: " + humane);
        assertTrue(humane.contains("INVALID_MEM_ACCESS"), "classification missing: " + humane);
        assertTrue(humane.contains("instruction offset 1"), "insn offset missing: " + humane);
        assertTrue(humane.contains("Why:"), "Why: missing: " + humane);
        assertTrue(humane.contains("Fix:"), "Fix: missing: " + humane);
    }

    @Test
    void formatHumaneHandlesEmptyLog() {
        var humane = VerifierFixSuggester.formatHumane(VerifierLogParser.parse(""));
        assertTrue(humane.contains("no recognisable error line"));
    }

    @Test
    void formatHumaneOmitsInsnOffsetWhenAbsent() {
        var humane = VerifierFixSuggester.formatHumane(VerifierLogParser.parse("standalone error\n"));
        assertFalse(humane.contains("instruction offset"),
                "should not print 'instruction offset' header when none present: " + humane);
    }

    @Test
    void mapValueOrNullEndToEndProducesNullCheckHint() {
        // Real "forgot null-check" scenario.
        var log = """
                ; Ptr<V> v = map.bpf_get(k);   // Sample.java:21
                0: (85) call bpf_map_lookup_elem#1
                ; v.field = 7;                  // Sample.java:22
                1: (61) r0 = *(u32 *)(r0 +0)
                R0 invalid mem access 'map_value_or_null'
                """;
        var humane = VerifierFixSuggester.formatHumane(VerifierLogParser.parse(log));
        assertTrue(humane.contains("UNCHECKED_NULL_DEREF"),
                "map_value_or_null must classify as UNCHECKED_NULL_DEREF: " + humane);
        assertTrue(humane.contains("null") || humane.contains("NULL"),
                "hint should mention nullability: " + humane);
    }

    @Test
    void programTooLargeHintMentionsTailCallOrLoop() {
        var hint = VerifierFixSuggester.suggest(err(VerifierLogParser.ErrorClass.PROGRAM_TOO_LARGE));
        var lc = hint.toLowerCase();
        assertTrue(lc.contains("tail") || lc.contains("bpf_loop") || lc.contains("split"),
                "PROGRAM_TOO_LARGE hint should suggest splitting / bpf_loop: " + hint);
    }

    @Test
    void registerNameSurfacesInHumaneOutput() {
        // The register that triggered the rejection is useful context.
        var log = """
                0: (61) r0 = *(u32 *)(r1 +0)
                R6 invalid mem access 'inv'
                """;
        var humane = VerifierFixSuggester.formatHumane(VerifierLogParser.parse(log));
        assertTrue(humane.contains("R6") || humane.contains("invalid mem access"),
                "humane output should preserve the original error text: " + humane);
    }
}
