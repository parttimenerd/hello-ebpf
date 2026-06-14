package me.bechberger.ebpf.bpf.compiler.verifier;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SourceMapReaderTest {

    @Test
    void emptyInputProducesEmptyMap() {
        var map = SourceMapReader.parse("");
        assertTrue(map.isEmpty());
        assertTrue(map.lookup(0).isEmpty());
    }

    @Test
    void nullInputProducesEmptyMap() {
        var map = SourceMapReader.parse(null);
        assertTrue(map.isEmpty());
    }

    @Test
    void simpleDumpAttachesCommentToNextInsn() {
        var dump = """
                ; int x = ptr->field;     // src/main/java/Foo.java:42
                0: (61) r0 = *(u32 *)(r1 +0)
                ; return x;               // src/main/java/Foo.java:43
                1: (95) exit
                """;
        var map = SourceMapReader.parse(dump);
        assertEquals(2, map.size());
        var loc0 = map.lookup(0).orElseThrow();
        assertEquals("src/main/java/Foo.java", loc0.file());
        assertEquals(42, loc0.line());
        assertTrue(loc0.column().isEmpty());
        var loc1 = map.lookup(1).orElseThrow();
        assertEquals(43, loc1.line());
    }

    @Test
    void columnIsParsedWhenPresent() {
        var dump = """
                ; foo();    // Foo.java:10:5
                0: (85) call 1
                """;
        var loc = SourceMapReader.parse(dump).lookup(0).orElseThrow();
        assertEquals(10, loc.line());
        assertEquals(5, loc.column().orElseThrow());
        assertEquals("Foo.java:10:5", loc.render());
    }

    @Test
    void renderWithoutColumnOmitsIt() {
        var loc = new SourceMapReader.SourceLocation("Foo.java", 42, Optional.empty());
        assertEquals("Foo.java:42", loc.render());
    }

    @Test
    void multipleInsnsShareTheSameSourceComment() {
        // Common when one Java statement lowers to several BPF insns.
        var dump = """
                ; int x = a + b * c;   // Calc.java:7
                0: (07) r1 += 1
                1: (07) r2 += 2
                2: (0f) r1 += r2
                """;
        var map = SourceMapReader.parse(dump);
        assertEquals(3, map.size());
        for (int off : new int[]{0, 1, 2}) {
            assertEquals(7, map.lookup(off).orElseThrow().line(),
                    "offset " + off + " should pick up the preceding comment");
        }
    }

    @Test
    void laterCommentReplacesPendingBeforeAnyInsn() {
        // Two source comments back-to-back without an insn between: most recent wins.
        var dump = """
                ; old text                   // Foo.java:1
                ; new text                   // Foo.java:99
                0: (b7) r1 = 0
                """;
        var loc = SourceMapReader.parse(dump).lookup(0).orElseThrow();
        assertEquals(99, loc.line(), "the most recent pending comment should win");
    }

    @Test
    void lineWithoutSourceCommentIsNotMapped() {
        var dump = """
                0: (b7) r1 = 0
                1: (95) exit
                """;
        var map = SourceMapReader.parse(dump);
        assertTrue(map.isEmpty(), "no source comments → no entries: " + map);
    }

    @Test
    void locateErrorReturnsRenderedLocation() {
        var dumpStr = """
                ; map.bpf_get(k).val();   // Sample.java:21
                0: (85) call bpf_map_lookup_elem#1
                ; deref;                   // Sample.java:22
                1: (61) r0 = *(u32 *)(r0 +0)
                """;
        var map = SourceMapReader.parse(dumpStr);

        var verifierLog = """
                0: (85) call bpf_map_lookup_elem#1
                1: (61) r0 = *(u32 *)(r0 +0)
                R0 invalid mem access 'map_value_or_null'
                """;
        var parsed = VerifierLogParser.parse(verifierLog);

        var loc = SourceMapReader.locateError(parsed, map).orElseThrow();
        assertEquals("Sample.java:22", loc, "should locate insn 1 → Sample.java:22");
    }

    @Test
    void locateErrorEmptyWhenNoOffset() {
        var parsed = VerifierLogParser.parse("standalone error\n");
        assertTrue(SourceMapReader.locateError(parsed, new SourceMapReader.SourceMap(java.util.Map.of())).isEmpty());
    }

    @Test
    void locateErrorEmptyWhenOffsetMissingFromMap() {
        var verifierLog = """
                0: (b7) r1 = 0
                42: (95) exit
                R0 something bad
                """;
        var parsed = VerifierLogParser.parse(verifierLog);
        var map = new SourceMapReader.SourceMap(java.util.Map.of(7,
                new SourceMapReader.SourceLocation("Foo.java", 1, Optional.empty())));
        assertTrue(SourceMapReader.locateError(parsed, map).isEmpty(),
                "offset 42 not in map → empty");
    }

    @Test
    void noisyCommentLinesWithoutCoordinatesAreIgnored() {
        var dump = """
                ; just a banner comment
                ; another banner
                ; real one  // Foo.java:9
                0: (b7) r1 = 0
                """;
        var loc = SourceMapReader.parse(dump).lookup(0).orElseThrow();
        assertEquals(9, loc.line());
    }

    @Test
    void deepPathIsPreserved() {
        var dump = """
                ; x;    // /home/user/proj/src/main/java/me/bechberger/Demo.java:123
                0: (b7) r1 = 0
                """;
        var loc = SourceMapReader.parse(dump).lookup(0).orElseThrow();
        assertEquals("/home/user/proj/src/main/java/me/bechberger/Demo.java", loc.file());
        assertEquals(123, loc.line());
    }

    @Test
    void interleavedSourceCommentAndInsnsCorrectlyAttributesEach() {
        // Each Java statement maps to its own group of insns.
        var dump = """
                ; if (x == null) return 0;   // Foo.java:10
                0: (15) if r0 == 0x0 goto pc+5
                1: (b7) r0 = 0
                ; return x.value;             // Foo.java:11
                2: (61) r0 = *(u32 *)(r0 +0)
                3: (95) exit
                """;
        var map = SourceMapReader.parse(dump);
        assertEquals(10, map.lookup(0).orElseThrow().line());
        assertEquals(10, map.lookup(1).orElseThrow().line());
        assertEquals(11, map.lookup(2).orElseThrow().line());
        assertEquals(11, map.lookup(3).orElseThrow().line());
    }

    @Test
    void linesWithoutLineNumberCommentAreIgnored() {
        // Comment without // path:line shape.
        var dump = """
                ; just bookkeeping, no path
                ; another comment
                0: (b7) r1 = 0
                """;
        var map = SourceMapReader.parse(dump);
        assertTrue(map.isEmpty(), "no valid source comments → empty map");
    }

    @Test
    void looksupOfMissingOffsetReturnsEmpty() {
        var dump = """
                ; foo;  // Foo.java:1
                0: (b7) r1 = 0
                """;
        var map = SourceMapReader.parse(dump);
        assertTrue(map.lookup(99).isEmpty(), "offset 99 was never traced");
    }

    @Test
    void parserToleratesHexOpcodePrefix() {
        var dump = """
                ; foo;  // Foo.java:5
                0: (0x07) r1 += 8
                """;
        var map = SourceMapReader.parse(dump);
        assertEquals(5, map.lookup(0).orElseThrow().line(),
                "should accept (0x07) as an instruction line");
    }

    @Test
    void renderWithColumnIncludesAllParts() {
        var loc = new SourceMapReader.SourceLocation("Foo.java", 42, Optional.of(5));
        assertEquals("Foo.java:42:5", loc.render());
    }

    @Test
    void pathWithSpacesIsHandledByFallback() {
        // The strict SRC_LINE pattern uses \\S+? for the path, which can't span spaces.
        // The fallback pattern uses .+? — verify that paths with spaces still parse.
        // (Real bpftool output rarely contains spaces in paths, but on macOS / Windows it can.)
        var dump = """
                ; foo;  // /Users/me/My Project/src/Foo.java:7
                0: (b7) r1 = 0
                """;
        var map = SourceMapReader.parse(dump);
        var loc = map.lookup(0).orElseThrow();
        assertEquals("/Users/me/My Project/src/Foo.java", loc.file());
        assertEquals(7, loc.line());
    }
}
