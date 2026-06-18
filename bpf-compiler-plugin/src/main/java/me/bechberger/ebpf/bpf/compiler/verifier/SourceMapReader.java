package me.bechberger.ebpf.bpf.compiler.verifier;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maps BPF instruction offsets to source-file coordinates. Stage 16 of the unified plan.
 *
 * <p>The compiler-plugin already emits {@code #line N "Foo.java"} directives into the generated
 * C, so clang propagates Java source coordinates into the object's BTF line-info. The runtime
 * tool {@code bpftool prog dump xlated file <obj.o> linum} prints those coordinates inline with
 * the disassembly. We do not parse BTF ourselves — bpftool already does it. This class consumes
 * bpftool's text output (or any equivalent {@code ; <stmt> // file:line} stream) and exposes
 * an {@code (insnOffset → SourceLocation)} lookup that the verifier-error formatter can use.
 *
 * <p>Pure: input is a string, output is a {@link SourceMap}. No I/O, no native calls.
 */
public final class SourceMapReader {

    /** A source-file coordinate (path, 1-based line, optional column). */
    public record SourceLocation(String file, int line, Optional<Integer> column) {
        public String render() {
            return column.isPresent() ? file + ":" + line + ":" + column.get() : file + ":" + line;
        }
    }

    /** Lookup table from instruction offset to source location. */
    public record SourceMap(Map<Integer, SourceLocation> byOffset) {
        public Optional<SourceLocation> lookup(int offset) {
            return Optional.ofNullable(byOffset.get(offset));
        }
        public boolean isEmpty() { return byOffset.isEmpty(); }
        public int size() { return byOffset.size(); }
    }

    /**
     * Matches an instruction line from bpftool: {@code "  10: (b7) r1 = 0"}. We only need the
     * offset; the rest is ignored.
     */
    private static final Pattern INSN_LINE = Pattern.compile(
            "^\\s*(\\d+):\\s*\\((?:0x)?[0-9a-fA-F]{1,2}\\).*$");

    /**
     * Matches a source-comment line. Two common shapes:
     * <ul>
     *   <li>{@code "; statement-text   // path/to/Foo.java:42"}</li>
     *   <li>{@code "; statement-text   // path/to/Foo.java:42:5"}</li>
     * </ul>
     * The path is "everything up to the trailing {@code :line[:col]}" — we anchor on the last
     * {@code :digits} group(s) at end-of-line so paths with digits in them parse correctly.
     */
    private static final Pattern SRC_LINE = Pattern.compile(
            "^\\s*;.*?//\\s*(?<file>\\S+?):(?<line>\\d+)(?::(?<col>\\d+))?\\s*$");

    /**
     * Fallback when the path itself contains characters {@code \S+?} would split on (rare but
     * possible). Anchors the line/col group at end-of-line and lets the path be anything
     * non-empty.
     */
    private static final Pattern SRC_LINE_FALLBACK = Pattern.compile(
            "^\\s*;.*?//\\s*(?<file>.+?):(?<line>\\d+)(?::(?<col>\\d+))?\\s*$");

    private SourceMapReader() {}

    /**
     * Parse the text output of {@code bpftool prog dump xlated file <obj.o> linum}.
     *
     * <p>Strategy: walk top-to-bottom. A source-comment line attaches to the *next* instruction
     * line, mirroring how bpftool / clang emit {@code line_info} (the comment precedes the insn
     * it annotates). When two source comments arrive back-to-back without an intervening insn,
     * the most recent one wins.
     */
    public static SourceMap parse(String dump) {
        var map = new HashMap<Integer, SourceLocation>();
        if (dump == null || dump.isBlank()) return new SourceMap(Map.of());

        SourceLocation pending = null;

        for (String raw : dump.split("\\R", -1)) {
            Matcher src = SRC_LINE.matcher(raw);
            if (!src.matches()) src = SRC_LINE_FALLBACK.matcher(raw);
            if (src.matches() && raw.trim().startsWith(";")) {
                String file = src.group("file");
                int line = Integer.parseInt(src.group("line"));
                Optional<Integer> col = src.group("col") == null ? Optional.empty()
                        : Optional.of(Integer.parseInt(src.group("col")));
                pending = new SourceLocation(file, line, col);
                continue;
            }
            Matcher insn = INSN_LINE.matcher(raw);
            if (insn.matches() && pending != null) {
                int off = Integer.parseInt(insn.group(1));
                map.putIfAbsent(off, pending);
                // Keep `pending` — bpftool sometimes emits one source comment for several
                // contiguous insns.
            }
        }
        return new SourceMap(Map.copyOf(map));
    }

    /**
     * Convenience: combine {@link VerifierLogParser.ParseResult} with a {@link SourceMap} to
     * produce a pretty location string for the rejected instruction. Returns empty if the error
     * has no insn offset or the offset is not in the map.
     */
    public static Optional<String> locateError(VerifierLogParser.ParseResult parsed, SourceMap map) {
        if (parsed.error().isEmpty()) return Optional.empty();
        var off = parsed.error().get().instructionOffset();
        if (off.isEmpty()) return Optional.empty();
        return map.lookup(off.get()).map(SourceLocation::render);
    }
}
