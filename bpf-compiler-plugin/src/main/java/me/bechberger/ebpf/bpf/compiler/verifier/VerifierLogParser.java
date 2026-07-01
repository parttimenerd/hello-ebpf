package me.bechberger.ebpf.bpf.compiler.verifier;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses libbpf / kernel verifier rejection logs into structured records.
 *
 * <p>A verifier log looks like:
 * <pre>
 * 0: (b7) r1 = 0
 * 1: (61) r0 = *(u32 *)(r1 +0)
 * R1 invalid mem access 'inv'
 * processed 2 insns ...
 * </pre>
 *
 * <p>This parser extracts:
 * <ul>
 *   <li>Per-instruction trace lines as {@link Insn} records.</li>
 *   <li>The error line as {@link VerifierError} (the most actionable piece).</li>
 *   <li>The "processed N insns" footer for diagnostics.</li>
 * </ul>
 *
 * <p>Pure: no I/O, no kernel calls. Stage 15/16 of the unified type-system plan. Lives in the
 * compiler-plugin module so it can be unit-tested on macOS without bpftool.
 */
public final class VerifierLogParser {

    /**
     * One instruction-trace line, e.g. {@code 12: (07) r1 += 8}. The {@code rawHex} is the
     * two-hex-byte opcode prefix; {@code body} is the rest of the line (the decoded form).
     */
    public record Insn(int offset, String rawHex, String body) {}

    /**
     * The verifier's terminal rejection message.
     *
     * @param message            verbatim rejection line
     * @param errorClass         coarse classification (see {@link ErrorClass})
     * @param instructionOffset  offset of the most recent traced insn before the error, or empty
     * @param register           the offending register ({@code "R0"}, {@code "R6"}, ...) when the
     *                           error line names one, otherwise empty
     */
    public record VerifierError(String message, ErrorClass errorClass,
                                Optional<Integer> instructionOffset,
                                Optional<String> register) {
        /** Backwards-compat constructor: no register extracted. */
        public VerifierError(String message, ErrorClass errorClass, Optional<Integer> off) {
            this(message, errorClass, off, Optional.empty());
        }
    }

    /** Coarse classification of a verifier rejection. The strings track libbpf's own categories. */
    public enum ErrorClass {
        INVALID_MEM_ACCESS,           // R_ invalid mem access
        UNCHECKED_NULL_DEREF,          // R_ pointer comparison prohibited / map_value_or_null
        OUT_OF_BOUNDS,                 // R_ min value is outside / max value is outside
        STACK_OOB,                     // invalid stack access / stack offset / misaligned stack
        TYPE_MISMATCH,                 // expected ... got ... / arg # type mismatch
        UNREACHABLE_INSTRUCTION,       // unreachable insn / dead code
        INFINITE_LOOP,                 // back-edge / loop unbound / infinite loop / too many insns
        HELPER_NOT_ALLOWED,            // unknown func / helper not allowed
        UNRESOLVED_FUNC,               // call to '...' is not allowed / unknown opcode
        PROGRAM_TOO_LARGE,             // BPF program is too large / processed insn count exceeded
        ARENA_NOT_ASSOCIATED,          // addr_space_cast insn can only be used in a program that has an associated arena
        INVALID_TIMER_DEFINITION,      // bpf_timer used as bare map value, or missing bpf_timer field where required
        OTHER                          // catch-all
    }

    /** Result of parsing one verifier log. */
    public record ParseResult(List<Insn> instructions, Optional<VerifierError> error,
                              Optional<Integer> processedInsnCount) {}

    /**
     * Matches a single instruction trace line. The opcode byte is normally two hex chars, but
     * we also tolerate the kernel's occasional {@code (0x07)} or single-digit form so we never
     * silently drop a real instruction.
     */
    private static final Pattern INSN = Pattern.compile(
            "^\\s*(\\d+):\\s*\\((?:0x)?([0-9a-fA-F]{1,2})\\)\\s*(.+?)\\s*$");

    private static final Pattern PROCESSED = Pattern.compile(
            "^\\s*processed\\s+(\\d+)\\s+insns\\b.*$");

    /** Matches register-name prefix on an error line: {@code "R0 something..."} */
    private static final Pattern REGISTER_PREFIX = Pattern.compile("^(R\\d+)\\b.*");

    /** Lines that are clearly not errors: the verifier's own bookkeeping. */
    static boolean isBookkeeping(String line) {
        if (line.isBlank()) return true;
        var trim = line.trim();
        if (trim.startsWith("from ") && trim.contains("to ")) return true;          // edge trace
        if (trim.startsWith("verification time")) return true;
        if (trim.startsWith("processed ")) return true;
        if (trim.startsWith("stack depth ")) return true;
        if (trim.startsWith("regs=")) return true;
        if (trim.startsWith("last_idx ")) return true;
        if (trim.startsWith("frame")) return true;                                   // frame0..N
        if (trim.startsWith("caller:") || trim.startsWith("callee:")) return true;
        if (trim.startsWith("the sequence of")) return true;                         // hint preamble
        if (trim.startsWith(";")) return true;                                       // source comments
        if (trim.startsWith("libbpf:")) return true;                                 // libbpf preamble
        if (trim.startsWith("-- BEGIN") || trim.startsWith("-- END")) return true;   // log markers
        if (trim.matches("^R\\d+_w?=.*")) return true;                               // register-state dump
        if (trim.matches("^=+\\s*$")) return true;                                   // separators
        // Multi-register state dumps: "0: R1=ctx() R10=fp0" — has insn-style prefix
        // but multiple R= tokens separated by spaces. Treated as bookkeeping.
        if (trim.matches("^\\d+:\\s*R\\d+(_w)?=.*")) return true;
        return false;
    }

    private VerifierLogParser() {}

    /** Parse the full text of a verifier log. Empty input returns an all-empty result. */
    public static ParseResult parse(String log) {
        if (log == null || log.isBlank()) {
            return new ParseResult(List.of(), Optional.empty(), Optional.empty());
        }
        var insns = new ArrayList<Insn>();
        Optional<Integer> processedInsns = Optional.empty();

        // Strategy: collect *all* candidate error lines (non-trace, non-bookkeeping). The "real"
        // error is the most specific classification we can derive from any of them. If nothing
        // classifies, fall back to OTHER on the last candidate. This is more robust than picking
        // the first or last line outright, because verifier output sometimes interleaves register
        // dumps and back-edge annotations *after* the actionable line.
        var candidates = new ArrayList<String>();
        // Parallel list: the most-recent traced insn offset at the moment each candidate was
        // collected. The chosen error attaches to its own offset, not to the first candidate's.
        var candidateOffsets = new ArrayList<Integer>();
        Integer lastInsnOffset = null;

        for (String line : log.split("\\R", -1)) {
            Matcher m = INSN.matcher(line);
            if (m.matches()) {
                int off = Integer.parseInt(m.group(1));
                insns.add(new Insn(off, m.group(2), m.group(3)));
                lastInsnOffset = off;
                continue;
            }
            Matcher p = PROCESSED.matcher(line);
            if (p.matches()) {
                processedInsns = Optional.of(Integer.parseInt(p.group(1)));
                continue;
            }
            if (isBookkeeping(line)) continue;
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            candidates.add(trimmed);
            candidateOffsets.add(lastInsnOffset);
        }

        Optional<VerifierError> err = Optional.empty();
        if (!candidates.isEmpty()) {
            // Pick the first candidate whose classification is not OTHER; if none classify, use
            // the last candidate as OTHER. This both stabilizes against register-dump trailing
            // lines AND keeps backward-compat with single-line error logs.
            String chosen = null;
            ErrorClass chosenClass = null;
            Integer chosenOffset = null;
            for (int i = 0; i < candidates.size(); i++) {
                ErrorClass cls = classify(candidates.get(i));
                if (cls != ErrorClass.OTHER) {
                    chosen = candidates.get(i);
                    chosenClass = cls;
                    chosenOffset = candidateOffsets.get(i);
                    break;
                }
            }
            if (chosen == null) {
                int idx = candidates.size() - 1;
                chosen = candidates.get(idx);
                chosenClass = ErrorClass.OTHER;
                chosenOffset = candidateOffsets.get(idx);
            }
            err = Optional.of(new VerifierError(
                    chosen,
                    chosenClass,
                    Optional.ofNullable(chosenOffset),
                    extractRegister(chosen)));
        }
        return new ParseResult(List.copyOf(insns), err, processedInsns);
    }

    /** Extract the {@code "R0"}-style register from an error line, if present. */
    static Optional<String> extractRegister(String line) {
        var m = REGISTER_PREFIX.matcher(line);
        return m.matches() ? Optional.of(m.group(1)) : Optional.empty();
    }

    /** Classify a single verifier message line. Public for testing. */
    public static ErrorClass classify(String message) {
        String m = message.toLowerCase();

        // Order matters: more specific shapes go first. UNCHECKED_NULL_DEREF must come before
        // INVALID_MEM_ACCESS because "invalid mem access 'map_value_or_null'" matches both.
        if (m.contains("map_value_or_null")
                || m.contains("_or_null'")
                || m.contains("ptr_or_null")
                || m.contains("pointer comparison prohibited")
                || m.contains("pointer arithmetic prohibited")
                || m.contains("pointer arithmetic on")) {
            return ErrorClass.UNCHECKED_NULL_DEREF;
        }

        if (m.contains("invalid mem access")
                || m.contains("invalid access to memory")
                || m.contains("misaligned packet access")) {
            return ErrorClass.INVALID_MEM_ACCESS;
        }

        if (m.contains("min value is outside")
                || m.contains("max value is outside")
                || m.contains("value is outside of the allowed memory range")
                || m.contains("access beyond")
                || m.contains("unbounded memory access")
                || m.contains("map_value access out of bounds")
                || m.contains("invalid access to map value")     // "invalid access to map value, value_size=N..."
                || m.contains("invalid access to packet")) {
            return ErrorClass.OUT_OF_BOUNDS;
        }

        if (m.contains("invalid stack")
                || m.contains("stack offset")
                || m.contains("misaligned stack access")
                || m.contains("stack-out-of-bounds")
                || m.contains("invalid read from stack")
                || m.contains("invalid write to stack")
                || m.contains("!read_ok")) {           // modern kernel: uninitialised stack/reg
            return ErrorClass.STACK_OOB;
        }

        if ((m.contains("expected") && (m.contains("got") || m.contains("but ")))
                || (m.startsWith("arg #") && m.contains("type"))
                || m.contains("type mismatch")
                || (m.contains("type=") && m.contains("expected="))  // "R1 type=scalar expected=map_ptr"
                || m.contains("reg type unsupported")) {
            return ErrorClass.TYPE_MISMATCH;
        }

        if (m.contains("unreachable insn")
                || m.contains("dead code")
                || m.contains("jump out of range")) {
            return ErrorClass.UNREACHABLE_INSTRUCTION;
        }

        if (m.contains("back-edge")
                || m.contains("loop unbound")
                || m.contains("infinite loop detected")
                || m.contains("bpf_loop")
                || (m.contains("loop") && m.contains("limit"))) {
            return ErrorClass.INFINITE_LOOP;
        }

        if (m.contains("bpf program is too large")
                || m.contains("program is too large")
                || (m.contains("processed") && m.contains("insn limit"))
                || (m.contains("processed") && m.contains("limit reached"))
                || m.contains("too many instructions")) {
            return ErrorClass.PROGRAM_TOO_LARGE;
        }

        if (m.contains("unknown func")
                || m.contains("invalid func")           // modern kernel: "invalid func unknown#999"
                || m.contains("helper not allowed")
                || (m.contains("function ") && m.contains("not allowed"))
                || m.contains("program of this type cannot use helper")) {
            return ErrorClass.HELPER_NOT_ALLOWED;
        }

        if (m.contains("unknown opcode")
                || (m.contains("call to ") && m.contains("not allowed"))
                || m.contains("unsupported function")
                || m.contains("kernel subsystem misconfigured func")) {
            return ErrorClass.UNRESOLVED_FUNC;
        }

        if (m.contains("addr_space_cast insn can only be used in a program that has an associated arena")) {
            return ErrorClass.ARENA_NOT_ASSOCIATED;
        }

        // bpf_timer signals from kernel/bpf/btf.c (map_check_btf) and kernel/bpf/verifier.c
        // (check_map_func_compatibility). The common thread is a mention of "bpf_timer" in an
        // error context — misusing bpf_timer as a bare map value is the most frequent trigger.
        if (m.contains("bpf_timer")
                && (m.contains("map value")
                    || m.contains("not allowed")
                    || m.contains("not found")
                    || m.contains("not owned")
                    || m.contains("no timer")
                    || m.contains("expected"))) {
            return ErrorClass.INVALID_TIMER_DEFINITION;
        }

        return ErrorClass.OTHER;
    }
}
