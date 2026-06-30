package me.bechberger.ebpf.bpf.compiler.verifier;

/**
 * Stage 15: turns a parsed {@link VerifierLogParser.VerifierError} into a 4-part hint
 * (what / Why / Fix / See) that points at the likely Java-source-level cause.
 *
 * <p>The verifier's own messages are precise but kernel-side; this class adds the
 * Java perspective ("you probably forgot to null-check the lookup"). Used by
 * {@code BPFVerifierException} formatting and by IDE / build-tool consumers that want a
 * humane error message instead of the raw libbpf log.
 *
 * <p>Pure: input is a structured error, output is a string. No I/O.
 */
public final class VerifierFixSuggester {

    private VerifierFixSuggester() {}

    /**
     * Returns a 4-part hint. The hint always includes "Why:" and "Fix:" lines. For categories
     * the suggester does not specifically recognise it returns a generic catch-all.
     */
    public static String suggest(VerifierLogParser.VerifierError error) {
        return switch (error.errorClass()) {
            case INVALID_MEM_ACCESS -> """
                    The verifier rejected a memory access.
                    Why: a register holds a value the verifier cannot prove is a valid pointer to \
                    the expected memory region (often a Map.bpf_get result that was not null-checked, \
                    or arithmetic that erased a packet pointer's tag).
                    Fix: store the result of map lookups in a local, null-check it, and only \
                    dereference the local. For packet pointers, add a bounds check against the \
                    end-pointer before any deref.
                    See: cookbook §Map lookups, §Packet bounds""";

            case UNCHECKED_NULL_DEREF -> """
                    The verifier rejected a pointer comparison or arithmetic.
                    Why: a value that may be NULL was used in pointer arithmetic, or two pointers \
                    were compared in a way the verifier cannot prove is safe.
                    Fix: ensure the pointer is non-null before any arithmetic:
                      Ptr<V> p = map.bpf_get(k);
                      if (p == null) return 0;
                      /* now p is provably non-null */
                    See: cookbook §Nullability""";

            case OUT_OF_BOUNDS -> """
                    The verifier rejected an access whose index it could not bound.
                    Why: an array or pointer access index was not provably within the type's size; \
                    the verifier conservatively treats unbounded values as out-of-range.
                    Fix: clamp the index with a literal mask or comparison before the access:
                      int i = key & (SIZE - 1);   // SIZE must be a literal power-of-two
                      // or
                      if (i < 0 || i >= SIZE) return 0;
                    See: cookbook §Bounds""";

            case STACK_OOB -> """
                    The verifier rejected a stack access.
                    Why: a write or read addressed a stack offset outside the function's stack \
                    frame. BPF stack frames are 512 bytes; per-call locals must fit.
                    Fix: move large buffers off the stack — use a per-cpu array map or an arena \
                    region. Per-cpu maps give per-thread storage without using the stack.
                    See: cookbook §Stack""";

            case TYPE_MISMATCH -> """
                    The verifier rejected an argument with the wrong type.
                    Why: a helper expected a pointer to a specific kind of memory (map value, \
                    packet, stack) and got a pointer to a different region or to scalar memory.
                    Fix: pass the value through the right cast — BPFJ.castUser / castKernel / \
                    castArena — or rebuild the call so the helper sees the region it expects.
                    See: cookbook §Memory regions""";

            case UNREACHABLE_INSTRUCTION -> """
                    The verifier rejected an unreachable instruction.
                    Why: the program contains code with no incoming control-flow edge — usually \
                    a fall-through after an unconditional return, or dead code left after a \
                    refactor.
                    Fix: remove the unreachable code, or restructure the surrounding control \
                    flow so the verifier can see why it would be entered.
                    See: cookbook §Control flow""";

            case INFINITE_LOOP -> """
                    The verifier rejected the program for unbounded looping.
                    Why: the verifier could not prove the loop terminates within its instruction \
                    budget (~1M, ~8M with bounded-loops). Both back-edges and processed-insn \
                    overflow trigger this.
                    Fix: rewrite as a literal-bounded for-loop ('for (int i=0; i<N; i++)' with N \
                    a compile-time constant), or use 'bpf_for_each_map_elem' / 'bpf_for'. The \
                    UnboundedLoopPass usually catches this at compile time — add \
                    @SuppressBPFWarning("bounds.unbounded-loop") only when you know the bound.
                    See: cookbook §Loops""";

            case HELPER_NOT_ALLOWED -> """
                    The verifier rejected a helper call as not allowed in this program type.
                    Why: BPF gates helpers by program section; calling 'bpf_X' from the wrong \
                    section type fails at load.
                    Fix: either move the call into a section that allows the helper, or use a \
                    context-equivalent helper that is allowed here. The HelperContextPass usually \
                    catches this at compile time.
                    See: cookbook §Helpers""";

            case UNRESOLVED_FUNC -> """
                    The verifier rejected a call to an unknown or disallowed function.
                    Why: the kernel did not recognise the helper number, or the call target is \
                    unsupported in this context.
                    Fix: confirm the helper exists in your kernel's BPF helper table (see \
                    'bpftool feature probe'). If you used @BuiltinBPFFunction, double-check the \
                    template renders to a known bpf_* name.
                    See: cookbook §Helpers""";

            case PROGRAM_TOO_LARGE -> """
                    The verifier rejected the program for exceeding its instruction budget.
                    Why: BPF caps total verified insns (~1M, ~8M with bounded loops) and total \
                    program size. Large fan-out (deeply nested branches, many inlined helpers, \
                    big literal-bounded loops) inflates the count quickly.
                    Fix: split logic across tail-called sub-programs, replace long inline loops \
                    with 'bpf_loop' / 'bpf_for_each_map_elem', or move data into maps so the \
                    verifier doesn't have to walk every iteration.
                    See: cookbook §Program size""";

            case ARENA_NOT_ASSOCIATED -> """
                    The verifier rejected an addr_space_cast instruction because the program has \
                    no associated arena.
                    Why: this is a hello-ebpf framework bug — the ArenaAssociationPass failed to \
                    inject the per-prog arena-association helper into this struct_ops entry, so \
                    the verifier did not see the required BPF_PSEUDO_MAP_FD ldimm64 for the \
                    arena map.
                    Fix: please file an issue at https://github.com/parttimenerd/hello-ebpf \
                    with the BPF source file and the @BPF class that triggered this error. \
                    Do NOT add manual bpfArenaAssociate calls — those are an internal \
                    implementation detail.
                    See: https://github.com/parttimenerd/hello-ebpf/issues""";

            case OTHER -> """
                    The verifier rejected the program with a message we do not yet pattern-match.
                    Why: see the verifier message above for the kernel's own explanation.
                    Fix: examine the named instruction in the trace; the most recent insn is \
                    usually the offending one. If this is a recurring shape, add a new pattern \
                    to VerifierFixSuggester so future occurrences get a specific hint.
                    See: cookbook §Verifier""";
        };
    }

    /**
     * Convenience: format an entire {@link VerifierLogParser.ParseResult} as a humane error
     * message including the original verifier line, the auto-suggested hint, and the
     * instruction offset (when available).
     */
    public static String formatHumane(VerifierLogParser.ParseResult result) {
        if (result.error().isEmpty()) {
            return "(verifier log contained no recognisable error line)";
        }
        var err = result.error().get();
        var sb = new StringBuilder();
        sb.append("Verifier rejected the program: ").append(err.message()).append('\n');
        err.instructionOffset().ifPresent(off -> sb.append("  at instruction offset ").append(off).append('\n'));
        sb.append("Classified as: ").append(err.errorClass()).append("\n\n");
        sb.append(suggest(err));
        return sb.toString();
    }
}
