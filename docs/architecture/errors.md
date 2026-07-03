# Error Classifier

When `BPFProgram.load()` fails, libbpf returns a raw verifier log full of kernel-side C-level messages. The `VerifierFixSuggester` + `VerifierLogParser` system classifies those messages and produces a Java-level diagnostic with a four-part **Why / Fix / See** hint pointing at the right guide page. `BPFVerifierException` assembles the final exception message from the parsed result. This page explains the classifier internals for contributors.

## How it works

`VerifierLogParser.parse(String log)` tokenises the log into instruction-trace lines (`Insn`), a structured `VerifierError`, and the processed-insn footer. For the error line it calls `classify()`, which matches substrings and patterns against the lower-cased message; the first match wins and the line is tagged with an `ErrorClass` enum constant.

`VerifierFixSuggester.suggest(VerifierError)` switches on `ErrorClass` and returns a multi-line string. `formatHumane(ParseResult)` wraps that string together with the original verifier line, the instruction offset, and the classification label into the text that ends up in `BPFVerifierException.getMessage()`.

Key types (source: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/verifier/`):

```java
// VerifierLogParser.java
public enum ErrorClass {
    INVALID_MEM_ACCESS, UNCHECKED_NULL_DEREF, OUT_OF_BOUNDS, STACK_OOB,
    TYPE_MISMATCH, UNREACHABLE_INSTRUCTION, INFINITE_LOOP, HELPER_NOT_ALLOWED,
    UNRESOLVED_FUNC, PROGRAM_TOO_LARGE, ARENA_NOT_ASSOCIATED,
    INVALID_TIMER_DEFINITION, OTHER
}
public record VerifierError(String message, ErrorClass errorClass,
                            Optional<Integer> instructionOffset,
                            Optional<String> register) {}
public record ParseResult(List<Insn> instructions, Optional<VerifierError> error,
                          Optional<Integer> processedInsnCount) {}
public static ParseResult parse(String log) { ... }
public static ErrorClass classify(String message) { ... }   // public for testing

// VerifierFixSuggester.java
public static String suggest(VerifierLogParser.VerifierError error) { ... }
public static String formatHumane(VerifierLogParser.ParseResult result) { ... }
```

The classifier is invoked from `BPFVerifierException` (`bpf/src/main/java/me/bechberger/ebpf/bpf/BPFVerifierException.java`), which calls `VerifierLogParser.parse()` then `VerifierFixSuggester.formatHumane()` inside its `buildMessage()` helper. There is no SPI or registry: all classification logic lives in the single `classify()` method and all hints live in the `suggest()` switch.

## Existing error classes

| `ErrorClass` | Matching substrings (excerpt) | Suggested fix summary |
|---|---|---|
| `INVALID_MEM_ACCESS` | `"invalid mem access"`, `"invalid access to memory"`, `"misaligned packet access"` | Null-check map lookups before deref; add packet bounds check |
| `UNCHECKED_NULL_DEREF` | `"map_value_or_null"`, `"_or_null'"`, `"pointer comparison prohibited"`, `"pointer arithmetic on"` | Null-check before pointer arithmetic; matched first so it takes priority over `INVALID_MEM_ACCESS` |
| `OUT_OF_BOUNDS` | `"min value is outside"`, `"max value is outside"`, `"map_value access out of bounds"`, `"invalid access to packet"` | Clamp index with literal mask or range check |
| `STACK_OOB` | `"invalid stack"`, `"stack offset"`, `"misaligned stack access"`, `"!read_ok"` | Move large buffers to per-cpu array map or arena |
| `TYPE_MISMATCH` | `"expected"` + `"got"`, `"arg #"` + `"type"`, `"type mismatch"`, `"reg type unsupported"` | Use the correct `BPFJ.castUser/castKernel/castArena` |
| `UNREACHABLE_INSTRUCTION` | `"unreachable insn"`, `"dead code"`, `"jump out of range"` | Remove dead code or restructure control flow |
| `INFINITE_LOOP` | `"back-edge"`, `"loop unbound"`, `"infinite loop detected"` | Use literal-bounded `for` loop or `bpf_loop` |
| `HELPER_NOT_ALLOWED` | `"unknown func"`, `"helper not allowed"`, `"program of this type cannot use helper"` | Move call to a compatible program section |
| `UNRESOLVED_FUNC` | `"unknown opcode"`, `"call to … not allowed"`, `"unsupported function"` | Verify helper exists via `bpftool feature probe` |
| `PROGRAM_TOO_LARGE` | `"bpf program is too large"`, `"processed … insn limit"`, `"too many instructions"` | Split via tail calls or replace loops with `bpf_loop` |
| `ARENA_NOT_ASSOCIATED` | `"addr_space_cast insn can only be used in a program that has an associated arena"` | Framework bug — file an issue; do not add manual `bpfArenaAssociate` calls |
| `INVALID_TIMER_DEFINITION` | `"bpf_timer"` + `"map value"/"not allowed"/"not found"`, `"no timer"`, `"timer field … not owned"` | Wrap `bpf_timer` in a `@Type`-annotated struct used as the map value type |
| `OTHER` | catch-all | Inspect the named instruction; consider adding a new pattern to `classify()` |

Classification order in `classify()` matters: `UNCHECKED_NULL_DEREF` is tested before `INVALID_MEM_ACCESS` because `"invalid mem access 'map_value_or_null'"` matches both.

## Adding a new error class

1. **Extend `ErrorClass`** — add a constant to `VerifierLogParser.ErrorClass` in
   `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/verifier/VerifierLogParser.java`.

2. **Add a classification branch** — in `VerifierLogParser.classify(String message)`, insert a new
   `if` block before the `return ErrorClass.OTHER` line. Use `m.contains(...)` for substring matches
   or compile a `Pattern` constant for regexp matches. Insert before any more-general class it could
   collide with.

3. **Add a hint** — in `VerifierFixSuggester.suggest(VerifierError error)`, add a `case` branch for
   the new constant. The string must contain `"Why:"`, `"Fix:"`, and `"See:"` labels or the
   `everyErrorClassHasAFourPartHint` test will fail.

4. **No registration needed** — there is no SPI or list to update. The `switch` in `suggest()` is
   exhaustive; the compiler will flag a missing case.

5. **Write a unit test** (see [Testing](#testing) below).

## Testing

Tests live in
`bpf-compiler-plugin/src/test/java/me/bechberger/ebpf/bpf/compiler/verifier/`.
They run on macOS without a kernel because `VerifierLogParser` and `VerifierFixSuggester` are pure
Java with no I/O.

**Pattern — classify a raw log string end-to-end:**

```java
@Test
void mapValueOrNullClassifiesAsUncheckedNullDeref() {
    var log = """
            0: (85) call bpf_map_lookup_elem#1
            1: (61) r0 = *(u32 *)(r0 +0)
            R0 invalid mem access 'map_value_or_null'
            """;
    var result = VerifierLogParser.parse(log);
    assertTrue(result.error().isPresent());
    assertEquals(VerifierLogParser.ErrorClass.UNCHECKED_NULL_DEREF,
                 result.error().get().errorClass());
}
```

**Pattern — assert the hint structure for a new class:**

```java
@Test
void myNewClassHintHasRequiredParts() {
    var err = new VerifierLogParser.VerifierError(
            "synthetic", VerifierLogParser.ErrorClass.MY_NEW_CLASS, Optional.of(7));
    String hint = VerifierFixSuggester.suggest(err);
    assertTrue(hint.contains("Why:"));
    assertTrue(hint.contains("Fix:"));
    assertTrue(hint.contains("See:"));
}
```

The `everyErrorClassHasAFourPartHint` test in `VerifierFixSuggesterTest` iterates all `ErrorClass`
values automatically, so any new constant without a hint will fail CI without requiring a bespoke
per-class test.
