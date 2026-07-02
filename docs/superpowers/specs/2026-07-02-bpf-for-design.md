# Design: automatic `bpf_for` lowering for dynamic-bound loops

Compiler-plugin support for the kernel `may_goto`-backed loop primitive
so Java loops with runtime-varying bounds pass the BPF verifier without
requiring `@BoundedBy` or a rewrite into callback style.

The spec is titled around `bpf_for` because that is the only macro the
lowerings in §6 emit. `bpf_repeat` — a fixed-N variant covering the
reverse-count idiom — is deferred as a non-goal per §3, and the
vendored header does not include it.

## 1. Problem

Today, a `@BPFFunction` like

```java
@BPFFunction
void sumFirst(int n) {
    long sum = 0;
    for (int i = 0; i < n; i++) sum += table.lookup(i);
    // ...
}
```

is translated to plain C `for (int i = 0; i < n; i++) { ... }`. The BPF
verifier cannot bound the iteration count at load time because `n` is a
runtime value, and the program is rejected. Users' current remedies:

1. Add `@BoundedBy(N)` on the loop variable, which rewrites the loop to
   include an explicit `if (i >= N) break;` cap. Works but forces a
   static safety cap that is often larger than the real iteration
   count.
2. Rewrite the loop as `BPFJ.bpfLoop(N, (i, ctx) -> { ... }, ctx)`.
   Works but loses `break`/`continue`/`return` semantics and reads
   awkwardly for what should be idiomatic Java.

Kernel 6.11 introduced `may_goto`, a verifier-visible instruction that
lets a loop fall through to termination after a bounded number of
iterations regardless of what the condition evaluates to. The
`bpf_experimental.h` header wraps it in `bpf_for(i, start, end) { ... }`
(a `for`-shaped loop where the verifier accepts arbitrary `start` /
`end`) among other macros.

hello-ebpf targets kernel 6.14+, so `may_goto` is always available.
This spec makes the compiler plugin emit `bpf_for` automatically for
loops whose bound isn't a Java compile-time constant, so users write
normal Java and the plugin picks the correct lowering.

## 2. Goals

- A `@BPFFunction` containing `for (int i = <expr>; i < <expr>; i++)`
  where either bound is not a Java compile-time constant compiles and
  loads without the user touching `@BoundedBy` or `bpfLoop`.
- A `@BPFFunction` containing `while (<cond>)` where `<cond>` is not a
  Java compile-time constant compiles and loads.
- `break`, `continue`, and `return` semantics inside these loops match
  what a Java reader expects.
- The existing `@BoundedBy` path continues to work unchanged for users
  who want the explicit safety cap.
- No behavior change for loops with compile-time-constant bounds.
- No behavior change for loops that don't match the two supported
  shapes (they fall through to today's translation).

## 3. Non-goals

- `do { ... } while (cond)` — not translated today; not added here.
- Enhanced-for over collections — still rejected with today's message.
- Reverse-count for-loops (`for (int i = n; i > 0; i--)`). Fall
  through to today's translation.
- Non-`i++` updates (`i += 2`, `i = i + step`). Fall through.
- Auto-detection of "effectively final" locals as constants. If a
  user wants JLS-constant treatment, they use `final int N = 32;`.
- A user-facing `BPFJ.canLoop()` helper. Not needed since the plugin
  emits `can_loop` internally; users writing hand-rolled `while
  (can_loop)` is out of scope.
- Kernel version probing. hello-ebpf's floor is 6.14+; `may_goto` is
  6.11+; the floor already covers this.
- Any new user-facing annotation. Detection is automatic.

## 4. Architecture

Three pieces, all in the compiler plugin:

**Shape classifier.** A new `LoopShapeClassifier` inspects each
`ForLoopTree` / `WhileLoopTree` and returns one of a sealed set of
`LoopShape` values: `CanonicalFor`, `GenericWhile`, or `Other`. Pure
function of the AST, needs `Trees` and `Types` for constness / type
queries.

**Verbatim lowering in Translator.** In
`Translator.translate(StatementTree)`, inside the `ForLoopTree` case:
after the existing `@BoundedBy` check (unchanged), call the classifier.
On `CanonicalFor`, emit a verbatim `bpf_for(...) { <translated body> }`
CAST node and set the `usedMayGoto` bit on the translator context.
On `Other`, fall through to today's code. Same in the `WhileLoopTree`
case for `GenericWhile`.

**Preamble injection.** When `usedMayGoto` is set on a compilation
unit, prepend `#include "bpf_experimental.h"` to that unit's C
preamble. The header is vendored into the plugin's resources and
placed alongside the generated `.c` file so the relative include
resolves.

The `@BoundedBy` path fires first, so `@BoundedBy` still wins when
present. `EnhancedForLoopTree` continues to be rejected. `DoWhileTree`
continues to be untranslated.

## 5. Shape classification

### 5.1 `CanonicalFor`

A `ForLoopTree` matching exactly:

- **initializer:** one initializer, of the form `int i = <start>` or
  `long i = <start>`. `<start>` may be any expression of the same
  integer type. Declaring the loop variable outside the loop
  (`int i; for (i = 0; ...)`) does not match — the variable must be
  scoped to the loop.
- **condition:** `i < <end>` or `i <= <end>`. Same variable as the
  initializer. `<end>` may be any expression.
- **update:** `i++` or `++i`. Not `i += 1`, not `i = i + 1`.
- **body:** does not reassign `i` at the top level. Shallow walk over
  the immediate statements of the block; nested loops that redeclare
  or shadow `i` are fine.
- **types:** both `<start>` and `<end>` are integer-typed.

Result: `CanonicalFor(String var, ExpressionTree start,
ExpressionTree end, boolean inclusive)`.

### 5.2 `GenericWhile`

A `WhileLoopTree` whose condition expression is not a Java
compile-time constant.

Result: `GenericWhile(ExpressionTree cond)`.

### 5.3 `Other`

Everything else. Includes:

- Non-matching `for` shapes (multiple initializers, non-simple
  condition, `i--` update, body reassigns `i`, etc.).
- `for` and `while` loops whose relevant expressions are all Java
  compile-time constants (today's translation produces correct C).
- `EnhancedForLoopTree` (rejected upstream of the classifier).
- `DoWhileTree` (not translated at all today).

### 5.4 Constness rule

An expression is "constant" iff
`com.sun.tools.javac.tree.TreeInfo.isConstant(expr)` returns true.
This is the same rule the Java compiler uses for `switch` case labels
(JLS §15.28). No other heuristic is applied.

**Consequence:** `for (int i = 0; i < N; i++)` where `N` is a field, a
method parameter, or a non-`final` local counts as *dynamic* and gets
`bpf_for`. A user who wants JLS-constant treatment writes
`final int N = 32;` at the appropriate scope.

**No user-visible regression.** Loops that loaded before still load
(bpf_for is a superset of what today's plain-C emission handles).
Loops that failed to load before because the verifier couldn't fold a
non-constant bound now load. Only the emitted C string changes for
these loops.

## 6. Lowering

### 6.1 `CanonicalFor` → `bpf_for`

- `i < <end>` → `bpf_for(<var>, <start>, <end>) { <body> }`
- `i <= <end>` → `bpf_for(<var>, <start>, (<end>) + 1) { <body> }`

Parentheses around `<end>` in the inclusive case preserve precedence
when `<end>` is a compound expression such as `a - b`.

**Overflow footnote:** `i <= INT_MAX` would silently overflow after
the `+ 1`. The verifier catches this in the pathological case; no
guard emitted.

### 6.2 `GenericWhile` → `while (can_loop)`

```
while (can_loop) {
    if (!(<cond>)) break;
    <body>
}
```

- `break` in body → C `break`; exits the `while (can_loop)`.
- `continue` in body → C `continue`; jumps to the `can_loop` check,
  which then re-tests `<cond>`.
- `return` → C `return`.
- Nested loops in body are classified and lowered independently.

### 6.3 CAST integration

Body is emitted via the existing recursive translation (so nested
statements, method calls, nested loops all keep working). Only the
loop scaffold (`bpf_for(...) { ... }` or `while (can_loop) { if
(!...) break; ... }`) is verbatim.

The plan task locates the existing verbatim-string CAST escape (a
`RawText`-style node or `verbatim(String)` factory) and reuses it. If
no such escape exists, the plan adds a minimal
`CAST.Statement.Verbatim(String)` node with one pretty-printer branch.

## 7. Vendored header

Location:
`bpf-compiler-plugin/src/main/resources/bpf_experimental.h`.

Source: copied at plan-execution time from
`tools/testing/selftests/bpf/bpf_experimental.h` in the current Linux
kernel tree, trimmed to the three macros this feature actually emits:
`may_goto`, `can_loop`, `bpf_for`. `bpf_repeat` is *not* vendored —
none of the lowerings in §6 emit it (reverse-count for-loops are a
non-goal per §3). If a future feature adds a lowering that uses
`bpf_repeat`, that feature adds the macro to the header.
Macro bodies are verbatim from upstream — not paraphrased.

Header retains its upstream SPDX identifier
(`GPL-2.0 OR BSD-3-Clause`) and adds a comment noting the trim and
the source path.

### 7.1 Placement of the header next to generated C

Preferred: the plugin copies the header into the same generated-sources
directory as each generated `.c` file at build time, so
`#include "bpf_experimental.h"` resolves as a relative include. The
plan task inspects one existing generated directory (e.g.
`bpf/target/generated-sources/annotations/...`) to confirm this
matches how other framework headers are handled; if not, the plan
falls back to adding `-I <resource-dir>` to the clang invocation.

### 7.2 Preamble injection point

`moveIncludesToTheFront` in `CompilerPlugin.java` reorders existing
includes but does not add new ones. The real emission point is
wherever the framework's baseline includes (`vmlinux.h`, etc.) are
printed. The plan's first task finds that site by grepping for
`bpf_helpers.h` or the file-header assembly. At that site:

```java
if (translationContext.usedMayGoto()) {
    output.append("#include \"bpf_experimental.h\"\n");
}
```

The `usedMayGoto` flag lives on the per-compilation-unit translator
context, set by the classifier's emit paths.

### 7.3 Attribution

Vendored external content needs an attribution entry. This is a
Linux kernel header rather than ebpf.io / blog content, so it does not
fit the existing `docs/assets/*/CREDITS.md` bins. The plan adds a
paragraph to `NOTICE.md` at the repo root (creating the file if it
does not exist): "bpf-compiler-plugin/src/main/resources/bpf_experimental.h
is copied from the Linux kernel source tree
(`tools/testing/selftests/bpf/bpf_experimental.h`, licensed
`GPL-2.0 OR BSD-3-Clause`), trimmed to `may_goto`, `can_loop`, and
`bpf_for`."


## 8. Error handling and diagnostics

**No new compile-time errors.** The classifier returns `Other` for
anything it cannot confidently lower; nothing about the loop is newly
rejected relative to today.

**No new runtime classifier entries.** hello-ebpf's kernel floor is
6.14+; `may_goto` is 6.11+; a user hitting an unsupported-kernel
error for `may_goto` specifically is unreachable in practice. If a
user runs on <6.14 they hit dozens of other issues first, and the
general unsupported-kernel story is not this feature's problem.

**Header drift.** If the vendored header ever diverges from a kernel
change (macro shape drift), the failure surfaces as a clang compile
error on the generated C, which the existing compile-error pipeline
already surfaces to the user. No special handling.

## 9. Sample and testing

### 9.1 Sample

`bpf-samples/src/main/java/me/bechberger/ebpf/samples/DynamicLoopSample.java`:

- Small `@BPF` class.
- A HASH map `counters: int → long`.
- A tracepoint or `execve` attachment (following `HelloWorld`
  simplicity).
- Reads a runtime-varying `int n` from an `@Type` global.
- Handler runs `for (int i = 0; i < n; i++) sum += counters.get(i);`
  and writes `sum` back to another global.
- `main()` sets `n = 32`, sleeps briefly, prints the sum.

Purpose: demonstrates a normal-looking Java for-loop with a dynamic
bound loads and runs. Doubles as the real-kernel smoke test.

### 9.2 Plugin unit tests

Location: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/LoopLoweringTest.java`.

Run on mac (pure Java, no kernel).

- `canonicalForWithDynamicEndLowersToBpfFor` — `for (int i = 0; i < n;
  i++)` where `n` is a parameter → assert generated C contains
  `bpf_for(i, 0, n)`.
- `canonicalForWithInclusiveEndAddsOne` — `i <= n` → assert
  `bpf_for(i, 0, (n) + 1)`.
- `canonicalForWithConstantBoundStaysPlainFor` — `i < 10` → assert
  plain `for` and no `bpf_for`.
- `boundedByStillWins` — `@BoundedBy` loop → assert existing rewrite
  is present and no `bpf_for`.
- `genericWhileLowersToCanLoop` — dynamic-condition `while` → assert
  generated C contains `while (can_loop)` and
  `if (!(<cond>)) break;`.
- `whileTrueStaysPlainWhile` — `while (true)` → assert no `can_loop`.
- `nestedLoopsAreLoweredIndependently` — a canonical-for containing a
  dynamic-condition while → assert each nested loop is in its correct
  form.
- `experimentalHeaderIncludedWhenUsed` — any lowering fires → assert
  `#include "bpf_experimental.h"` in preamble.
- `experimentalHeaderAbsentWhenUnused` — no lowering fires → assert
  header not included.

### 9.3 Real-kernel integration test

Location:
`bpf-samples/src/test/java/me/bechberger/ebpf/samples/DynamicLoopSmokeTest.java`.

Runs on thinkstation via vng (matches the pattern of
`RustlandFifoSampleSmokeTest`). Loads `DynamicLoopSample`, sets a
known `n`, triggers the handler, reads the sum, asserts it matches
the expected value. The load itself is the primary assertion: it
proves the verifier accepts the `bpf_for` lowering.

## 10. Interaction with the pending arena-association work

There is separate in-flight work on automatic `@InArena` per-prog
arena association in the compiler plugin. That work also modifies
`Translator.java` and `CompilerPlugin.java`. These features are
functionally orthogonal but touch overlapping files.

- If the arena work lands first: this feature's plan rebases onto the
  new structure. The arena work adds a translator side-channel and a
  post-translation pass; the loop-translation switch inside
  `translate(StatementTree)` is unchanged, so the rebase is
  mechanical.
- If this feature lands first: the arena work rebases similarly.
- If both are in flight: the implementation plans call out which
  files each touches so an executor can serialize.

## 11. Docs updates

Deferred to a follow-up commit if the docs-restructure Spec 1 stubs
are not landed by the time this ships.

- `docs/verifier-features.md`: one row noting automatic dynamic-bound
  loop support via `may_goto`.
- Loop cookbook page (name pending Spec 1 stubs): one paragraph and
  one code snippet showing which loop shape works automatically vs.
  which still needs `@BoundedBy` or `bpfLoop`.
- `docs/reference/bpfj.md` (from Spec 1): mention `can_loop` /
  `bpf_for` / `bpf_repeat` as macros the framework may emit, so a
  reader inspecting generated C recognizes them.

## 12. Success criteria

- All plugin unit tests in §9.2 pass on the mac.
- `DynamicLoopSample` loads and produces the correct sum on
  thinkstation under vng.
- `RustlandFifoSampleSmokeTest` and other existing samples continue
  to pass (no regression on loops with constant bounds).
- Generated `.c` files for programs that don't use dynamic loops
  contain no `#include "bpf_experimental.h"` (proves the flag is
  actually conditional).

## 13. Handoff

Plan writer: read this spec in full, then produce
`docs/superpowers/plans/2026-07-02-bpf-for.md` following the
writing-plans skill. Tasks should be sized so each ends with a
commit and a green build gate. The first task must inspect the
existing include-emission path and confirm the injection point before
any lowering code lands, since the current understanding is inferred
from grep, not observed on disk.
