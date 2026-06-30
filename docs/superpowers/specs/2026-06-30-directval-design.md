# `Ptr.directVal()` + Inline-C Builtin Removal — Design

## Context

`Ptr.val()` lowers to `(*($this))` via `@BuiltinBPFFunction`. When the result is followed by a `MemberSelect` whose root resolves to a kernel-BTF type, the compiler plugin's `tryLiftCoreRead` rewrites the access into a `BPF_CORE_READ(p, field)` chain. This is correct and required for forward-compat across kernel struct layouts — but `BPF_CORE_READ` strips the **trusted-pointer** annotation that some kfuncs require on their arguments.

Concrete symptom: `bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)` fails verifier load because the cpumask argument arrives untrusted. The current workaround in `UserspaceSchedulerBase` is an inline-C `@BuiltinBPFFunction`:

```java
@BuiltinBPFFunction("bpf_cpumask_test_cpu((u32)$arg1, $arg2->cpus_ptr)")
static boolean taskCpuIsAllowed(int cpu, Ptr<task_struct> p) { ... }
```

This is a code smell: every CO-RE / trusted-pointer collision spawns another inline-C builtin. We want a clean Java-side mechanism instead.

The Translator's `stripPtrVal()` method matches the method name `"val"` exactly and pierces the `Ptr` to expose the receiver for `tryLiftCoreRead`. **A pierce method with any other name skips the lifting entirely** — the MemberSelect ends up as plain `(*p).field`, which clang lowers to `p->field` with the trusted annotation preserved.

That's the lever this design uses.

A second, related cleanup: `UserspaceSchedulerBase` also has two arena-write builtins:

```java
@BuiltinBPFFunction("*($arg1) |= (s64)($arg2)") static void arena_or_assign(...)
@BuiltinBPFFunction("*($arg1) &= (s64)($arg2)") static void arena_and_assign(...)
```

These predate proper Java translation of `Ptr.set(Ptr.val() | x)`. **Validated on thinkstation 2026-06-30**: `word.set(word.val() | mask)` lowers to `*(word) = (*(word)) | mask` — identical non-atomic C to the builtin template. The two builtins are gratuitous and can be deleted in the same change.

## Approach

Add `Ptr.directVal()` — a sibling of `val()` whose body is just `return val();` and whose distinguishing feature is the *name*. Because `stripPtrVal()` only matches `"val"`, the result of `directVal()` doesn't go through CO-RE lifting; subsequent `MemberSelect` accesses emit direct field reads.

To express the body as plain Java (no `@BuiltinBPFFunction` template duplication), we **generalise `@BPFJavaInline` to work on any class**, not only `@BPFAbstraction`-annotated ones. The carrier-field rewrite (every instance field substituted with the receiver expression) stays gated behind `@BPFAbstraction`; for non-abstraction classes, only `this` is substituted with the receiver. That makes `@BPFJavaInline` a general-purpose "inline this Java body at the call site" primitive — and lets `Ptr.directVal()` say literally `return val();` and have the plugin inline it to `(*(p))` via `val()`'s existing template.

`directVal()` is a sharp tool. The plugin enforces a structural rule: **the result of `directVal()` must be immediately followed by a `MemberSelect`**, or the call is a compile error. Two overrides relax the check:

- `@TrustedPtr` on a kfunc parameter — declares "feeding this argument needs a trusted pointer; `directVal()` calls landing in this parameter are intentional." Documents the *why* at the API.
- `@AllowDirectVal` on a local-variable declaration or enclosing `@BPFFunction` — escape hatch for cases where the user can't annotate the kfunc parameter (e.g., externally-declared builtins).

In the same change, delete the three inline-C builtins (`taskCpuIsAllowed`, `arena_or_assign`, `arena_and_assign`) and rewrite their call sites in pure Java.

## File Structure

**`bpf-processor/src/main/java/me/bechberger/ebpf/type/Ptr.java`** — add `directVal()` using `@BPFJavaInline`. Pure additive change.

**`annotations/src/main/java/me/bechberger/ebpf/annotations/`** — add two source-retention annotations:
- `TrustedPtr.java` — `@Target(PARAMETER)`
- `AllowDirectVal.java` — `@Target({LOCAL_VARIABLE, METHOD})`

**`bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/Translator.java`** —
- **Generalise `@BPFJavaInline`**: lift the `@BPFAbstraction` gate in `tryInlineAbstractionMethod` (line 2409). When the enclosing class is `@BPFAbstraction`, keep current behaviour (all instance fields substituted with receiver). When it is NOT, skip field-substitution; only `this` references in the body resolve to the receiver expression. Rename `tryInlineAbstractionMethod` → `tryInlineJavaInlineMethod` to reflect the broader applicability.
- Extend `stripPtrVal()` to also match `"directVal"` (so the result is pierced for emission).
- Add the structural check at the `MethodInvocationTree` emission site: detect `directVal()` calls, classify by parent shape (MemberSelect = OK; else search for override; else error).

**`annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFJavaInline.java`** —
- Update Javadoc: remove the "only on `@BPFAbstraction`" implication; document the field-substitution caveat ("carrier-field substitution only applies on `@BPFAbstraction` classes; on other classes, `this` is the only thing rewritten").

**`bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java`** —
- Delete `taskCpuIsAllowed`, `arena_or_assign`, `arena_and_assign` methods.
- Rewrite callers (cpumask check in selectCpu's path; setBit/clearBit) using `directVal()` + plain Java arithmetic on `set`/`val`.

**`bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java`** —
- `tryDispatchToLocalCpu` at line 1040 currently uses `bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)`, which lowers to `BPF_CORE_READ(p, cpus_ptr)` (verified in UserspaceSchedulerBaseImpl.c:293) — the same trusted-pointer bug `taskCpuIsAllowed` was created to dodge. Migrate to `p.directVal().cpus_ptr` to fix it for all Scheduler implementations.

**`bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/BpfDefinitions.java:7177`** —
- Add `@TrustedPtr` to the second parameter of the `bpf_cpumask_test_cpu` declaration. This is a generated file; check whether it's regenerated from a `.btf` extractor pass — if so, also update the extractor template. If not, the annotation can be added directly.

**Other call sites** to audit and migrate as part of this work:
- `bpf-samples/.../LotteryScheduler.java:41` — `bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)` (same pattern).
- `bpf/src/main/java/me/bechberger/ebpf/bpf/sched/DispatchQueue.java:341` — appears in a Javadoc snippet; update the doc.

**`bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/DirectValTest.java`** — new file with the seven directVal unit cases.

**`bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/BPFJavaInlineGeneralisationTest.java`** — new file covering the lifted `@BPFAbstraction` gate (see Tests).

**`bpf-samples/src/test/java/me/bechberger/ebpf/bpf/DirectValTaskCpuAllowedTest.java`** — new framework-level integration test running a minimal scheduler that exercises `p.directVal().cpus_ptr` against a real kernel.

## API Surface

### `Ptr.directVal()`

```java
/**
 * Like {@link #val()}, but tells the BPF compiler plugin to emit a *direct*
 * field access ({@code (*p).field} → {@code p->field}) instead of a CO-RE
 * relocation ({@code BPF_CORE_READ(p, field)}).
 *
 * Use this only when a kfunc requires a trusted pointer on a field load.
 * BPF_CORE_READ strips the trusted annotation; a direct access preserves it.
 *
 * The plugin enforces that the result of directVal() is immediately followed
 * by a field access. Other uses are a compile error. To override the check,
 * annotate the call site with @AllowDirectVal or the kfunc parameter with
 * @TrustedPtr.
 *
 * Outside a @BPFFunction body this method is identical to val().
 */
@BPFJavaInline
@NotUsableInJava
public T directVal() {
    return val();
}
```

The `@BPFJavaInline` body inlines the `val()` call to its template `(*($this))`, so at every call site `p.directVal()` becomes `(*(p))` — identical to `val()`'s emitted C, only the method name differs (and that's what suppresses the CO-RE lifting via `stripPtrVal()`).

This relies on the generalised `@BPFJavaInline` — `Ptr` is not `@BPFAbstraction`, so the carrier-field substitution doesn't apply; only `this` resolves to the receiver expression.

### `@TrustedPtr`

```java
@Target({ElementType.PARAMETER})
@Retention(RetentionPolicy.SOURCE)
public @interface TrustedPtr {}
```

Marker for kfunc parameter declarations. Documents that the kfunc expects a trusted pointer and that `directVal()` field accesses are the intended way to feed it.

### `@AllowDirectVal`

```java
@Target({ElementType.LOCAL_VARIABLE, ElementType.METHOD})
@Retention(RetentionPolicy.SOURCE)
public @interface AllowDirectVal {}
```

Call-site escape hatch.

## Plugin Enforcement

### Generalising `@BPFJavaInline`

The check that currently restricts inlining to `@BPFAbstraction` classes lives at `Translator.java:2409`:

```java
if (enclosingClass.getAnnotation(BPFAbstraction.class) == null) {
    return null;
}
```

Remove this gate. The downstream code that builds the carrier-field substitution map (lines 2437-2456) stays — but it should be guarded so that on non-`@BPFAbstraction` classes the `innerCarrierMap` is left empty for fields, and only `this` is populated.

Pseudocode for the gated section:

```java
boolean isAbstraction = enclosingClass.getAnnotation(BPFAbstraction.class) != null;
String carrierExpr = receiverExpr != null ? translate(receiverExpr).toPrettyString() : null;

if (isAbstraction && carrierExpr != null) {
    // Existing behaviour: every instance field rewritten to the receiver expression.
    for (var fieldName : collectInstanceFields(enclosingClass)) {
        innerCarrierMap.put(fieldName, carrierExpr);
    }
}
if (carrierExpr != null) {
    innerCarrierMap.put("this", carrierExpr);  // always available
}
```

The inner translator's `this`-substitution is the new piece — verify the existing carrier-map lookup path also routes `this` references through `innerCarrierMap`. If it doesn't, add that handling. (The existing `@BPFAbstraction` use case never references `this` because the field substitution covers it; the test suite for that path doesn't exercise `this`. The Translator's expression path that resolves `MemberSelectTree` against `this` needs to be reviewed during implementation.)

Rename `tryInlineAbstractionMethod` → `tryInlineJavaInlineMethod`.

### `directVal()` structural check

A single check at the `MethodInvocationTree` translation site in `Translator.java`:

1. Detect `directVal()` invocation via a helper `isDirectValCall(mit)` that mirrors the structure of `stripPtrVal()`.
2. Inspect `TreePath.getParentPath().getLeaf()`:
   - **`MemberSelectTree`** → OK, emit the pierce, no diagnostic.
   - **Anything else** → run override search:
     - Walk to the enclosing `MethodInvocationTree`. If found, resolve the callee `MethodSymbol`, locate the parameter index this expression is passed as, check for `@TrustedPtr` on the parameter symbol → OK.
     - Walk to the enclosing `VariableTree` or `StatementTree`. Check its modifiers for `@AllowDirectVal` → OK.
     - Walk to the enclosing `@BPFFunction`-annotated `MethodTree`. Check its modifiers for `@AllowDirectVal` → OK.
   - Otherwise emit `compiler.err.proc.messager` at the call site:
     > `directVal() result must be followed by a field access (or annotate the kfunc parameter with @TrustedPtr / the call site with @AllowDirectVal)`

Also extend `stripPtrVal()` so it pierces both `val` and `directVal` — without this, the `(*p)` produced by the inlined body would be left in the emitted C verbatim, breaking the MemberSelect-to-direct-access lowering.

## Migration of UserspaceSchedulerBase

### Site 1 — `taskCpuIsAllowed`

**Delete** the builtin method. **Replace** the single call site (in the cpumask-affinity check) with:

```java
if (bpf_cpumask_test_cpu(cpu, p.directVal().cpus_ptr)) { ... }
```

**Annotate** the `bpf_cpumask_test_cpu` Java parameter declaration in `bpf-runtime/.../BpfDefinitions.java:7177` with `@TrustedPtr` so the structural check passes silently.

### Site 1b — `Scheduler.tryDispatchToLocalCpu`

Currently `bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)`. The generated C emits `BPF_CORE_READ(p, cpus_ptr)` (UserspaceSchedulerBaseImpl.c:293). Migrate to:

```java
if (!bpf_cpumask_test_cpu(cpu, p.directVal().cpus_ptr)) return false;
```

Same migration in `LotteryScheduler.java:41`.

### Sites 2 & 3 — `arena_or_assign` / `arena_and_assign`

**Delete** both builtin methods. **Replace** call sites in `setBit`/`clearBit`:

```java
Ptr<Long> word = idleMaskBase.add(wordIdx);
if (idle) word.set(word.val() | mask);
else      word.set(word.val() & ~mask);
```

The local variable ensures `idleMaskBase.add(wordIdx)` is evaluated once, matching the builtin's semantics.

## Tests

**`@BPFJavaInline` generalisation tests** (`BPFJavaInlineGeneralisationTest.java`, mac OK):

1. `javaInlineWorksOnNonAbstractionClass` — non-`@BPFAbstraction` class with a `@BPFJavaInline` method calling another method; assert body inlines correctly at the call site.
2. `javaInlineFieldSubstitutionStillRequiresAbstraction` — non-`@BPFAbstraction` class with an instance field; `@BPFJavaInline` method body references the field; assert the field reference is emitted as `receiver->field` (regular field access) **not** rewritten to the carrier expression. (This is the boundary that distinguishes the new behaviour from the original carrier-substitution.)
3. `javaInlineCarrierSubstitutionStillWorksOnAbstraction` — control: existing `@BPFAbstraction` + `@BPFJavaInline` test from `BPFAbstractionTest` continues to pass unchanged.
4. `javaInlineThisSubstitution` — non-`@BPFAbstraction` class with `@BPFJavaInline` body that uses `this` explicitly; assert `this` resolves to the receiver carrier expression.

**`directVal()` plugin unit tests** (`DirectValTest.java`, mac OK):

1. `directValBeforeMemberSelectEmitsDirectAccess` — `kfunc(p.directVal().field)` → C contains `kfunc(p->field)`, not `BPF_CORE_READ(p, field)`.
2. `directValWithoutMemberSelectErrors` — `long x = p.directVal()` → compile error with documented message.
3. `directValWithTrustedPtrParamSilent` — kfunc param annotated `@TrustedPtr`, `directVal()` used in non-MemberSelect context → no error.
4. `directValWithAllowDirectValOnStatementSilent` — `@AllowDirectVal` on a local-var declaration → no error.
5. `directValWithAllowDirectValOnMethodSilent` — `@AllowDirectVal` on the enclosing `@BPFFunction` → no error.
6. `valCallStillEmitsCoreRead` — control: `p.val().field` still emits `BPF_CORE_READ` (no regression).
7. `directValOnNonPtrReceiverDoesNotCrash` — `someObj.directVal()` where `someObj` isn't a `Ptr`: plugin doesn't crash, doesn't false-error.

**Framework-level integration test** (thinkstation, vng-required):

`DirectValTaskCpuAllowedTest` — minimal `@BPF` scheduler that invokes `bpf_cpumask_test_cpu(cpu, p.directVal().cpus_ptr)` inside `enqueue()`. Real-kernel load must succeed. If `directVal()` regresses to CO-RE lifting, the verifier rejects with a trusted-pointer error — this test catches it.

**Regression coverage:**

- `ArenaFromStructOpsHandlerTest` (Task E) exercises `counter.set(counter.val() + 1)` against the real kernel — already covers the arena `set/val` path.
- `RustlandFifoSampleSmokeTest` exercises `setBit`/`clearBit` post-refactor.

**Manual verification (in implementation plan):**

Inspect `bpf/target/generated-sources/.../UserspaceSchedulerBaseImpl.c`:
- `taskCpuIsAllowed`, `arena_or_assign`, `arena_and_assign` no longer appear.
- Cpumask check call site emits `bpf_cpumask_test_cpu(cpu, p->cpus_ptr)`.
- `setBit`/`clearBit` emit `*(word) = (*(word)) | mask` / `& ~mask`.

## Validation Anchors

- **Arena builtin removal hypothesis** validated on thinkstation 2026-06-30 with a stub `ArenaCompoundTest` exercising `word.set(word.val() | mask)` — emitted `*(word) = (*(word)) | mask`. Same lowering as the deleted builtin's template.
- **`p.val().cpus_ptr` does lower to `BPF_CORE_READ(p, cpus_ptr)`** — verified in `UserspaceSchedulerBaseImpl.c:293` (the `tryDispatchToLocalCpu` body). The inline-C `taskCpuIsAllowed` builtin at line 795 of the same file emits `p->cpus_ptr` directly, confirming the gap `directVal()` is designed to close.
- **`stripPtrVal` only matches "val"** — confirmed by reading `Translator.java:2289` (`!"val".contentEquals(mst.getIdentifier())`). A method named `directVal` falls through the early-return and is *not* stripped; the `(*p)` template survives translation, and the MemberSelect on it produces `(*p).field` → `p->field` in clang.

## Out of Scope

- New trusted-pointer mechanisms beyond the field-access case.
- Atomic arena writes (`__sync_fetch_and_or` etc.) — separate design if/when needed; BPF_ATOMIC is rejected on AS1 today.
- Auditing every `@BuiltinBPFFunction` in the codebase for inline-C-replaceability — focused scope: only the three in `UserspaceSchedulerBase`.
- A pre-pass architecture (`DirectValGuardPass`) — rejected as over-engineered for a single structural check.
