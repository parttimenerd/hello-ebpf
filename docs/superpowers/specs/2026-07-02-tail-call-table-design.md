# Design: `@BPFTailCallTable` — annotation surface for `PROG_ARRAY`

Add an annotation-driven binding layer over the existing
`BPFProgArray` so a user can declare a tail-call table by name, mark
methods as slot-N implementations, and have the compiler plugin plus
runtime automatically populate the map with the resolved program fds.

Parent roadmap: `docs/superpowers/specs/2026-07-02-roadmap-t0-plus.md`
§6. Assumes hello-ebpf's existing single-shot `BPFProgram.load()`
lifecycle (no three-phase open/load split).

## 1. Problem

`BPFProgArray` already exists at
`bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java` (96
lines). It wraps `BPF_MAP_TYPE_PROG_ARRAY`, offers
`register(int slot, ProgramHandle)`, and exposes a builtin
`tailCall(ctx, slot)` that lowers to `bpf_tail_call(ctx, &map, slot)`.

What's missing is the wiring that turns this into a first-class user
API:

- Users must declare a program array via `@BPFMapDefinition` and set
  `maxEntries` by hand, matching the number of tail-call targets they
  intend to register.
- Users must call `array.register(slot, prog.getProgramByName("X"))`
  explicitly, for every slot, at the right point in their `main()`.
  Getting a slot number wrong is silent — the wrong program tail-calls
  and the trace goes off the rails.
- There is no compile-time check that slot indices are unique, in
  bounds, or that methods declared as tail-call targets are of a
  program type compatible with the entry program's context.
- Users cannot reference "slot 0" by a stable name; slot numbers get
  hardcoded on both the C-side dispatch (`tailCall(ctx, 0)`) and the
  Java-side registration.

Every canonical tail-call use case — the profiler pattern (dispatch by
runtime type: native / hotspot / send-error), state-machine transitions,
plugin architectures — needs one BPF program per slot, all populated
at startup with no manual index-tracking. The library work is already
done; only the annotation surface is missing.

## 2. Goals

- `@BPFTailCallTable(maxEntries = N)` on a `BPFProgArray` field declares
  a tail-call table; the plugin wires the map definition and remembers
  the field's name.
- `@BPFTailCallSlot(table = "field-name", slot = i)` on a `@BPFFunction`
  method binds that program to slot `i` of the named table.
- After `BPFProgram.load(cls)` returns, all `@BPFTailCallSlot` methods
  are already registered — the user does not call `.register(...)`.
- Compile-time checks: unique `(table, slot)` pairs; `slot < maxEntries`;
  method has a compatible context type; the referenced table field
  exists and is marked `@BPFTailCallTable`.
- Runtime fallback: users may still call `array.register(slot, handle)`
  post-load to override or add manual slots. The auto-registration
  short-circuits when the same slot is already populated.

## 3. Non-goals

- **Runtime slot names.** Slots are `int`s; no string-keyed dispatch.
- **Slot ranges on a single method.** Each `@BPFTailCallSlot` declares
  one slot. Two slots pointing at the same body need two methods (or
  two `@BPFTailCallSlot` annotations if we later allow repeatable).
- **Dynamic table resizing.** `maxEntries` is fixed at compile time.
- **Cross-program-array tail calls.** `bpf_tail_call` only reaches
  programs in the *same* map. Users who want cross-map dispatch write
  their own logic.
- **Compile-time check on tail-call target reachability.** A
  `@BPFFunction` marked `@BPFTailCallSlot` may still get called via
  `bpf_tail_call` from elsewhere; we don't statically prove one caller
  or one path.
- **Auto-inferred `maxEntries`.** Users write it. The plugin errors if
  the highest `slot` exceeds `maxEntries - 1`.

## 4. Architecture

Three components, all additive:

**Annotations.** `@BPFTailCallTable` on a `BPFProgArray` field.
`@BPFTailCallSlot` on `@BPFFunction` methods that are targets.

**Compiler plugin.** Extends the existing map-discovery pass in
`bpf-processor` to recognise `@BPFTailCallTable` and emit the map
definition with `BPF_MAP_TYPE_PROG_ARRAY` (this is what `BPFProgArray`'s
`cTemplate` already produces via `@BPFMapDefinition` — the new
annotation is a superset that carries slot-binding metadata). Extends
the method-discovery pass to record `(field-name, slot)` for every
`@BPFTailCallSlot`.

**Runtime.** `BPFProgram.load(cls)` runs a post-load hook (generated
in `BPFImpl` by the plugin) that iterates the collected
`(field-name, slot, program-name)` triples and calls the existing
`BPFProgArray.register(slot, handle)` API. No new runtime primitives.

## 5. Java API

### 5.1 `@BPFTailCallTable`

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Declare a program array (BPF_MAP_TYPE_PROG_ARRAY) used for tail
 * calls. Methods marked @BPFTailCallSlot(table = "&lt;this field's
 * name&gt;", slot = i) are registered into slot i at load time.
 *
 * &lt;p&gt;The field must be of type {@link
 * me.bechberger.ebpf.bpf.map.BPFProgArray}.
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFTailCallTable {
    /** Number of slots. All slots referenced by @BPFTailCallSlot must
     *  satisfy 0 &le; slot &lt; maxEntries. */
    int maxEntries();
}
```

Only fields typed as `BPFProgArray` may carry this annotation; the
plugin errors otherwise. The plugin also errors if the same field
carries both `@BPFMapDefinition` and `@BPFTailCallTable` (the
tail-call table implicitly defines the map).

### 5.2 `@BPFTailCallSlot`

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Bind this @BPFFunction to a fixed slot of a @BPFTailCallTable.
 * Auto-registration fires at BPFProgram.load() time.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFTailCallSlot {
    /** Name of a class field annotated @BPFTailCallTable. */
    String table();

    /** Slot index. 0 &le; slot &lt; table's maxEntries. */
    int slot();
}
```

The method must also be `@BPFFunction` (otherwise it has no BPF
section to attach). The plugin errors on missing companion
annotations.

### 5.3 Usage

```java
@BPF
public abstract class Profiler extends BPFProgram {

    @BPFTailCallTable(maxEntries = 8)
    public BPFProgArray tracers;   // initialised by plugin-generated BPFImpl

    @BPFTailCallSlot(table = "tracers", slot = 0)
    @BPFFunction
    public void unwindNative(Ptr<pt_regs> ctx) {
        // ...
    }

    @BPFTailCallSlot(table = "tracers", slot = 1)
    @BPFFunction
    public void unwindHotspot(Ptr<pt_regs> ctx) {
        // ...
    }

    @BPFTailCallSlot(table = "tracers", slot = 7)
    @BPFFunction
    public void sendError(Ptr<pt_regs> ctx) {
        // ...
    }

    @PerfEvent(freq = 99)
    public void onSample(Ptr<pt_regs> ctx) {
        int which = pickTracer(ctx);   // e.g. based on task->comm
        tracers.tailCall(ctx, which);  // lowers to bpf_tail_call
        // never returns unless the map slot is unpopulated
    }
}

// In main():
try (Profiler p = BPFProgram.load(Profiler.class)) {
    p.autoAttachPrograms();
    // tracers slot 0/1/7 already populated; user does nothing.
    Thread.sleep(5000);
}
```

### 5.4 Runtime escape hatch

Users may still call `array.register(slot, handle)` after `load()`.
This overwrites the auto-registered fd. Users may also point a slot at
a program *not* declared as `@BPFTailCallSlot` — the two paths compose.

## 6. Compiler plugin work

### 6.1 Map discovery

`TypeProcessor.java`'s field-discovery pass currently scans for
`@BPFMapDefinition`. Extend it to also scan for `@BPFTailCallTable`.
When found:

1. Validate the field type is `BPFProgArray`.
2. Validate no companion `@BPFMapDefinition`.
3. Emit the map C definition from `BPFProgArray`'s existing `cTemplate`,
   substituting `$maxEntries` with the annotation's value.
4. Emit the `BPFImpl` field initialiser (matches `javaTemplate =
   "new $class($fd, $maxEntries)"`).
5. Record the `field-name → maxEntries` mapping in a plugin-side
   structure for later cross-checking.

### 6.2 Slot discovery

Method-discovery pass: for each `@BPFTailCallSlot`:

1. Look up the referenced `table` field. Error if missing or not
   `@BPFTailCallTable`.
2. Validate `0 <= slot < maxEntries`.
3. Validate the method is also `@BPFFunction`.
4. Validate `(table, slot)` is unique across the class. On collision,
   error citing both methods.
5. Record the `(table, slot, methodName)` triple in a plugin-side
   structure.

### 6.3 Registration code emission

In the generated `BPFImpl` constructor (or in a
`postLoadRegister()` method invoked by `BPFProgram.load`), after all
programs are loaded and all maps are opened:

```java
// Generated by the plugin:
private void postLoadRegisterTailCallSlots() {
    tracers.register(0, getProgramByName("unwindNative"));
    tracers.register(1, getProgramByName("unwindHotspot"));
    tracers.register(7, getProgramByName("sendError"));
}
```

Called at the tail of the existing `BPFProgram.load()` path, after
`bpf_object__load` succeeds.

### 6.4 C emission of the tail-call target

The `@BPFFunction` machinery already emits each method as a separate
BPF program with a `SEC(...)` line. `@BPFTailCallSlot` does not
override the section — the method keeps whatever section its other
annotations give it (typically none — tail-call targets don't need
attach type). Convention: methods with only `@BPFFunction` +
`@BPFTailCallSlot` get `SEC("kprobe/tail_call_target")` or similar
neutral section that the verifier accepts. Verify: check what
`BPFProgArray.tailCall` currently expects the callee to be tagged as
(likely `SEC("prog") + prog_type inferred from caller`); match.

## 7. Validation rules (all compile-time)

- `@BPFTailCallTable` on a non-`BPFProgArray` field → error.
- `@BPFTailCallTable` alongside `@BPFMapDefinition` on the same field
  → error.
- `@BPFTailCallSlot` on a method not also `@BPFFunction` → error.
- `@BPFTailCallSlot(table = "X")` where no field named `X` has
  `@BPFTailCallTable` → error.
- `@BPFTailCallSlot(slot = N)` where `N >= maxEntries` → error.
- Duplicate `(table, slot)` on the same class → error, citing both
  methods.
- `slot < 0` → error.

## 8. Interaction with other roadmap features

- **§4 cookies + `@KProbe.Multi`.** No interaction. Tail-call target
  programs are never directly attached, so cookies aren't relevant.
- **§8 `Features.hasX(...)`.** `Features.hasMapType(PROG_ARRAY)` is
  always true on 6.14+; no runtime gate needed. `Features.hasHelper(
  TAIL_CALL)` similarly. No integration required.
- **§3 `@StructOps`.** No interaction.
- **§7 `HASH_OF_MAPS`.** Independent.
- **§2 `bpf_for` / `bpf_repeat`.** Independent.

## 9. Testing

### 9.1 Compile-time diagnostic tests (mac)

`bpf-compiler-plugin-test/src/test/java/.../BPFTailCallTableAnnotationTest.java`:

- `slotOutOfRangeReported` — `slot = 8` with `maxEntries = 8` → error.
- `duplicateSlotReported` — two methods with same `(table, slot)` →
  error, citing both.
- `unknownTableReported` — `table = "nonexistent"` → error.
- `nonProgArrayFieldReported` — `@BPFTailCallTable` on a
  `BPFHashMap<...>` → error.
- `bothTableAndMapDefinitionReported` — combined annotations → error.

### 9.2 Codegen test (mac)

`.../BPFTailCallTableCodegenTest.java`:

- Given a fixture class with `@BPFTailCallTable(maxEntries = 4)` and
  three `@BPFTailCallSlot` methods (slots 0, 1, 3), assert the
  generated `BPFImpl.postLoadRegisterTailCallSlots()` contains three
  `register` calls in slot order, and none for slot 2.
- Assert the generated `.c` file contains the `PROG_ARRAY` map
  definition with `max_entries = 4`.

### 9.3 Real-kernel smoke test (thinkstation vng)

`bpf-samples/src/test/java/.../HelloTailCallSampleSmokeTest.java`:

- Load `HelloTailCallSample` (see §10).
- Trigger the entry program (attached via `@Kprobe` or `@Tracepoint`).
- Read a HASH map that each tail-call target increments per-slot.
- Assert every slot's counter is > 0.

## 10. Sample

`bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloTailCallSample.java`:

- Small `@BPF` class.
- `@BPFTailCallTable(maxEntries = 3) tracers`.
- Three `@BPFTailCallSlot` methods (`slot = 0`, `1`, `2`) each
  bumping a `HASH<int, long>` at their own key.
- One `@Tracepoint(category = "syscalls", name = "sys_enter_openat")`
  entry that dispatches based on `pid % 3`.
- `main()` loads, attaches, sleeps 2 seconds, prints the three
  counter values, exits.
- Doubles as the smoke-test target.

## 11. Migration

No existing code uses `@BPFTailCallTable` — these annotations are new.
Existing users of `BPFProgArray` via `@BPFMapDefinition` +
`.register(...)` continue to work unchanged (the plugin does not
require the new annotations).

Docs are a follow-up: one paragraph on the tail-call page pointing
users at the annotation-driven form as the default.

## 12. Risks

- **Section-name convention for tail-call target methods.** A
  `@BPFFunction` needs *some* section string. Today users hand-write
  it. Tail-call targets don't have a natural section; the plugin picks
  one (proposal: `tail_call/<method-name>`). Load-time verification is
  identical regardless of section prefix, so the choice is cosmetic —
  but pick once and document.
- **Program type inheritance.** `bpf_tail_call` requires the callee's
  program type to match the caller's. The plugin has no static way to
  know the caller — the same `@BPFTailCallTable` might be tail-called
  from a kprobe and a perf-event program. Rely on the verifier to
  reject mismatches at load time; document that all callers must be of
  the same program type.
- **Auto-register vs manual `.register()` ordering.** If a user calls
  `.register(0, otherHandle)` in `main()` after `load()`, the auto
  registration ran first. The manual call wins. Documented as a
  post-load override; not enforced.
- **`getProgramByName` lookup cost at load.** Registration walks
  `getProgramByName` once per slot. For O(10) slots this is
  irrelevant. For pathological O(1000) slots we would batch — not
  needed today.
- **Field-name change breaks slot annotations.** If a user renames the
  `tracers` field, every `@BPFTailCallSlot(table = "tracers")` becomes
  a compile error. That's the intended behaviour — refactor tools
  handle the rename.

## 13. Success criteria

- `HelloTailCallSample` loads and dispatches to three tail-call
  targets; the smoke test observes all three counters incrementing.
- All five compile-time diagnostic tests fire the expected errors.
- Codegen tests confirm the generated `BPFImpl.postLoadRegisterTailCallSlots()`
  matches the annotation set.
- No regression in existing `BPFProgArray` users (there are none in
  `bpf-samples/` today; check `bpf/` for internal uses).
- Docs page under `docs/reference/` (or the cookbook) points at the
  new annotations as the preferred style.

## 14. Handoff

Plan writer: implementation plan at
`docs/superpowers/plans/2026-07-02-tail-call-table.md`. Sequencing:

1. Add `@BPFTailCallTable` and `@BPFTailCallSlot` annotations
   (compilation-only artefacts). Commit.
2. Wire the annotation processor: map discovery, method discovery,
   validation, error diagnostics. Write the compile-time-diagnostic
   tests first, then make them fire. Commit.
3. Extend the plugin's `BPFImpl` generation: post-load register hook.
   Write the codegen test first. Commit.
4. Wire `BPFProgram.load()` to call the post-load hook. Commit.
5. Write the sample + smoke test. Commit.

Each task ends with a green build gate on thinkstation
(`ssh thinkstation ... mvn ...`). The first plan task reads
`BPFProgArray.java`, `TypeProcessor.java`, and one of the existing
`@BPFMapDefinition`-using samples so the codegen shape matches
established convention before any code lands.
