# Design: `HASH_OF_MAPS` and `ARRAY_OF_MAPS`

Add Java wrappers for `BPF_MAP_TYPE_HASH_OF_MAPS` (id 13) and
`BPF_MAP_TYPE_ARRAY_OF_MAPS` (id 12) so users can nest a per-key inner
map under an outer map — the canonical shape for per-executable
`.eh_frame` tables, per-cgroup rule sets, per-tenant map partitioning,
and the OTel profiler's inner-unwind-table pattern.

Parent roadmap: `docs/superpowers/specs/2026-07-02-roadmap-t0-plus.md`
§7. Assumes hello-ebpf's existing single-shot `BPFProgram.load()`
lifecycle (no three-phase open/load split).

## 1. Problem

`bpf/src/main/java/me/bechberger/ebpf/bpf/map/MapTypeId.java:10` already
enumerates:

```java
ARRAY_OF_MAPS(12), HASH_OF_MAPS(13),
```

but no wrapper classes back them. Consequences:

- Users who want per-key inner maps have to declare a top-level map
  per-key (unbounded fanout at compile time) or emulate the nesting
  with an outer HASH<key, u32-inner-id> plus a manual lookup — losing
  BPF-side ergonomics.
- The profiler roadmap (T2#38 native unwinder) needs per-executable
  `.eh_frame` lookup tables. Without HASH_OF_MAPS, this requires
  either a fixed-N pool of inner arrays (worst-case memory) or a
  monolithic outer map with tuple keys (bad locality).
- Per-cgroup rule engines (whitelists/blacklists per cgroup id) need
  the same shape.
- Every peer library has these wrappers.

Kernel semantics (verified against `kernel/bpf/hashtab.c` and
`kernel/bpf/arraymap.c` for 6.14):

- Outer map holds inner-map fds as values (value_size = 4 = fd width).
- `bpf_map_update_elem(outer, key, &inner_fd)` registers.
- `bpf_map_lookup_elem(outer, key)` returns a pointer to the inner
  map's kernel object; the BPF-side `bpf_map_lookup_elem` on that
  pointer gives the inner value.
- BPF-side: `bpf_map_lookup_elem(bpf_map_lookup_elem(&outer, &okey),
  &ikey)` — two nested calls, or the shorthand helper macros in
  `bpf_helpers.h`.
- Inner maps must all be created with the *same* template — same
  type / key size / value size / max_entries / flags. Kernel enforces
  at `bpf_map_update_elem` time.
- Removing an outer entry (`.remove(key)` or `bpf_map_delete_elem`)
  drops the outer's reference to the inner. The inner map lives as
  long as anything holds its fd.

## 2. Goals

- `BPFHashOfMaps<K, InnerV>` wrapper: an outer HASH keyed by `K` whose
  values are inner maps of value type `InnerV`.
- `BPFArrayOfMaps<InnerV>` wrapper: an outer ARRAY (u32 keys) whose
  values are inner maps.
- Both wrappers follow the established `@BPFMapClass(cTemplate =
  ..., javaTemplate = ...)` pattern used by every other map wrapper.
- `.put(key, innerMap)` / `.remove(key)` / `.lookup(key)` Java-side.
- BPF-side helper method that performs the nested lookup as a single
  Java call.
- Compile-time discovery of the inner-map template from the generic
  type parameters, so the plugin can emit the right `struct inner_map
  { ... }` template alongside the outer.

## 3. Non-goals

- **Heterogeneous inner maps.** Every inner map must share the same
  template. Users who need heterogeneity nest deeper or pick a
  different structure.
- **Runtime template mutation.** The inner-map template is fixed at
  compile time; users can't switch template mid-run.
- **`HASH_OF_MAPS` variants beyond HASH / LRU_HASH inner maps.** The
  kernel accepts any inner map type. v1 supports inner types that
  hello-ebpf already wraps: `BPFHashMap`, `BPFLRUHashMap`, `BPFArray`,
  `BPFPerCpuArray`, `BPFPerCpuHashMap`, `BPFQueue`, `BPFStack`,
  `BPFRingBuffer`. Ringbuf-inner is a smoke test (uncommon but
  supported).
- **Iteration over inner maps as first-class API.** Users iterate
  outer keys, then hold each inner as a normal `BPFMap` and iterate
  it. No `outerMap.forEachEntry(...)` sugar.
- **Deeper nesting.** `HASH_OF_MAPS_OF_MAPS` isn't a kernel type. Not
  supported.

## 4. Architecture

Three components:

**Map wrapper classes.** `BPFHashOfMaps<K, InnerV>` and
`BPFArrayOfMaps<InnerV>` extend `BPFMap` (not `BPFBaseMap` — the
value-side has no `BPFType`; values are inner-map fds). Each carries a
handle to the inner-map template so `.put(...)` can validate that the
supplied inner map matches.

**Compiler-plugin extension.** `TypeProcessor.java`'s
`@BPFMapDefinition` discovery already infers `maxEntries`, key type,
value type from the generic bounds. For maps-of-maps, the value type
is another `BPFMap` subtype with its own generics; the plugin walks
those and emits the inner-map template.

**BPF-side nested-lookup builtin.** A method on the wrapper marked
`@BuiltinBPFFunction` lowers to the two-step nested lookup so the user
writes one call.

## 5. Java API

### 5.1 `BPFHashOfMaps<K, InnerV>`

```java
package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

/**
 * eBPF hash-of-maps: an outer hash keyed by K, whose values are inner
 * BPF maps. All inner maps share the same template (type, key, value,
 * max_entries).
 *
 * &lt;p&gt;Usage:
 * &lt;pre&gt;{@code
 * @BPFMapDefinition(maxEntries = 1024)
 * BPFHashOfMaps&lt;Integer, BPFArray&lt;Long&gt;&gt; perPidUnwind;
 *
 * // Userspace registers an inner map:
 * BPFArray&lt;Long&gt; inner = ...;   // separately created
 * perPidUnwind.put(pid, inner);
 *
 * // BPF-side single-call nested lookup:
 * Ptr&lt;Long&gt; slot = perPidUnwind.lookupNested(pid, index);
 * if (slot != null) *slot += 1;
 * }&lt;/pre&gt;
 */
@BPFMapClass(
        cTemplate = """
        struct $field##_inner {
            $innerCTemplate
        };
        struct {
            __uint (type, BPF_MAP_TYPE_HASH_OF_MAPS);
            __type (key, $c1);
            __type (value, __u32);
            __uint (max_entries, $maxEntries);
            __array (values, struct $field##_inner);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $innerCtor)
        """)
public class BPFHashOfMaps<K, InnerV extends BPFMap> extends BPFMap {

    private final BPFType<K> keyType;
    private final InnerMapTemplate<InnerV> innerTemplate;

    public BPFHashOfMaps(FileDescriptor fd, BPFType<K> keyType,
                        InnerMapTemplate<InnerV> innerTemplate) {
        super(MapTypeId.HASH_OF_MAPS, fd);
        this.keyType = keyType;
        this.innerTemplate = innerTemplate;
    }

    /** Register an inner map at outerKey. Validates template compatibility. */
    public void put(K outerKey, InnerV innerMap);

    /** Remove the inner-map registration. Does not close the inner map. */
    public void remove(K outerKey);

    /** Return the currently-registered inner-map fd, or -1 if none. */
    public int lookupFd(K outerKey);

    // -- BPF-side single-call nested lookup --------------------------
    /** Nested lookup: outer[outerKey][innerKey]. Returns null if either
     *  lookup misses. Emits two chained bpf_map_lookup_elem calls. */
    @BuiltinBPFFunction(
            "({ void *__inner = bpf_map_lookup_elem(&$this, &$arg1); " +
            "__inner ? bpf_map_lookup_elem(__inner, &$arg2) : NULL; })")
    @NotUsableInJava
    public <IK, IV> Ptr<IV> lookupNested(K outerKey, IK innerKey) {
        throw new MethodIsBPFRelatedFunction();
    }
}
```

`BPFArrayOfMaps<InnerV>` mirrors this with `int` keys and the ARRAY C
template (`__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS)` + no
`__type(key, ...)`).

### 5.2 `InnerMapTemplate`

A record threading the inner-map's construction args from the plugin's
compile-time discovery to the outer's runtime `.put()` validation:

```java
package me.bechberger.ebpf.bpf.map;

/** Compile-time-discovered template of an inner map. The plugin emits
 *  a call to InnerMapTemplate.of(...) in the outer map's javaTemplate. */
public record InnerMapTemplate<M extends BPFMap>(
        Class<M> innerClass,
        MapTypeId innerMapType,
        int innerKeySize,
        int innerValueSize,
        int innerMaxEntries,
        int innerMapFlags) {

    /** Validate a supplied inner map matches this template. */
    public void check(BPFMap candidate) {
        if (candidate.mapType() != innerMapType)
            throw new BPFError("inner map type mismatch: expected " + innerMapType
                    + ", got " + candidate.mapType(), -1);
        // Additional checks via bpf_map_get_info_by_fd.
    }
}
```

### 5.3 Usage

```java
@BPF
public abstract class PerPidUnwinder extends BPFProgram {

    @BPFMapDefinition(maxEntries = 1024)
    public BPFHashOfMaps<Integer, BPFArray<Long>> perPidUnwind;

    @KProbe("do_sys_openat2")
    int onOpen(Ptr<pt_regs> ctx) {
        int pid = (int) BPFJ.bpfGetCurrentPidTgid();
        Ptr<Long> slot = perPidUnwind.lookupNested(pid, 0);
        if (slot != null) *slot = *slot + 1;
        return 0;
    }
}

// User side:
try (PerPidUnwinder prog = BPFProgram.load(PerPidUnwinder.class)) {
    prog.autoAttachPrograms();

    // Create per-pid inner arrays lazily as pids show up:
    int selfPid = ProcessHandle.current().pid();
    BPFArray<Long> selfSlots = createInnerArrayForPid(selfPid);  // separate helper
    prog.perPidUnwind.put(selfPid, selfSlots);
    // ...
}
```

Note: BPFArray's construction uses the inner-map builder. The
outer-map's `.put(pid, inner)` doesn't create the inner — the user
does — because inner-map lifetime is a user decision.

## 6. Compiler-plugin work

### 6.1 Generic type discovery

`TypeProcessor.java` already extracts generic type arguments off
`@BPFMapDefinition` fields (see how `BPFHashMap<K, V>` gets its
`keyType`/`valueType`). Extend the walker to:

1. Recognise `BPFHashOfMaps<K, InnerV>` / `BPFArrayOfMaps<InnerV>`.
2. For `K` on `BPFHashOfMaps`, use the existing key-type mapping.
3. For `InnerV`, resolve its own `@BPFMapClass` metadata (template
   substitutions, MapTypeId, key/value BPFTypes). Emit those as
   `$innerCTemplate`, `$innerCtor`, `$innerKeySize`,
   `$innerValueSize`, `$innerMaxEntries` in the outer's substitution
   context.
4. Emit the outer's C definition — the template substitutions in the
   `@BPFMapClass.cTemplate` above use these directly.
5. Emit the outer's Java constructor call — likewise via the outer's
   `javaTemplate`.

### 6.2 Inner-map template substitution mechanism

Extend the `@BPFMapClass` template language to recognise the
`$innerCTemplate` / `$innerCtor` placeholders. The plugin, when it sees
an outer map wrapper whose type has `<InnerV extends BPFMap>` bounds,
walks `InnerV`'s own `@BPFMapClass` and substitutes.

Reserved placeholder names: `$innerCTemplate`, `$innerCtor`,
`$innerKeySize`, `$innerValueSize`, `$innerMaxEntries`,
`$innerMapType`.

If `InnerV` itself has multiple generic parameters (e.g.
`BPFHashMap<InnerK, InnerV>`), the outer wrapper carries all of them
through — the inner's own template substitutions
(`$c1` / `$c2` / `$b1` / `$b2`) resolve against `InnerV`'s own type
bounds independently.

### 6.3 Nested-generic inner limitation

The plugin does not support `HASH_OF_MAPS<K, HASH_OF_MAPS<K2, V>>` in
v1 — the kernel supports it in principle but the plugin's template
substitution isn't recursive. Error at compile time citing the
non-goal.

## 7. Kernel semantics + validation

### 7.1 Inner-map template match

Kernel enforces that all inner maps share:

- map type
- key_size
- value_size
- max_entries
- map_flags

Wrong template → `bpf_map_update_elem` returns `EINVAL`. hello-ebpf's
`.put(...)` calls `bpf_map_get_info_by_fd` on the supplied inner map
and cross-checks against `InnerMapTemplate` before calling
`bpf_map_update_elem`. On mismatch, throw `BPFError` with a specific
message ("inner map key_size=8 but template expects key_size=4").

### 7.2 Reference counting

Registering an inner map with `.put(...)` increments the kernel's
refcount on that inner map. Closing the outer or `.remove(key)`ing
releases the reference. Closing the inner map before `.remove(key)`
is safe: the outer holds a kernel ref; user-side fd close doesn't
free the inner map object. Java-side `BPFMap.close` gets a
warn-if-still-registered check that walks known outer-map registries
and logs.

### 7.3 BPF-side nested lookup

The verifier requires the intermediate pointer to be null-checked
before use. The `lookupNested` template:

```c
({ void *__inner = bpf_map_lookup_elem(&$this, &$arg1);
   __inner ? bpf_map_lookup_elem(__inner, &$arg2) : NULL; })
```

The ternary keeps the null check in a single expression, which is what
the verifier accepts. Confirmed against the kernel's
`bpf_hashtab_map_lookup_elem` semantics: the returned pointer either
points at valid inner-map memory or is NULL.

## 8. Testing

### 8.1 Plugin-side codegen (mac)

`bpf-compiler-plugin-test/src/test/java/.../HashOfMapsCodegenTest.java`:

- `outerAndInnerEmitted` — for a `BPFHashOfMaps<Integer, BPFArray<Long>>`
  field, assert the generated `.c` contains the inner struct
  declaration and the outer map declaration.
- `innerTemplateReflectedInJavaInit` — assert the generated `BPFImpl`
  constructor builds an `InnerMapTemplate` with the right
  `MapTypeId.ARRAY`, key size 4, value size 8, matching maxEntries.
- `arrayOfMapsSameShape` — same fixture with `BPFArrayOfMaps<...>`.
- `nestedGenericInnerRejected` — a `HashOfMaps<Integer,
  HashOfMaps<...>>` fails compile with the non-goal citation.

### 8.2 Real-kernel unit tests (thinkstation)

`bpf/src/test/java/me/bechberger/ebpf/bpf/HashOfMapsTest.java`:

- `putAndLookupInner` — create outer + inner, `put(1, inner)`, kernel
  lookup returns the same fd.
- `putValidatesTemplate` — mismatched inner (different key size)
  rejected with a specific `BPFError`.
- `removeReleasesRef` — `put`, close the local inner fd, `remove`, then
  `.stat` the kernel to confirm the inner is gone.
- `closeOuterReleasesInnerRefs` — put N inners, close outer, confirm
  each inner fd is now the sole reference.
- `bpfSideLookupNestedNullOnMiss` — attach a probe that does
  `perPidUnwind.lookupNested(BOGUS_PID, 0)` and returns; assert map
  side-effect *not* seen.

### 8.3 Real-kernel smoke sample (thinkstation)

`bpf-samples/src/test/java/.../PerExeUnwindSmokeTest.java` runs
`PerExeUnwindSample` from §9 and asserts each expected per-exe entry
resolves.

## 9. Sample

`bpf-samples/src/main/java/me/bechberger/ebpf/samples/PerExeUnwindSample.java`:

- Small `@BPF` class.
- `@BPFMapDefinition(maxEntries = 128)
  BPFHashOfMaps<Integer, BPFArray<Long>> perPidCounts;`
- A `@KProbe("do_sys_openat2")` that increments the per-pid inner
  array at index `pid_tgid % 8`.
- `main()` picks the current pid, creates an inner `BPFArray<Long>`
  sized 8, puts it, sleeps 2 seconds, prints the array contents.
- Doubles as the smoke-test target.

## 10. Interactions with other roadmap features

- **§4 cookies + multi-attach.** No interaction.
- **§6 `@BPFTailCallTable`.** No interaction. A tail-call table is
  itself a map-of-maps-adjacent shape but keyed by `int` on program
  fds, not on maps.
- **§8 `Features.hasX(...)`.** `Features.hasMapType(HASH_OF_MAPS)` and
  `hasMapType(ARRAY_OF_MAPS)` are always true on 6.14+; no gate.
- **§3 `@StructOps`.** No interaction.
- **§2 `bpf_for` / `bpf_repeat`.** Independent.

## 11. Migration

None. The wrappers are new. No existing code uses HASH_OF_MAPS /
ARRAY_OF_MAPS today because there were no wrappers.

The profiler roadmap (T2#38) will consume this feature; that's a
separate spec.

## 12. Risks

- **Template-string extension.** Adding `$innerCTemplate` /
  `$innerCtor` to the plugin's placeholder set is intrusive. Existing
  wrappers use only `$field`, `$maxEntries`, `$c1`, `$c2`, `$b1`,
  `$b2`. The new placeholders are additive; existing templates are
  unaffected. Document the new set.
- **`##` C-preprocessor token pasting.** The outer template above uses
  `$field##_inner` to name the inner struct. This works if the plugin
  emits the substitution and clang sees the concatenation as ordinary
  identifier text (not preprocessor macros). Verify: the plugin
  substitutes `$field` textually *before* the C compiler sees the
  source, so `##` is not actually the preprocessor operator — it's a
  literal identifier separator that the plugin must strip. Fix: use
  `<field>_inner` as the template and have the plugin substitute
  `<field>` → the actual name. Or use `${field}_inner` if the plugin
  supports the brace form. Confirm with the plugin's actual template
  substitution mechanics in the first plan task.
- **BPFMap lifetime tracking.** The warn-if-still-registered check on
  `.close()` walks known outer-map registries. If the user creates an
  outer, puts an inner, drops the outer without closing, the inner's
  refcount stays elevated until GC finalizes the outer (or forever,
  if there's no `AutoCloseable` discipline). Documented; not enforced
  further.
- **Kernel refcount surprises.** `.put(key, inner)` on a slot that was
  already holding a *different* inner map decrements the old inner's
  ref and increments the new one. Users may not expect the drop of a
  reference by simple reassignment. Documented in `.put(...)` Javadoc.
- **`bpf_map_get_info_by_fd` availability.** Requires libbpf, present
  in every version we support. No probe.

## 13. Success criteria

- `PerExeUnwindSample` loads on thinkstation, populates a per-pid
  inner array, reads back the counts.
- All plugin codegen tests pass.
- All real-kernel unit tests pass.
- Template-mismatch case throws the expected `BPFError`.
- No regression: existing `BPFHashMap` / `BPFArray` wrappers still
  work identically (only the plugin's template-substitution set has
  grown; the existing substitutions are unchanged).

## 14. Handoff

Plan writer: implementation plan at
`docs/superpowers/plans/2026-07-02-maps-of-maps.md`. Sequencing:

1. Inspect the plugin's actual template-substitution mechanism (Task 0
   — no code change) to nail down how `$field` and `##` interact and
   which placeholder syntax works. This drives the exact `cTemplate`
   string.
2. Add `InnerMapTemplate` record + plumbing on `BPFMap` to expose
   `mapType()` and `getInfo()` if not already public.
3. Add `BPFHashOfMaps<K, InnerV>` wrapper (skeleton class, no template
   yet). Wire the plugin's generic walker to recognise inner-map
   bounds. Ship compile-time codegen tests first (`HashOfMapsCodegenTest`),
   then make them pass. Commit.
4. Add `.put`/`.remove`/`.lookupFd` runtime methods with template
   validation. Real-kernel unit tests. Commit.
5. Add `lookupNested` builtin. Verifier smoke test. Commit.
6. Add `BPFArrayOfMaps<InnerV>` — smaller diff, same shape. Commit.
7. Write `PerExeUnwindSample` + smoke test. Commit.

First plan task also inspects `BPFArena`'s `.put(...)` refcount
handling (arenas have similar semantics) and `BPFRingBuffer`'s
close-time cleanup for the warn-if-registered pattern.
