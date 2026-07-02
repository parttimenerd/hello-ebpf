# Design: Generic `@StructOps` runtime

Promote hello-ebpf's bespoke sched-ext machinery to a generic `bpf_struct_ops`
runtime that can implement any kernel struct_ops table. Land sched-ext as the
migration proof point; ship TCP congestion control, `Qdisc_ops`, and
`hid_bpf_ops` as new consumers.

Parent roadmap: `docs/superpowers/specs/2026-07-02-roadmap-t0-plus.md` §3.
Assumes hello-ebpf's existing single-shot `BPFProgram.load()` lifecycle (no
three-phase open/load split).

## 1. Problem

The scheduler pipeline embeds struct_ops emission directly in
`bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java` (~line 168) — the
`SEC("struct_ops/…")` scaffolding is inline strings keyed to sched_ext's
field names. Consequences:

- **A second struct_ops kind requires copying the scaffolding.** TCP
  congestion control (`tcp_congestion_ops`), `Qdisc_ops` (`bpf_qdisc_ops`
  in BTF), and `hid_bpf_ops` all follow the same shape kernel-side; on the
  Java side each would need to reinvent field-name mapping, section
  emission, and attach glue.
- **The kernel has been steadily adding struct_ops kinds** — 6.14+ ships
  four widely-used ones, more in flight (BPF sockmap, next-hop
  drivers). Every one is a candidate feature; the current architecture
  doesn't scale.
- **Sched-ext-shaped abstractions leak.** The `Scheduler` interface today
  bakes in sched-ext semantics that don't apply to other kinds
  (`Ptr<task_struct>` args, dispatch queues, DSQ ids). Users implementing
  TCP CC shouldn't see any of that.
- **Attach and lifecycle live in the wrong place.** `attachScheduler()`
  in `BPFProgram` calls `bpf_map__attach_struct_ops` on a single
  sched-ext map by hand. Generalising means walking the class's
  `@StructOps`-implementing interfaces and attaching each.

Kernel shape (verified against `include/linux/bpf.h`, `kernel/bpf/bpf_struct_ops.c`,
and BTF for 6.14):

- A struct_ops kind is a plain C `struct` of function pointers plus small
  data fields (name strings, flags).
- Registration is `bpf_map__attach_struct_ops(map)`; the map's value type
  matches the kernel struct.
- Each method is a separate BPF program with section
  `SEC("struct_ops/<field_name>")` (or `SEC("struct_ops.s/<field_name>")`
  for sleepable entries).
- The map itself has `SEC(".struct_ops.link")` (or `.struct_ops` for the
  eager variant); libbpf handles registration by scanning these sections.
- Kernel struct fields are snake_case; libbpf uses the field name literally.

## 2. Goals

- `@StructOps("kernel_struct_name")` interface annotation drives all
  struct_ops emission generically.
- Hello-ebpf ships marker interfaces for the four supported kinds:
  `SchedExtOps`, `TcpCongestionControl`, `QdiscOps`, `HidBpfOps`. Users
  implement one (or more) on their `@BPF` class.
- Existing sched-ext consumers keep working: `SchedulerBase` continues to
  compile and behave identically, but is refactored to sit on top of the
  generic layer.
- Compile-time method-to-field matching: unknown methods, wrong return
  types, and wrong arg counts produce clear diagnostics.
- Load-time attach: `BPFProgram.load()` walks the implementing
  `@StructOps` interfaces and calls `bpf_map__attach_struct_ops` for each.
- Kernel-version gating via `Features.hasStructOps(name)` (§8): missing
  support → `BPFLoadError.UnsupportedKernel(...)`.

## 3. Non-goals

- **Runtime struct_ops discovery.** All struct_ops kinds are fixed at
  compile time by the interfaces the user implements. No reflection-driven
  attach.
- **Optional-method probes.** Users signal "this callback isn't present"
  by not overriding the interface's default (empty) method. The plugin
  emits nothing for un-overridden methods; the kernel accepts a NULL
  function pointer for optional callbacks. We do not add a separate
  `@Optional` annotation.
- **Non-BTF struct_ops kinds.** Every 6.14 struct_ops kind is BTF-typed;
  we do not support hand-carried layouts.
- **Multiple instances per interface per class.** One `@BPF` class
  implements each `@StructOps` interface at most once. Multi-instance
  needs multiple classes.
- **Kernels older than 6.14.** No back-compat for pre-6.14 struct_ops
  shapes.
- **Non-generic subclassing of struct_ops interfaces.** The interface
  must be directly `@StructOps`-annotated; the plugin does not follow
  a chain of extending interfaces.

## 4. Architecture

Three components:

**Annotation.** `@StructOps("kernel_struct_name")` on an interface names
the kernel BTF type. The interface's methods become the callback set;
method names lower to snake_case to match BTF field names.

**Compiler-plugin extension.** When a `@BPF` class implements a
`@StructOps`-annotated interface, the plugin:

1. Reads the pre-dumped kernel BTF layout for the named struct
   (see §7 on how the BTF ships).
2. For each interface method the user overrides, maps the method name to
   a BTF field. Validates return type and arg types against BTF.
3. Emits `SEC("<prefix><field>") <ret> <field>(<args>) { … }` for each
   method.
4. Emits `SEC(".struct_ops.link") struct <kernel_struct_name>
   <instance_name> = { .field = field, … };`.

**Runtime attach.** A new
`bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsAttach.java`
utility. `BPFProgram.load()` calls `StructOpsAttach.attachAll(this)` after
`bpf_object__load`; walks the class's implemented `@StructOps` interfaces
and calls `bpf_map__attach_struct_ops` for each corresponding map.

## 5. Java API

### 5.1 `@StructOps`

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Mark an interface as the mirror of a kernel struct_ops table. The
 * interface's methods are the callback slots; their names map to
 * kernel field names via camelCase → snake_case lowering.
 *
 * &lt;p&gt;The annotated interface must have all-abstract or empty-default
 * methods. When a {@code @BPF} class implements this interface, the
 * compiler plugin emits one BPF program per overridden method and the
 * struct_ops map instance.
 */
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
@Documented
public @interface StructOps {
    /** Kernel BTF type name of the struct_ops kind, e.g. "sched_ext_ops",
     *  "tcp_congestion_ops", "bpf_qdisc_ops", "hid_bpf_ops". */
    String value();

    /** BPF section prefix. Default "struct_ops/" for regular callbacks;
     *  "struct_ops.s/" for sleepable variants. Rarely overridden. */
    String sectionPrefix() default "struct_ops/";

    /** Optional: name of the struct_ops instance C variable. Defaults to
     *  the implementing @BPF class name in camelCase. */
    String instanceName() default "";
}
```

### 5.2 Marker interfaces

Hello-ebpf ships one file per supported kind under
`bpf/src/main/java/me/bechberger/ebpf/bpf/structops/`. Each is an
interface annotated `@StructOps("<name>")` with one default method per
BTF field. Defaults are empty bodies (or `return 0` for `int` returns);
users override the ones they care about.

**`SchedExtOps.java`** — matches sched_ext_ops BTF. Preserves the current
sched-ext callback set (`select_cpu`, `enqueue`, `dispatch`, `runnable`,
`running`, `stopping`, `quiescent`, `init_task`, `exit_task`, `init`,
`exit`, etc.). Types stay: `Ptr<task_struct>`, dispatch-queue ids, etc.

**`TcpCongestionControl.java`**:

```java
@StructOps("tcp_congestion_ops")
public interface TcpCongestionControl {
    default void init(Ptr<sock> sk)                 { }
    default void release(Ptr<sock> sk)              { }
    default int ssthresh(Ptr<sock> sk)              { return 0; }
    default void congAvoid(Ptr<sock> sk, int ack, int acked) { }
    default void setState(Ptr<sock> sk, int newState) { }
    default void cwndEvent(Ptr<sock> sk, int event) { }
    default int  undoCwnd(Ptr<sock> sk)             { return 0; }
    default void pktsAcked(Ptr<sock> sk, Ptr<rate_sample> rs) { }
    default int  minTso(Ptr<sock> sk)               { return 0; }
    // ... one default per struct field
    // Special data field:
    default String name()                           { return "hello_cc"; }
}
```

The `name()` method is a special-case: string-typed BTF fields lower to
a `char[]` data initialiser rather than a program. The plugin recognises
this from the BTF field type.

**`QdiscOps.java`** — BTF name `bpf_qdisc_ops`. Callbacks include
`enqueue`, `dequeue`, `init`, `reset`, `destroy`. Types are
`Ptr<sk_buff>`, `Ptr<Qdisc>`.

**`HidBpfOps.java`** — BTF name `hid_bpf_ops`. Callback `hidRawEvent`
plus `hidDeviceEvent`.

### 5.3 Usage

```java
@BPF
public abstract class MyCubic extends BPFProgram
        implements TcpCongestionControl {

    @Override
    public int ssthresh(Ptr<sock> sk) {
        // ...
        return computedSsthresh;
    }

    @Override
    public void congAvoid(Ptr<sock> sk, int ack, int acked) {
        // ...
    }

    @Override
    public String name() { return "mycubic"; }
}

// User side:
try (MyCubic cc = BPFProgram.load(MyCubic.class)) {
    // attachStructOps already ran inside load(); the algo is live.
    Thread.sleep(30_000);
}
```

### 5.4 `StructOpsAttach` / `StructOpsInfo`

```java
package me.bechberger.ebpf.bpf.structops;

public final class StructOpsAttach {
    private StructOpsAttach() {}

    /**
     * Attach every @StructOps-annotated interface this program's class
     * implements. Called by BPFProgram.load() after bpf_object__load.
     * Idempotent — re-invocation is a no-op.
     */
    public static List<StructOpsInfo> attachAll(BPFProgram program);
}

public record StructOpsInfo(
        String kernelName,   // "tcp_congestion_ops"
        String mapName,      // "MyCubic" (the C instance variable name)
        int mapFd,           // fd of the .struct_ops.link map
        long bpfLinkId       // returned from bpf_map__attach_struct_ops
) {}
```

Users don't call `attachAll` — it runs inside `load()`. `StructOpsInfo`
is available via `program.structOpsInfo()` for diagnostics.

## 6. Method-to-field mapping rules

### 6.1 Name mapping

Java camelCase → kernel snake_case by lowercasing each
uppercase letter and prefixing `_`. Examples:

- `congAvoid` → `cong_avoid`
- `selectCpu` → `select_cpu`
- `hidRawEvent` → `hid_raw_event`
- `undoCwnd` → `undo_cwnd`

Rules:

1. Leading char stays as-is (already lowercase in Java conventions).
2. Consecutive capitals in Java are unusual for struct_ops callbacks; if
   they occur (`ACPI` — pathological), lower each and separate with `_`.
   Compile error if the resulting string doesn't match a BTF field.
3. Numeric suffixes are treated as regular chars (`send2` → `send2`).

### 6.2 Type mapping

For each interface method, the plugin fetches the BTF field's function
prototype. Return type and each arg type must match:

- `void` ↔ `void`.
- `int`, `long`, `short`, `byte` ↔ corresponding BTF integer widths.
- `Ptr<X>` ↔ `struct X *` or `X *` where `X` is a BTF struct.
- `String` in a data field ↔ `char[]`.

Mismatches produce a diagnostic:
`method 'congAvoid' return type 'int' does not match BTF field
'cong_avoid' return type 'void'`. Argument arity mismatches say
`expected 3 args, method has 2`.

### 6.3 Unknown method

An interface method whose lowered name is not in the BTF struct is a
compile error at the interface's declaration site
(`method 'fooBar' has no matching field in kernel struct
'tcp_congestion_ops'`). The user needs to remove or rename.

### 6.4 Un-overridden defaults

A `@StructOps` interface method the user does not override → the plugin
emits nothing for it, and the resulting struct instance leaves the
corresponding field as NULL. The kernel accepts NULL for optional
callbacks; for required ones (e.g. `sched_ext_ops.enqueue`) the kernel
rejects at attach time. That rejection surfaces as
`BPFLoadError.StructOpsAttachFailed("sched_ext_ops missing required
callback 'enqueue'")`.

## 7. BTF sourcing

The plugin needs the kernel struct's field layout **at compile time**,
not runtime — the C emitter needs the field-name list plus per-field
prototypes before the class is loaded.

**Sourcing.** Ship a pre-dumped BTF-derived layout under
`bpf-compiler-plugin/src/main/resources/struct-ops-layouts/`:

```
struct-ops-layouts/
    sched_ext_ops.json
    tcp_congestion_ops.json
    bpf_qdisc_ops.json
    hid_bpf_ops.json
```

Each file lists field name, kind (`function` / `data`), return type,
arg-name+type list.

Refresh procedure (documented in `struct-ops-layouts/README.md`):

```bash
# Against a live 6.14+ vmlinux:
bpftool btf dump file /sys/kernel/btf/vmlinux format c \
    | scripts/extract-struct-ops-layouts.py \
    > bpf-compiler-plugin/src/main/resources/struct-ops-layouts/*.json
```

**Why not runtime BTF.** Plugin runs during `mvn compile`; there's no
guarantee `vmlinux` is present, and cross-compilation would fail. The
struct layouts are stable across 6.14–6.19 for these four kinds
(verified against 6.14 and 6.18); when a kind's shape changes, refresh
and republish.

Kernel-version gate: at load time, `Features.hasStructOps(name)` (§8)
verifies the running kernel still has the struct. If the running kernel
has a *narrower* variant, un-overridden fields stay NULL and the kernel
accepts. If the running kernel expects fields the plugin's layout
doesn't know about, they stay NULL; kernel behaviour is per-kind (some
require, some are optional).

## 8. C emission example

For a class `MyCubic implements TcpCongestionControl` that overrides
`ssthresh`, `congAvoid`, and `name`:

```c
/* generated from ssthresh() */
SEC("struct_ops/ssthresh")
__u32 BPF_PROG(ssthresh, struct sock *sk) {
    /* translated body */
}

/* generated from congAvoid() */
SEC("struct_ops/cong_avoid")
void BPF_PROG(cong_avoid, struct sock *sk, __u32 ack, __u32 acked) {
    /* translated body */
}

/* generated struct instance */
SEC(".struct_ops.link")
struct tcp_congestion_ops MyCubic = {
    .ssthresh   = (void *)ssthresh,
    .cong_avoid = (void *)cong_avoid,
    .name       = "mycubic",
};
```

Note the `BPF_PROG(...)` macro wraps the argument list per libbpf
convention; the plugin emits this wrapper because it strips the trampoline
argument the kernel prepends.

## 9. Runtime attach

### 9.1 Discovery

`StructOpsAttach.attachAll(program)` walks `program.getClass()`'s
interfaces (via `Class.getInterfaces()` transitively), filters for
those annotated `@StructOps`, and for each computes the map name from
either the annotation's `instanceName()` or the concrete class's
simple name.

### 9.2 Attach

For each discovered instance, call the existing FFI shape:

```java
MemorySegment map = Lib.bpf_object__find_map_by_name(bpfObject, mapName);
long link = Lib.bpf_map__attach_struct_ops(map);
if (link < 0) throw new BPFLoadError.StructOpsAttachFailed(
    kernelName, "bpf_map__attach_struct_ops returned " + link);
records.add(new StructOpsInfo(kernelName, mapName, mapFd, link));
```

The links live on `BPFProgram`; `close()` unlinks each.

### 9.3 Feature-gate

Before attaching, `Features.hasStructOps(kernelName)` (§8 spec). If
`Unsupported`, throw `BPFLoadError.UnsupportedKernel(kernelName,
"since <version>")` with a per-kind minimum version:

- `sched_ext_ops` — 6.12
- `tcp_congestion_ops` — 5.6 (below our 6.14 floor; effectively no gate)
- `bpf_qdisc_ops` — 6.10
- `hid_bpf_ops` — 6.11

Version strings are baked into the plugin's layout JSONs so message
comes from data, not code.

## 10. Migration: sched-ext

The existing sched-ext machinery is refactored, not deleted, so callers
continue to work.

**Before:**
- `Scheduler.java` is the bespoke sched_ext_ops interface with all sched
  types (`Ptr<task_struct>`, DSQ ids) inline.
- `SchedulerBase` is an abstract class implementing `Scheduler`.
- `BPFProgram.attachScheduler()` calls `bpf_map__attach_struct_ops` on
  the well-known `sched_ops` map.
- `Scheduler.java`'s emission code (~line 168) uses inline
  `SEC("struct_ops/…")` template strings keyed to sched_ext.

**After:**
- `Scheduler` becomes an interface annotated `@StructOps("sched_ext_ops")`.
- `SchedulerBase` implements `Scheduler`; the abstract class still
  provides empty defaults for optional callbacks. Public API unchanged.
- `BPFProgram.attachScheduler()` is deleted; the generic
  `StructOpsAttach.attachAll()` (called from `load()`) does the work.
  Callers no longer call `attachScheduler()`.
- `Scheduler.java`'s inline emission goes away; the plugin's generic
  `@StructOps` codegen produces identical output.

Regression coverage: the existing `bpf-samples` scheduler samples
(`FifoSample`, `RustlandFifoSample`, etc.) build and pass their smoke
tests with no source changes. Documented in §12.

## 11. Compiler plugin work

### 11.1 Class-discovery pass

`TypeProcessor.java` currently detects `@BPF` classes and walks their
methods. Extend to:

1. For each `@BPF` class, walk implemented interfaces via
   `TypeElement.getInterfaces()`.
2. Collect those annotated `@StructOps`. Non-annotated interfaces are
   ignored.
3. For each such interface, load the pre-dumped BTF layout from
   resources.
4. For each interface method the class overrides, resolve the BTF field
   by name (lowering camelCase); validate the return/arg types.
5. Emit the C for each overridden method (via the existing per-method
   emitter, which already knows how to lower Java bodies to BPF C).
6. Emit the `SEC(".struct_ops.link")` struct instance with pointers to
   each emitted method and literals for any data fields.

### 11.2 Section-prefix handling

`@StructOps.sectionPrefix()` defaults to `struct_ops/`. Sleepable
variants use `struct_ops.s/`. The plugin substitutes at emission time;
no other logic differs.

### 11.3 `BPF_PROG(...)` wrapper

Every struct_ops callback is wrapped in libbpf's `BPF_PROG(name, args…)`
macro so the trampoline arg is stripped. The plugin emits this wrapper
around each method's body, extracting arg names from the method's Java
parameter names.

### 11.4 Diagnostics

Compile-time errors, all pointing at the source position:

- `@StructOps("X")` where `X` has no matching JSON layout → error
  ("unknown struct_ops kind 'X' — supported: sched_ext_ops,
  tcp_congestion_ops, bpf_qdisc_ops, hid_bpf_ops. Refresh
  bpf-compiler-plugin/src/main/resources/struct-ops-layouts/ if you're
  adding a new one.")
- Method not found in BTF layout → error at the method site.
- Return-type mismatch → error at the method site with expected/got.
- Arg count / arg type mismatch → same.
- A `@BPF` class implementing two `@StructOps` interfaces where a method
  name collides across both after lowering → error citing both
  interfaces.

### 11.5 Runtime layout write

The plugin emits a companion class next to `BPFImpl` — call it
`StructOpsManifest` — that carries a `List<Descriptor>` with the
kernel name, map name, and expected callback set. `StructOpsAttach.attachAll`
reads this at runtime to know what to attach without reflection over
Java interfaces.

## 12. Testing

### 12.1 Codegen tests (mac; no kernel needed)

`bpf-compiler-plugin-test/src/test/java/.../StructOpsCodegenTest.java`:

- `sched_ext_migrationRoundTrip` — feed the existing FifoSample source;
  assert the generated `.c` for FifoSample is byte-identical to what
  today's bespoke pipeline produces (modulo insignificant whitespace).
- `tcp_cong_minimalEmits` — a stub class implementing
  `TcpCongestionControl` with `ssthresh`+`congAvoid`+`name` overrides.
  Assert the `.c` contains one `SEC("struct_ops/ssthresh")`, one
  `SEC("struct_ops/cong_avoid")`, and the `SEC(".struct_ops.link")`
  struct instance with the `name` literal.
- `qdisc_opsMinimalEmits` — same shape for `QdiscOps` with `enqueue`
  and `dequeue`.
- `hid_bpf_opsMinimalEmits` — same shape for `HidBpfOps`.
- `unknownKind` — `@StructOps("no_such_ops")` interface → compile error.
- `unknownMethod` — override a method whose lowered name isn't in the
  BTF layout → compile error.
- `wrongReturnType` — override `ssthresh` returning `void` → compile
  error.
- `collidingMethodsAcrossInterfaces` — a class implementing two
  `@StructOps` interfaces where an overridden method name collides
  (both have `init(Ptr<sock>)`) → compile error citing both.

### 12.2 Real-kernel tests (thinkstation)

`bpf/src/test/java/me/bechberger/ebpf/bpf/StructOpsAttachTest.java`:

- `attachTcpCong_minimal` — load a class implementing
  `TcpCongestionControl` with a no-op `congAvoid`, `ssthresh` returning
  a constant, `name = "hellocc"`. Assert
  `Files.readString(Path.of("/proc/sys/net/ipv4/tcp_available_congestion_control"))`
  contains `hellocc` after `load()`.
- `attachQdisc_smoke` — same for `QdiscOps` with an `enqueue` that
  returns `NET_XMIT_SUCCESS`. Assert `tc qdisc add dev lo …` succeeds.
- `attachHidBpf_smoke` — `HidBpfOps.hidRawEvent` returning 0. Skip if
  no HID device is exposed to VNG (documented; not a bug).
- `attachSchedExt_migrationSmoke` — load `FifoSample` (unchanged
  source); assert it attaches, then detaches on `close()`.
- `structOpsInfoPopulated` — after load, `program.structOpsInfo()`
  returns the expected `kernelName` + `mapName`.

### 12.3 Migration integration test

`bpf-samples/src/test/java/.../SchedulerRefactorRegressionTest.java`:

- Load `FifoSample` (existing). Run for 3 seconds. Verify no error, no
  regressions vs the pre-refactor baseline (attach count = 1, at least
  one dispatch counter incremented).
- Same for `RustlandFifoSample` if it isn't already covered by another
  smoke test.

### 12.4 Feature-gate test

`bpf/src/test/java/.../StructOpsFeatureGateTest.java`:

- Force `Features.probeStructOps("nonexistent_ops")` cache to
  `Unsupported`, attempt to load a class implementing an interface with
  that annotation. Assert `BPFLoadError.UnsupportedKernel`.

## 13. Sample

`bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java`:

- A minimal TCP congestion-control algorithm derived from cubic that
  logs one `bpf_printk` per `congAvoid` call.
- Registers as `hellocubic`.
- `main()` loads, prints instructions
  (`echo hellocubic > /proc/sys/net/ipv4/tcp_congestion_control` to
  activate), sleeps 30 seconds, prints the trace pipe tail, unloads.
- Doubles as the smoke-test target.

## 14. Migration considerations

Callers of the old `attachScheduler()` need to remove that call. The
scheduler samples are the only in-tree consumers; migrate them in the
same commit that deletes the method. External users get a deprecation
window: keep `attachScheduler()` as a no-op wrapper around `load()` for
one release, mark `@Deprecated(forRemoval = true)`, then remove.

BPF programs that today declared `SEC("struct_ops/…")` sections by hand
in `@BPFFunction` methods (an escape hatch, currently used by nothing in
tree) keep working — the plugin only intercepts methods on
`@StructOps`-annotated interfaces. Users who mix both should not, but
we don't error on the combination.

## 15. Risks

- **BTF-JSON drift.** The dumped struct layouts under `resources/`
  become stale if the kernel renames fields or changes types. Mitigation:
  a CI job re-dumps against a matrix of kernels (6.14, 6.18, latest LTS)
  and asserts equality. Failures gate the release, forcing a manual
  refresh + version-gating decision.
- **Sched-ext migration surface.** Sched-ext callbacks use complex types
  (`Ptr<task_struct>`, DSQ ids, `bpf_iter_scx_dsq`). The generic layer
  must handle all of these without regressing existing schedulers. The
  `sched_ext_migrationRoundTrip` codegen test is the load-bearing gate.
- **`name` field lowering.** `TcpCongestionControl.name()` returns a
  `String` but the C-side is a `char[16]` in the struct. The plugin must
  detect string-typed BTF data fields and emit a `.name = "…"` literal
  rather than a `SEC("struct_ops/name")` program. Handled by the
  BTF-field's `kind = "data"` marker.
- **libbpf-side idempotency.** `bpf_map__attach_struct_ops` on a map
  that's already attached returns an error. `attachAll`'s idempotence is
  Java-side: the second call sees the recorded `StructOpsInfo` for the
  map and no-ops. Documented.
- **Multiple struct_ops kinds in one class.** A class that implements
  both `TcpCongestionControl` and `QdiscOps` is legal (weird, but the
  kernel doesn't forbid it). The plugin emits both instances; the user
  gets both attached. Documented; not tested beyond a fabricated unit
  test.

## 16. Interactions with other roadmap features

- **§4 attach cookies + multi-attach.** No interaction. Struct_ops
  callbacks aren't attached via kprobe/uprobe; cookies don't apply.
- **§6 `@BPFTailCallTable`.** Struct_ops callbacks can tail-call — the
  same `BPFProgArray` shape works — but the two features compose
  transparently.
- **§7 HASH_OF_MAPS.** Independent.
- **§8 `Features.hasX(...)`.** `hasStructOps(name)` gates each attach.
- **§2 `bpf_for` / `bpf_repeat`.** Independent.

## 17. Migration path summary

None for new users — the API is additive. For existing sched-ext users:

1. Recompile against the refactored library. Public API unchanged;
   generated C output identical (verified by codegen round-trip test).
2. Remove any manual `attachScheduler()` calls; migration commit
   updates every in-tree caller.
3. External users see one deprecation cycle before removal.

## 18. Success criteria

- Every existing scheduler sample loads and runs on thinkstation after
  the refactor, with no source changes and matching runtime behaviour.
- `HelloCubicSample` loads, registers `hellocubic` in the kernel's TCP
  CC list, handles a socket, and unloads cleanly.
- `QdiscOps` and `HidBpfOps` smoke tests pass (subject to hardware
  availability for HID).
- All codegen diagnostic tests fire the expected errors at the expected
  source positions.
- `bpf_map__attach_struct_ops` FFI plumbing wired through
  `StructOpsAttach`.
- No regression: `mvn -pl bpf-samples test` on thinkstation shows the
  same pass count as pre-refactor for scheduler smoke tests.

## 19. Handoff

Plan writer: implementation plan at
`docs/superpowers/plans/2026-07-02-struct-ops.md`. Sequencing:

1. Read the current `Scheduler.java` + `SchedulerBase.java` +
   `attachScheduler` path to lock down the exact BTF field-name set for
   sched_ext_ops. Dump the four BTF JSONs and land them under
   `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/`. No
   plugin code change yet. Commit.
2. Add `@StructOps` annotation + the four marker interfaces
   (`SchedExtOps`, `TcpCongestionControl`, `QdiscOps`, `HidBpfOps`).
   Commit.
3. Extend the compiler plugin: class-discovery pass, BTF-JSON reader,
   method-to-field validation, per-kind C emission, struct-instance
   emission. Ship codegen tests first (`sched_ext_migrationRoundTrip`),
   make them pass. Commit.
4. Add `StructOpsAttach` + `StructOpsInfo` + `StructOpsManifest`. Wire
   into `BPFProgram.load()`. Real-kernel `attachTcpCong_minimal` smoke
   test. Commit.
5. Refactor `Scheduler` from concrete class to
   `@StructOps("sched_ext_ops")` interface. Refactor `SchedulerBase`.
   Delete `attachScheduler()` from `BPFProgram`. Update in-tree
   callers. Run scheduler smoke tests on thinkstation. Commit.
6. Add `QdiscOps` + `HidBpfOps` smoke tests. Commit.
7. Add `HelloCubicSample`. Commit.

First plan task also spelunks the existing sched-ext template emission
in `Scheduler.java:168` so the generic emitter reproduces it exactly.
