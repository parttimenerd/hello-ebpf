# Roadmap: T0 + loop lowering + generic `@StructOps`

Combined design covering seven features that, together, unblock the majority of
`docs/superpowers/research/research-feature-ranking.md`'s T1/T2 catalogue:

1. Automatic `bpf_for` / `bpf_repeat` lowering (in progress; referenced).
2. Generic `@StructOps` runtime — sched-ext refactored onto it, plus TCP CC,
   qdisc, HID-BPF as new consumers.
3. Attach-cookie fix + `KPROBE.MULTI` / `UPROBE.MULTI` attach (T0#1).
4. Three-phase lifecycle: `SkelBuilder → OpenBPFProgram → BPFProgram` (T0#2).
5. `PROG_ARRAY` + `@BPFTailCallTable` (T0#3) — extend the existing
   `BPFProgArray` with the annotation surface.
6. `HASH_OF_MAPS` + `ARRAY_OF_MAPS` wrappers (T0#4).
7. Feature-detection API (`Features.hasX(...)`) (T0#5).

**Why one doc.** All seven items land inside the same 6-month window, four of
them share the compiler-plugin surface, and the dependency graph
(§9) has three-phase-lifecycle and feature-detection sitting under every other
item. A single roadmap doc keeps the shared decisions (map-class layout,
error-taxonomy, kernel-version gating) in one place so per-feature
implementation plans can reference them without re-arguing.

**Companion docs.**

- `docs/superpowers/specs/2026-07-02-bpf-for-design.md` — full detail on
  `bpf_for` and the loop-shape classifier. This roadmap adds `bpf_repeat`
  (reverse-count only) and locates the feature in the T2 catalogue.
- `docs/superpowers/research/research-feature-ranking.md` — the authoritative
  ranked catalogue this roadmap draws from. Every § heading below links back to
  a T-tier entry.
- `docs/superpowers/research/research-gap-designs.md` — engineering roadmaps
  for Gaps 1–5, several of which this doc slices differently.

## 0. Table of contents

- §1 Cross-cutting decisions
- §2 Feature: `bpf_for` / `bpf_repeat` (T2#36, in progress)
- §3 Feature: Generic `@StructOps` (T1#12)
- §4 Feature: attach cookies + `KPROBE.MULTI` / `UPROBE.MULTI` (T0#1 + T1#6)
- §5 Feature: three-phase lifecycle (T0#2)
- §6 Feature: `@BPFTailCallTable` (T0#3)
- §7 Feature: `HASH_OF_MAPS` + `ARRAY_OF_MAPS` (T0#4)
- §8 Feature: `Features.hasX(...)` (T0#5)
- §9 Dependency graph and shipping order
- §10 Non-goals
- §11 Open questions
- §12 Success criteria

---

## 1. Cross-cutting decisions

### 1.1 Kernel floor

hello-ebpf targets **6.14+**. All features in this roadmap assume that floor
unless a section says otherwise. Kernel-version fallback code is a non-goal
(§10).

### 1.2 Compiler-plugin cooperation

Four features cooperate with the compiler plugin:

- `bpf_for` / `bpf_repeat` — emits verbatim C from `Translator`.
- `@StructOps` — emits `struct sched_ext_ops X = { ... }` (or the corresponding
  kernel struct) plus per-entry `SEC("struct_ops/name")` sections.
- `@BPFTailCallTable` — emits a `BPF_MAP_TYPE_PROG_ARRAY` definition and
  bookkeeping so `table.tailCall(ctx, slot)` lowers to `bpf_tail_call`.
- `KPROBE.MULTI` / `UPROBE.MULTI` — emits the same C section as ordinary
  kprobes but expects a `bpf_link_create` with `link_create.kprobe_multi`
  populated on the Java side.

Each of these already has some scaffolding
(`bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/`
`TypeProcessor.java` for map-class discovery; `Translator.java` for the C
emission).

### 1.3 Java API style: annotations + interfaces + records

hello-ebpf's established style is:

- **Annotations** name a role (`@BPF`, `@BPFFunction`, `@BPFMapDefinition`).
- **Interfaces** declare hook methods a user implements
  (`SystemCallHooks.enterOpenat`, `Scheduler` from the sched-ext base).
- **Records** carry configuration (map defs, program handles).

Every feature below extends these three shapes rather than inventing a fourth.
For `@StructOps` specifically, the generalisation is: users declare a plain
Java interface that mirrors the kernel struct_ops table, mark it
`@StructOps("kernel_struct_name")`, and implement the methods; the compiler
plugin emits the layout.

### 1.4 Error taxonomy

All new failure paths report through a `sealed interface BPFLoadError`
hierarchy (does not exist yet — this roadmap creates it). The
existing `libbpf`-flavoured errors get wrapped:

```java
public sealed interface BPFLoadError {
    record VerifierRejection(String log, String programName)          implements BPFLoadError {}
    record UnsupportedKernel(String feature, String requiredSince)    implements BPFLoadError {}
    record MissingKfunc(String name, String programName)              implements BPFLoadError {}
    record AttachFailed(String programName, String attachType, int errno) implements BPFLoadError {}
    record MapCreationFailed(String mapName, int errno)               implements BPFLoadError {}
    record ArenaAssociationMissing(String programName)                implements BPFLoadError {}
    record TailCallSlotUnbound(String tableName, int slot)            implements BPFLoadError {}
    record StructOpsMissingHandler(String opsKind, String required)   implements BPFLoadError {}
}
```

`Features.hasX(...)` (§8) uses these types too — a probe returning `false`
knows *why* (e.g. `MissingKfunc(...)` vs `UnsupportedKernel(...)`).

### 1.5 Three-phase lifecycle as the load-time chassis

Every feature that needs to twiddle load-time state (typed rodata, autoload
toggling, `set_max_entries`, `set_attach_target` for fentry/freplace, feature
probing at open time) hangs off §5's three-phase lifecycle. The current
`BPFProgram.load(X.class)` shorthand stays as sugar over
`openBuilder(X.class).open().load()`. §5 is the T0 item that many other
sections quietly depend on; ship it first.

---

## 2. `bpf_for` / `bpf_repeat` lowering (T2#36; in progress)

Full detail: `docs/superpowers/specs/2026-07-02-bpf-for-design.md`. This
section captures deltas and the `bpf_repeat` addition only.

### 2.1 What the referenced spec covers

- Automatic detection of `for (int i = <expr>; i < <expr>; i++)` (canonical
  for-loop) when at least one bound is not a Java compile-time constant.
- Automatic detection of `while (<cond>)` when `<cond>` is not a constant.
- Verbatim emission of `bpf_for(i, start, end)` and `while (can_loop) { if
  (!(cond)) break; ...}`.
- Vendored trim of `bpf_experimental.h` at
  `bpf-compiler-plugin/src/main/resources/bpf_experimental.h`.
- `LoopShapeClassifier` with sealed `LoopShape { CanonicalFor, GenericWhile,
  Other }`.

Task 1 (vendor header + `NOTICE.md`) is already committed as
`f9e2238`. Tasks 2–9 in `docs/superpowers/plans/2026-07-02-bpf-for.md` are
paused.

### 2.2 Delta: add `bpf_repeat` (reverse-count only)

Extend the classifier with a new shape:

```java
sealed interface LoopShape {
    record CanonicalFor(String var, ExpressionTree start, ExpressionTree end,
                        boolean inclusive)                            implements LoopShape {}
    record ReverseCountFor(String var, ExpressionTree n)              implements LoopShape {}  // NEW
    record GenericWhile(ExpressionTree cond)                          implements LoopShape {}
    record Other()                                                    implements LoopShape {}
}
```

`ReverseCountFor` matches exactly:

- Initializer: one `int|long i = <n>` where `<n>` is any expression (may be
  dynamic).
- Condition: `i > 0` (strict), same variable.
- Update: `i--` or `--i` on the same variable.
- Body: does not reassign `i` at the top level.
- `<n>` is integer-typed.

Emission: `bpf_repeat(<n>) { <translated body> }`.

The vendored header needs one more macro:

```c
#define bpf_repeat(N)                                                       \
	for (int __repeat_i = 0; __repeat_i < (N) && can_loop; __repeat_i++)
```

`bpf_repeat` is *not* in the kernel header today (only `bpf_for` /
`may_goto` / `can_loop` are). The macro is a hello-ebpf-side helper that
composes `can_loop` with a counter. Attribution note in `NOTICE.md` gets an
extra sentence: "The `bpf_repeat` macro is a hello-ebpf composition; see
§2.2 of `docs/superpowers/specs/2026-07-02-roadmap-t0-plus.md`."

### 2.3 Java-side API

None — the plugin does the lowering silently. User writes ordinary
`for (int i = n; i > 0; i--) { ... }` and the plugin picks the right lowering.

### 2.4 Risks

- **Two dynamic-loop lowerings can collide** in a nested loop: outer
  `bpf_for` + inner `bpf_repeat` with the same synthetic counter name would
  clash. The macro's `__repeat_i` needs `__COUNTER__`-based uniquification.
  Fix: `#define bpf_repeat(N) for (int __repeat_ ## __COUNTER__ = 0; ...)`,
  and use `__PASTE` since the kernel header already exposes it.

- **Constant-N reverse-count** (e.g. `for (int i = 5; i > 0; i--)`) still
  falls through to `Other` — today's translation produces plain C and the
  verifier folds it. Not a bug.

---

## 3. Generic `@StructOps` runtime (T1#12)

Ships the compiler plugin from "knows how to emit `sched_ext_ops`" to
"knows how to emit any kernel `bpf_struct_ops` table." Existing sched-ext
code migrates onto the generic layer as the smoke test. TCP CC, qdisc, and
HID-BPF are covered as first-class users.

### 3.1 Problem

Today the code that emits `struct sched_ext_ops X = { ... }` lives in bespoke
paths (`Scheduler.java` at line 168 has the `SEC("struct_ops/")` templating
inline as a string). Adding a second struct_ops kind means duplicating that
scaffolding. The kernel supports at least four struct_ops kinds today (6.14):

- `sched_ext_ops` — task scheduler (already implemented).
- `tcp_congestion_ops` — TCP congestion control algorithm (`cong_avoid`,
  `slow_start`, `ssthresh`, etc.).
- `Qdisc_ops` — packet scheduler (6.14+). Kernel struct name in BPF-visible
  BTF is `bpf_qdisc_ops`.
- `hid_bpf_ops` — HID input transform (6.11+).

Each is a `struct` of function pointers plus a small config struct; each has
its own `bpf_struct_ops_reg`/`unreg` kernel path. The user-facing API for
sched-ext gives us the shape:

```java
// TODAY (sched-ext bespoke)
@BPF
public abstract class MyScheduler extends SchedulerBase {
    @Override public int selectCpu(Ptr<task_struct> p, ...) { ... }
    @Override public void enqueue(Ptr<task_struct> p, ...) { ... }
    // ...
}
```

We want:

```java
// TOMORROW (generic)
@StructOps("sched_ext_ops")     public interface SchedExtOps { ... }
@StructOps("tcp_congestion_ops") public interface TcpCong    { ... }
@StructOps("Qdisc_ops")         public interface QdiscOps    { ... }
@StructOps("hid_bpf_ops")       public interface HidOps      { ... }

// Users pick one:
@BPF
public abstract class MyCubic extends BPFProgram implements TcpCong {
    @Override public void congAvoid(Ptr<sock> sk, int ack, int acked) { ... }
    // ...
}
```

### 3.2 Architecture

Three pieces:

**Annotation.** `@StructOps("kernel_struct_name")` marks a Java interface as
the mirror of a kernel struct_ops table. The interface's methods are the
callbacks; their names must match the kernel struct's field names in
snake_case (Java camelCase is auto-lowered). The annotation carries the
kernel BTF type name so the plugin can look up the layout from vmlinux BTF at
build time.

```java
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface StructOps {
    /** Kernel BTF type name, e.g. "sched_ext_ops", "tcp_congestion_ops". */
    String value();
    /** Optional: BPF section prefix (defaults to "struct_ops/"). Sleepable variant is
     *  "struct_ops.s/". Users normally leave this default. */
    String sectionPrefix() default "struct_ops/";
}
```

**Compiler plugin extension.** In `TypeProcessor.java`'s class-discovery
pass, when a `@BPF` class implements a `@StructOps`-annotated interface, the
plugin:

1. Loads the kernel BTF layout for the named struct.
2. For each method the user overrides, matches by name (camelCase→snake_case)
   to a struct field.
3. Emits `SEC("<sectionPrefix><field_name>") <return_type> <field_name>(<args>) { ... }`
   for the method body.
4. Emits `struct <kernel_struct_name> <camelCaseClassName> = { .field1 = field1, ... };`
   and `SEC(".struct_ops.link")` binding.
5. Handles the "s/" sleepable prefix for opt-in sleepable entries.

**Runtime attach.** `BPFProgram` gets a `attachStructOps()` method that walks
the `@StructOps`-implementing interfaces on the class and calls
`bpf_map__attach_struct_ops` for each. The current sched-ext
`attachScheduler()` is deleted in favour of this.

### 3.3 Migration path for sched-ext

- `SchedulerBase` continues to exist as a convenience abstract class that
  implements `@StructOps("sched_ext_ops") SchedExtOps` and provides no-op
  defaults for the optional callbacks. Users who extend `SchedulerBase` get
  the same experience they have today.
- The bespoke `Scheduler.java` macro templating goes away. The `Scheduler`
  interface becomes the `@StructOps`-annotated one.
- `UserspaceSchedulerBase` continues to extend `SchedulerBase`.

### 3.4 Java API surface (concrete)

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsAttach.java
public final class StructOpsAttach {
    /** Attach every @StructOps-annotated interface this class implements. Idempotent. */
    public static void attachAll(BPFProgram program);
}

// bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsInfo.java
public record StructOpsInfo(String kernelName, String mapName, int mapFd, long bpfLinkId) {}
```

For each concrete kind, hello-ebpf ships a marker interface:

```java
package me.bechberger.ebpf.bpf.structops;

@StructOps("tcp_congestion_ops")
public interface TcpCongestionControl {
    /** Called on every ACK; the argument is the socket. */
    void congAvoid(Ptr<sock> sk, int ackSeq, int acked);
    /** Return the current ssthresh. */
    int ssthresh(Ptr<sock> sk);
    // ... one method per struct_ops entry; defaults are empty.
}
```

Same for `QdiscOps` and `HidBpfOps`. Users import and implement.

### 3.5 C emission example

For a user class implementing `TcpCongestionControl`:

```c
SEC("struct_ops/cong_avoid")
void BPF_PROG(cong_avoid, struct sock *sk, __u32 ack, __u32 acked) {
    /* translated body */
}

SEC("struct_ops/ssthresh")
__u32 BPF_PROG(ssthresh, struct sock *sk) {
    /* translated body */
}

SEC(".struct_ops.link")
struct tcp_congestion_ops MyCubic = {
    .cong_avoid = (void *)cong_avoid,
    .ssthresh   = (void *)ssthresh,
    .name       = "mycubic",
};
```

### 3.6 Kernel-version gating

Each kind gates on `Features.hasStructOps("<kernel_name>")` (§8). At load
time, if the probe fails, the user gets `UnsupportedKernel("tcp_congestion_ops",
"6.10+")`.

### 3.7 Risks

- **BTF-driven layout.** vmlinux BTF is needed at *build time* for the
  plugin to know the struct's field names and types. Today the plugin reads
  BTF at runtime. Compile-time BTF access requires either (a) a
  build-time BTF dump under `bpf-compiler-plugin/src/main/resources/` (dumped
  once against 6.14 vmlinux; struct layouts are stable across kernel
  versions for these four types), or (b) a build-time helper Maven mojo
  that dumps BTF from the current runtime kernel. Prefer (a) — smaller
  moving parts.

- **Method-name to field-name mapping.** Kernel struct fields are already
  snake_case (`cong_avoid`, `select_cpu`); Java methods are camelCase
  (`congAvoid`, `selectCpu`). The plugin's convention: strip `snake` from
  the kernel name and match; ambiguous names get a compile error citing
  both candidates.

- **Return-type mismatches.** Kernel struct_ops entries return `int`, `void`,
  or occasionally a pointer. Java-side we emit `int`, `void`, or `Ptr<X>`.
  The plugin needs to check each method's return type against the BTF
  layout at compile time.

---

## 4. Attach cookies + `KPROBE.MULTI` / `UPROBE.MULTI` (T0#1 + T1#6)

### 4.1 Problem

`bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java:711` hardcodes the
attach cookie to `0L`:

```java
opts.set(JAVA_LONG, 16, 0L);                               // bpf_cookie
```

This kills every documented use case for `bpf_get_attach_cookie(ctx)`:
per-attach discrimination (which of ten kprobes fired?), ordering (which
TCX program ran first?), single-callback fan-in. Every peer library (aya,
cilium-ebpf, libbpf-rs, libbpfgo) exposes a first-class attach-cookie API.

`KPROBE.MULTI` / `UPROBE.MULTI` are kernel 6.6+ attach modes that let one
`bpf_link_create` cover N attach points (a pattern or an address list) at
~200× lower attach overhead. They naturally consume attach cookies —
without cookies you can't tell which of the N probes fired.

### 4.2 Java API

Two additions:

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/attach/AttachOptions.java
public record AttachOptions(long cookie) {
    public static final AttachOptions DEFAULT = new AttachOptions(0L);
    public AttachOptions withCookie(long c) { return new AttachOptions(c); }
}

// Existing @KProbe becomes:
@KProbe(function = "tcp_v4_do_rcv")
public void onRcv(Ptr<pt_regs> ctx) { ... }

// New sibling annotations:
@KProbe.Multi(pattern = "tcp_v4_*")
public void onAnyTcpV4(Ptr<pt_regs> ctx) {
    long which = BPFJ.getAttachCookie(ctx);   // NEW builtin
    // ...
}

@KProbe.Multi(functions = { "tcp_v4_rcv", "tcp_v6_rcv" }, cookies = { 4L, 6L })
public void onAnyTcpRcv(Ptr<pt_regs> ctx) {
    long ipVersion = BPFJ.getAttachCookie(ctx);   // 4 or 6
}

@UProbe.Multi(binary = "/usr/lib/x86_64-linux-gnu/libjvm.so",
              symbols = { "SafepointSynchronize::begin", "SafepointSynchronize::end" },
              cookies = { 1L, 2L })
public void onSafepoint(Ptr<pt_regs> ctx) { ... }
```

`BPFJ.getAttachCookie(ctx)` is a new `@BuiltinBPFFunction` lowering to
`bpf_get_attach_cookie(ctx)`.

### 4.3 Runtime plumbing

`BPFProgram.attach<KType>(...)` gains an `AttachOptions` overload. For
`@KProbe.Multi` / `@UProbe.Multi`, the plugin generates an attach descriptor
including the `addr`s / `symbol`s / `cookie`s arrays and hands them to a new
`bpf_link_create_kprobe_multi` / `bpf_link_create_uprobe_multi` Java
wrapper.

### 4.4 Migration for existing code

The one-line fix (change `0L` at line 711 to `opts.cookie()` via the new
overload) unblocks per-attach cookies immediately. Existing samples that use
`@KProbe` without cookies are unchanged — `AttachOptions.DEFAULT` matches
today's behaviour.

### 4.5 Risks

- **Cookie plumbing needs the three-phase lifecycle.** For the pattern-based
  `@KProbe.Multi(pattern = ...)`, the plugin can't know the number or names
  of matched functions until the kernel resolves the glob at attach time.
  That means the cookie array is chosen *at attach time*, not compile time,
  which the current single-phase `load()` can't accommodate cleanly. §5 (the
  three-phase lifecycle) is a prerequisite for pattern-based multi-attach;
  address-list multi-attach works without it.

---

## 5. Three-phase lifecycle (T0#2)

### 5.1 Problem

`BPFProgram.load(X.class)` today does everything at once: reads the ELF,
creates maps, loads programs, done. Nothing can happen between "ELF opened"
and "programs verified":

- Can't set `set_autoload(false)` to disable a program the user doesn't want
  on this run.
- Can't `set_max_entries(map, n)` where `n` is a runtime value.
- Can't rewrite `.rodata` constants (the verifier bakes them in at load
  time; the user's Java code has to `set()` before load, but there's no
  hook).
- Can't `set_attach_target(prog, target_prog_fd, ...)` for fentry/freplace
  extensions.
- Can't `set_ifindex(prog, ifindex)` for XDP HW offload.

libbpf's canonical solution is a three-phase lifecycle:

1. **Skeleton phase** — parse the ELF, discover programs and maps. No fds
   yet.
2. **Open phase** — create map fds; expose `set_max_entries`,
   `set_autoload`, `.rodata` access. Program fds not yet created.
3. **Load phase** — load programs, run the verifier. All fds fixed.

libbpf-rs and aya expose this as three types. hello-ebpf should mirror it.

### 5.2 API sketch

```java
public abstract class BPFProgram implements AutoCloseable {

    /** Existing single-shot shorthand — unchanged. */
    public static <T extends BPFProgram> T load(Class<T> cls);

    /** New: start the three-phase build. */
    public static <T extends BPFProgram> SkelBuilder<T> openBuilder(Class<T> cls);
}

/** Phase 1 → 2 builder. */
public interface SkelBuilder<T extends BPFProgram> {
    /** Fully synchronous — parses the ELF and creates the OpenBPFProgram. */
    OpenBPFProgram<T> open();
}

/** Phase 2 — before verifier. */
public interface OpenBPFProgram<T extends BPFProgram> extends AutoCloseable {
    /** Toggle autoload for a program by name. Default: true. */
    void setAutoload(String programName, boolean autoload);

    /** Adjust a map's max_entries. Must be called before load(). */
    void setMaxEntries(String mapName, int maxEntries);

    /** Typed rodata access. Returns the same POJO the plugin generates
     *  for a class's @Type static-final fields. */
    <R> R rodata();

    /** For fentry/freplace: set the attach target program's fd. */
    void setAttachTarget(String programName, int targetProgFd, String targetFuncName);

    /** For XDP HW offload: set the interface. */
    void setIfindex(String programName, int ifindex);

    /** Advance to phase 3. */
    T load();
}
```

Usage:

```java
try (OpenBPFProgram<MyProg> open = BPFProgram.openBuilder(MyProg.class).open()) {
    open.setMaxEntries("events", 8192);
    open.setAutoload("optionalTracer", false);
    open.rodata().minLatencyUs = 500;
    try (MyProg p = open.load()) {
        p.autoAttachPrograms();
        // ...
    }
}
```

The single-shot `BPFProgram.load(cls)` becomes sugar over
`openBuilder(cls).open().load()`.

### 5.3 Interaction with the sample suite

Every existing sample uses `BPFProgram.load(X.class)` and expects it to
still work. That's the whole reason single-shot stays. Only the few samples
that today do "set globals, then load, then hope" (there are ~3) get to
delete their workarounds.

### 5.4 Interaction with `@SharedFrom`

`@SharedFrom` producers hold an advisory flock during pin-setup. That
serialisation moves from load-time to open-time so producers can share
their initial state before the consumer's `load()` fires.

### 5.5 Risks

- **API churn.** Every existing sample keeps working, but new code should
  prefer the three-phase form. Docs need updating.
- **`try-with-resources` composition.** The `OpenBPFProgram` and the loaded
  `BPFProgram` are both `AutoCloseable`. Closing the outer without loading
  should clean up map fds; closing the inner should not close the outer's
  resources twice. Owner semantics: `open.load()` transfers ownership of
  map fds to the returned `BPFProgram`; closing the `OpenBPFProgram` after
  a successful load is a no-op.

---

## 6. `@BPFTailCallTable` (T0#3)

`BPFProgArray` already exists at
`bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java`. What's
missing is the annotation-processor surface that lets users declare tail-call
tables *by name* and have the compiler-plugin bind program fds to slots
automatically.

### 6.1 Java API

```java
@BPF
public abstract class Profiler extends BPFProgram {

    /** 8-slot dispatch table. */
    @BPFTailCallTable(maxEntries = 8)
    public final BPFProgArray tracers = new BPFProgArray(...);

    @BPFTailCallSlot(table = "tracers", slot = 0)
    @BPFFunction
    public void unwindNative(Ptr<pt_regs> ctx) { ... }

    @BPFTailCallSlot(table = "tracers", slot = 1)
    @BPFFunction
    public void unwindHotspot(Ptr<pt_regs> ctx) { ... }

    @BPFTailCallSlot(table = "tracers", slot = 7)
    @BPFFunction
    public void sendError(Ptr<pt_regs> ctx) { ... }

    @PerfEvent(...)
    public void onSample(Ptr<pt_regs> ctx) {
        tracers.tailCall(ctx, dispatch(ctx));   // → bpf_tail_call
        // never returns
    }
}
```

At load time, the plugin generates the code that populates each slot with
the corresponding program's fd. Users don't call `tracers.register(...)`
manually unless they want a runtime override.

### 6.2 Compiler-plugin work

- Discover `@BPFTailCallTable` fields; emit the map definition C.
- Discover `@BPFTailCallSlot` methods; emit their program bodies with the
  right `SEC(...)` section.
- At load time (via §5's open phase), populate each slot with the resolved
  program fd.

### 6.3 Risks

- **Slot uniqueness.** Two `@BPFTailCallSlot(table="x", slot=3)` on the same
  class is a compile error.
- **Table-size vs. slot bounds.** `slot >= maxEntries` is a compile error.
- **Programs referenced by tail-call must not be attached elsewhere.** The
  kernel enforces this; the plugin adds a compile-time diagnostic when a
  method has both `@BPFTailCallSlot` and `@KProbe` etc.

---

## 7. `HASH_OF_MAPS` + `ARRAY_OF_MAPS` (T0#4)

### 7.1 Problem

`MapTypeId` already enumerates `ARRAY_OF_MAPS(12)` and `HASH_OF_MAPS(13)`,
but no wrapper class exists. Users can't have per-executable `.eh_frame`
lookup tables (OTel profiler's core pattern), per-cgroup rule sets, or
per-tenant map partitioning.

### 7.2 Java API

```java
public final class BPFHashOfMaps<K, InnerV> extends BPFBaseMap<K, Integer> {
    public BPFHashOfMaps(FileDescriptor fd, Class<K> keyType, Class<InnerV> innerType);

    /** Register an inner map at a given key. Ownership stays with the caller. */
    public void put(K key, BPFMap innerMap);

    /** Kernel-side (via @BuiltinBPFFunction): look up the inner map, then
     *  look up in it. Returns null if either lookup misses. */
    @BuiltinBPFFunction("bpf_map_lookup_percpu_elem(&$this, &$arg1, 0)")
    public InnerV lookupNested(K outerKey, Object innerKey);
}
```

`BPFArrayOfMaps` is the same shape with `int` keys and no rehash.

### 7.3 Annotation surface

```java
@BPFMapDefinition(maxEntries = 1024)
public final BPFHashOfMaps<Integer, BPFArray<Long, Long>> perExeUnwindTables =
        new BPFHashOfMaps<>(...);
```

The plugin discovers the generic type parameters and emits:

```c
struct inner_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 65536);
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(key_size, sizeof(__u32));
    __array(values, struct inner_map);
    __uint(max_entries, 1024);
} perExeUnwindTables SEC(".maps");
```

### 7.4 Kernel semantics

- `.put(key, innerMap)` uses `bpf_map_update_elem` with the inner map's fd.
- Removing entries with `.remove(key)` frees the inner map's kernel ref.
- The inner map's `values` must be a struct type known to BTF at compile
  time; the plugin uses the `InnerV`'s generic bounds to derive the map
  definition.

### 7.5 Risks

- **BTF generic-erasure.** Java erases `BPFArray<Long, Long>` at runtime. The
  plugin needs the static bound — it reads the generic type argument off the
  field declaration.
- **Inner-map lifetime.** If the user closes the inner map while still
  registered in the outer, the outer map holds a kernel ref. Closing the
  outer or explicitly `.remove(key)`ing releases it. Java-side `BPFMap.close`
  needs a warn-if-still-registered check.

---

## 8. Feature-detection API (`Features.hasX(...)`) (T0#5)

### 8.1 Problem

Every peer library has a first-class probe API. hello-ebpf today refuses to
load with a raw verifier error, giving users no way to graceful-degrade. The
`Features.hasX(...)` API is a prerequisite for every kernel-gated feature in
this roadmap (`@StructOps` per-kind gating, `KPROBE.MULTI` availability, BPF
streams, etc.).

### 8.2 API

```java
public final class Features {
    private Features() {}

    /** Cached across the JVM lifetime. Probes lazily. */
    public static boolean hasProgramType(BPFProgramType t);
    public static boolean hasMapType(MapTypeId t);
    public static boolean hasHelper(BPFHelper h);
    public static boolean hasKfunc(String name);
    public static boolean hasKfunc(String name, String moduleName);
    public static boolean hasStructOps(String kernelStructName);
    public static boolean hasAttachType(BPFAttachType t);

    /** Kernel version tuple (major, minor, patch). Uses uname()+parse. */
    public static KernelVersion kernelVersion();

    /** Diagnostic dump. */
    public static Map<String, Boolean> probeAll();
}
```

Backing mechanism per probe:

- **`hasProgramType`** — try `bpf(BPF_PROG_LOAD, ...)` with a trivial program
  of that type and check for `EINVAL`. Cached.
- **`hasMapType`** — try `bpf(BPF_MAP_CREATE, ...)` with a 1-slot instance.
  Cached.
- **`hasHelper`** — try loading a program that calls the helper. Cached.
- **`hasKfunc`** — probe via BTF: look up the name in vmlinux BTF (loaded
  once at first `Features` call).
- **`hasStructOps`** — check for the named struct in BTF plus attempt a
  `bpf(BPF_LINK_CREATE)` in dry-run mode.
- **`hasAttachType`** — try `bpf(BPF_LINK_CREATE, ...)` and check for
  `EINVAL`.

### 8.3 Semantics: eager vs lazy

**Lazy.** Probes fire on first use. Reason: some probes require kernel
capabilities the user may not want to grant at process start (e.g. loading
programs as an unprivileged user). Eager probing would surface those
requirements at unexpected moments. Lazy fires them in the same context as
the load that triggered the check.

### 8.4 Integration with `@BPF` classes

At load time (three-phase open), if a program's declared attach type /
map types / kfunc calls include something not probed available, the
`OpenBPFProgram.load()` throws `BPFLoadError.UnsupportedKernel(...)`
BEFORE the syscall — giving a friendly error message instead of the
verifier's cryptic one.

### 8.5 Risks

- **Probe cost.** Each probe is one syscall + one kernel program load; on
  cold JVM, the first `Features.hasProgramType(...)` call can take ~1ms.
  Amortised across a load, this is inconsequential.
- **Kernel refuse-to-probe.** Under LSM lockdown or restricted CAP_BPF, the
  probe itself may fail with an error that isn't "unsupported" — it's
  "unauthorised." `Features` reports these distinctly:
  `ProbeUnavailable(reason)` vs `Unsupported`.

---

## 9. Dependency graph and shipping order

```
                                    ┌────────────────────┐
                                    │ §5 Three-phase     │
                                    │ lifecycle (T0#2)   │
                                    └─────┬──────┬───────┘
                                          │      │
                          ┌───────────────┘      └────────────────┐
                          v                                        v
             ┌────────────────────────┐                ┌────────────────────────┐
             │ §8 Features.hasX(...)  │                │ §7 HASH_OF_MAPS +      │
             │ (T0#5)                 │                │ ARRAY_OF_MAPS (T0#4)   │
             └─────────┬──────────────┘                └──────────┬─────────────┘
                       │                                          │
                       │       ┌──────────────────────────────────┤
                       │       │                                  │
                       v       v                                  v
             ┌────────────────────────┐                ┌────────────────────────┐
             │ §3 @StructOps (T1#12)  │                │ §6 @BPFTailCallTable   │
             │  ├── sched_ext         │                │  (T0#3)                │
             │  ├── tcp_congestion    │                └──────────┬─────────────┘
             │  ├── Qdisc             │                           │
             │  └── hid_bpf           │                           v
             └────────────────────────┘                (OTel profiler roadmap)

             ┌────────────────────────┐                ┌────────────────────────┐
             │ §4 attach cookies +    │                │ §2 bpf_for/bpf_repeat  │
             │ KPROBE.MULTI (T0#1)    │                │ (T2#36, in progress)   │
             └────────────────────────┘                └────────────────────────┘
             (pattern variant depends on §5)           (independent)
```

**Suggested ship order.**

1. **§5 three-phase lifecycle** — everything else benefits.
2. **§8 feature detection** — one syscall wrapper; unblocks graceful gating
   everywhere.
3. **§4 attach-cookie fix + KPROBE.MULTI (address-list)** — one-line fix
   ships immediately; multi-attach follows.
4. **§2 bpf_for / bpf_repeat** — already scoped and in progress; resume the
   plan.
5. **§6 @BPFTailCallTable** — small; unblocks profiler roadmap.
6. **§7 HASH_OF_MAPS / ARRAY_OF_MAPS** — small; profiler needs this too.
7. **§3 generic @StructOps** — biggest; needs BTF wiring. Ships in two
   sub-phases: (a) migrate sched-ext onto the generic layer as a refactor
   with zero user-visible change, (b) add TCP CC / qdisc / HID-BPF as
   consumers.

Total effort: ~14 engineer-weeks aggregated.

---

## 10. Non-goals

- **Kernel version fallback** for pre-6.14 features (see §1.1).
- **DWARF native unwinder / HotSpot unwinder** — profiler-side; T2#38/#39;
  separate spec, dependent on this roadmap's T0 items.
- **Off-CPU profiling** — separate spec (T2#40).
- **BPF static linker** — non-goal per feature ranking §7.
- **AF_XDP userspace ring** — non-goal per feature ranking §7.
- **`do { } while` lowering, enhanced-for lowering, non-`i++` updates** —
  loop-shape non-goals from the referenced bpf_for spec §3.
- **Kernel version gating for `may_goto` itself** — 6.14 covers it (per
  feature ranking §1.1).
- **Generic struct_ops kinds beyond the four in §3.1** — HID-BPF is the
  cut line; anything newer waits for a real user.
- **Runtime cookie rewriting after attach.** Cookies are fixed at
  `bpf_link_create` time; no update API.

---

## 11. Open questions

1. **BTF-at-build-time delivery mechanism.** §3.7 recommends a vendored BTF
   dump under `bpf-compiler-plugin/src/main/resources/`. Two sub-questions:
   which kernel to dump against (6.14 baseline is safe for these four
   struct_ops; is that enough?), and how to refresh (annual bump? on
   demand?). Recommendation: vendor 6.14 vmlinux BTF once; refresh when
   a new struct_ops kind lands upstream.
2. **`@StructOps` method-name matching for edge cases.** Kernel struct
   `sched_ext_ops` has a field `dispatch` and a field `dispatch_max_batch`.
   Java camelCase collapses to `dispatch` and `dispatchMaxBatch` — no
   collision. But `Qdisc_ops.dequeue_peeked` vs `dequeuePeeked` is fine
   too. Ambiguity is theoretical; is a compile-time collision check enough?
3. **Cookie fan-in vs discrimination — which is the primary use case?** The
   API supports both. Docs should default to one; recommendation:
   discrimination (per-attach identity), with a "fan-in" cookbook page.
4. **`OpenBPFProgram` try-with-resources composition.** §5.5 sketches
   ownership transfer at `open.load()`. Is that the least-surprising
   semantics, or should the outer stay responsible until closed? aya and
   libbpf-rs both transfer; hello-ebpf likely follows.
5. **`Features.hasStructOps("...")` implementation.** Probe via BTF
   lookup + dry-run `BPF_LINK_CREATE`? Or is BTF alone enough (i.e. the
   kernel has the struct definition therefore also has the register
   path)? Recommendation: BTF alone; verify against 6.14 to see if the
   two ever diverge.
6. **Whether `@BPFTailCallSlot` methods should be private in Java** since
   they're never called from Java (only tail-call'd). Nothing in Java's
   type system prevents a user from calling them directly, which would
   crash on the `throw` in `tailCall`. Recommendation: no enforcement;
   docs note the pattern.
7. **Sched-ext migration back-compat.** §3.3 says `SchedulerBase` stays.
   Do we deprecate `Scheduler.java`'s macro string entirely, or keep it
   as an escape hatch for users who need un-generic struct_ops emission?
   Recommendation: delete; the generic path covers everything.

---

## 12. Success criteria

Per feature:

- **§2 bpf_for/bpf_repeat.** `LoopShapeClassifier` returns
  `CanonicalFor`/`ReverseCountFor`/`GenericWhile`/`Other` correctly;
  `DynamicLoopSample` loads and computes `sum(0..31) = 496`; nested loops
  each lower independently.
- **§3 @StructOps.** Sched-ext samples continue to pass on thinkstation
  with zero user-visible change. A new `TcpCubicSample` loads a
  hello-ebpf-written TCP congestion controller. A `QdiscHtbSample` loads
  a qdisc. A `HidTapToClickSample` transforms HID input.
- **§4 cookies + multi.** `BpfCookieDiscriminationSample` loads 10 kprobes
  in one syscall and dispatches to per-cookie handlers; the smoke test
  asserts observed cookie == expected. A regression test asserts today's
  samples still pass with `AttachOptions.DEFAULT`.
- **§5 three-phase.** Every existing sample keeps working via the
  single-shot form. Two new samples exercise `setMaxEntries` and
  `setAutoload`. `try-with-resources` composition doesn't leak fds.
- **§6 tail-call table.** A minimal `HelloTailCallSample` chains three
  programs via `BPFProgArray.tailCall`. The compiler plugin emits the
  right registration code.
- **§7 HASH_OF_MAPS.** A `PerExeCounterSample` uses a
  `BPFHashOfMaps<Integer, BPFArray<Long, Long>>` and looks up per-pid
  arrays. Nested lookup returns the expected values.
- **§8 Features.** `Features.hasProgramType(...)` returns `false` on
  kernels that don't support it; caching means the same call is <1µs on
  the second hit. Load-time integration surfaces
  `UnsupportedKernel(...)` before the verifier fires.

Cross-cutting:

- No regression in the existing sample suite on thinkstation.
- Docs page (`docs/reference/roadmap.md` — new) reflects the ship order
  in §9.
- Per-feature implementation plans land under
  `docs/superpowers/plans/2026-07-XX-<feature>.md`.

---

## 13. Handoff

Plan writers: this roadmap is the design document. Each of §2 through §8
becomes its own implementation plan under `docs/superpowers/plans/`. §2's
plan already exists at
`docs/superpowers/plans/2026-07-02-bpf-for.md`; the `bpf_repeat` addition
in §2.2 becomes one extra task inside it. The other six sections get
fresh plans.

Recommend the ship order in §9. Individual plans reference this doc as
context ("see roadmap §5 for the three-phase lifecycle") so per-feature
decisions don't have to re-argue the cross-cutting ones.
