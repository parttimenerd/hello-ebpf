# Cookbook

Short recipes for the shapes the BPF verifier and the hello-ebpf plugin
care about. Each entry is a problem, the fix, and the smallest bit of code
that gets you past it.

The verifier's error messages point back here — a rejection like
`R1 invalid mem access` prints a hint ending in `See: cookbook §Map lookups`,
and that section is on this page.

## Table of recipes

| Verifier hint | Recipe |
|---------------|--------|
| `§Map lookups`, `§Nullability` | [Nullability](#nullability), [Map lookups](#map-lookups) |
| `§Packet bounds`, `§Bounds` | [Bounds](#bounds) |
| `§Stack` | [Stack](#stack) |
| `§Memory regions` | [Memory regions](#memory-regions) |
| `§Control flow` | [Control flow](#control-flow) |
| `§Loops` | [Loops](#loops) |
| `§Helpers` | [Helpers](#helpers) |
| `§Program size` | [Program size](#program-size) |
| `§Timers` | [Timers](#timers) |
| `§Verifier` | [Reading verifier logs](#reading-verifier-logs) |

Framework features worth their own recipe:

- [Trusted-pointer field access with `directVal`](#trusted-pointer-field-access-with-directval)
- [Arena memory with `@InArena`](#arena-memory-with-inarena)

## Nullability

**Problem.** The verifier rejects a deref of a map lookup: `R_ pointer arithmetic on map_value_or_null`.

**Cause.** `Map.bpf_get()` returns a nullable pointer. Kernel-side, that's `map_value_or_null` — the verifier refuses any use of it until you prove it's non-null.

**Fix.** Bind to a local, null-check, then use the local:

```java
Ptr<Long> p = counters.bpf_get(key);
if (p == null) return 0;
Ptr.of(p.val()).set(p.val() + 1);
```

Do not deref `counters.bpf_get(key)` inline — the plugin cannot fuse the check with the read for you.

## Map lookups

**Problem.** `R1 invalid mem access 'inv'` on the first line that touches the lookup result.

**Cause.** Same as [Nullability](#nullability) — unchecked lookup return.

**Recipe: read-or-init.**

```java
@BPFMapDefinition(maxEntries = 1024)
BPFHashMap<Integer, Long> counts;

@BPFFunction
long bump(int key) {
    Ptr<Long> p = counts.bpf_get(key);
    if (p != null) {
        Ptr.of(p.val()).set(p.val() + 1);
        return p.val();
    }
    long fresh = 1;
    counts.put(key, fresh);
    return fresh;
}
```

The two branches keep the verifier happy — one path proves `p` non-null, the
other never derefs `p`.

## Bounds

**Problem.** `R_ min value is outside of the allowed memory range` or a
`max value` variant.

**Cause.** The verifier could not prove an array/pointer index is in range.
Any value that came from a map, packet, or arithmetic on one is unbounded
until you clamp it.

**Fix — literal power-of-two mask.** Cheapest form the verifier accepts:

```java
static final int RING_SIZE = 512;   // must be a literal power of two

@BPFFunction
int slotFor(int hash) {
    int i = hash & (RING_SIZE - 1);   // now provably 0..RING_SIZE-1
    return ring[i];
}
```

**Fix — explicit compare.** When the size isn't a power of two:

```java
if (i < 0 || i >= RING_SIZE) return 0;
return ring[i];
```

For packet data, always compare against the packet end before the deref:

```java
Ptr<ethhdr> eth = ctx.val().data.<ethhdr>cast();
if (Ptr.<Byte>cast(eth).plus(sizeof(ethhdr))
        .greaterThan(Ptr.<Byte>cast(ctx.val().data_end))) {
    return XDP_PASS;   // not enough bytes
}
```

## Stack

**Problem.** `invalid stack access` / `stack offset out of bounds`.

**Cause.** BPF stack frames are 512 bytes. A `byte[512]` local plus a
struct plus the caller's temps overflows.

**Fix — move the buffer off the stack.** Per-CPU array maps are the cheapest
alternative; one entry per CPU, no locking needed:

```java
@BPFMapDefinition(maxEntries = 1)
BPFPerCpuArray<@Size(4096) String> scratch;

@BPFFunction
int handle() {
    Ptr<@Size(4096) String> buf = scratch.bpf_get(0);
    if (buf == null) return 0;
    // …use buf…
    return 0;
}
```

For genuinely large working sets, see [Arena memory](#arena-memory-with-inarena).

## Memory regions

**Problem.** `arg #1 type=mem expected=fp` or `R1 type=scalar expected=map_ptr`.

**Cause.** BPF distinguishes kernel memory, packet memory, map values, and
stack. A helper that wants one won't take another.

**Fix.** Route the pointer through the right cast — the plugin exposes
`BPFJ.castUser`, `BPFJ.castKernel`, and `BPFJ.castArena` for the three
common cases. If none of them is what the helper wants, the call is
wrong — look at the helper's kfunc signature.

## Control flow

**Problem.** `unreachable insn`.

**Cause.** Code the verifier's CFG walker can't reach. Usually a
fall-through after `return`, or dead code left after a refactor.

**Fix.** Delete the unreachable statements, or restructure so the flow into
them is visible. `return` in one arm of an `if`/`else` followed by more code
in the "impossible" side is the classic offender.

## Loops

**Problem.** `back-edge` / `infinite loop detected` / `too many instructions`.

**Cause.** The verifier could not prove your loop terminates within its
instruction budget (~1 M, ~8 M with bounded-loops).

**Fix — literal-bounded `for`.** Verifier's most compatible shape:

```java
static final int MAX_ITERS = 32;

for (int i = 0; i < MAX_ITERS; i++) {
    if (done) break;
    // work…
}
```

`MAX_ITERS` **must** be a compile-time constant. A `final` field on the
class works; a method argument does not.

**Fix — `bpf_for_each_map_elem` / `bpf_loop`.** For genuinely variable
iteration counts, use the kernel helpers. They run outside the verifier's
per-insn budget.

The `UnboundedLoopPass` in the plugin catches the common shapes at compile
time. Add `@SuppressBPFWarning("bounds.unbounded-loop")` only when you
know the bound and the check is a false positive.

## Helpers

**Problem.** `unknown func bpf_X` or `program of this type cannot use helper`.

**Cause.** BPF gates helpers by program section. `bpf_get_current_task`
works from a kprobe but not from XDP, for example.

**Fix.** Move the call into a section that allows it, or find a
context-equivalent helper. The `HelperContextPass` catches this at compile
time for helpers the plugin knows about; unknown helpers fail at load.

If you added a helper via `@BuiltinBPFFunction`, double-check its
template renders to a real `bpf_*` name — a typo gives `unresolved func`.

## Program size

**Problem.** `BPF program is too large` or the verifier gives up after
walking too many instructions.

**Cause.** BPF caps total verified insns and program size. Deeply
nested branches, many inlined helpers, and big literal-bounded loops all
inflate the count fast.

**Fixes, in order of preference:**

1. **Tail calls.** Split logic across `@BPFFunction`s and dispatch through
   `BPFProgArray`. Each tail-called prog is verified independently.
2. **`bpf_loop`.** Replace long inline loops with `bpf_loop` — one
   iteration is verified once, not `N` times.
3. **Move data into maps.** Precomputed tables often collapse
   deeply-branching code into a single lookup.

## Timers

**Problem.** `bpf_timer is not allowed in map value` or `map value has no timer`.

**Cause.** The kernel requires `bpf_timer` to live *inside* a struct used as
the map value, not to *be* the map value. A bare declaration like
`BPFHashMap<Integer, bpf_timer>` triggers this at load — but the plugin now
also rejects it at compile time.

**Fix.** Wrap it:

```java
@Type
public static class TimerVal {
    public bpf_timer timer;
}

@BPFMapDefinition(maxEntries = 1)
BPFHashMap<Integer, TimerVal> timers;
```

Then initialise the field via `bpf_timer_init` inside a `@BPFFunction`, and
arm it via `bpf_timer_set_callback` / `bpf_timer_start`.

The plugin diagnostic quotes the exact struct name it wants you to use,
so if you missed a step the compiler will tell you which.

## Reading verifier logs

When load fails, hello-ebpf attaches the verifier's own message to the
thrown `BPFLoadException` and runs the log through
`VerifierLogParser` + `VerifierFixSuggester`. You'll see:

```
Verifier rejected the program: R1 invalid mem access 'map_value_or_null'
  at instruction offset 42
Classified as: UNCHECKED_NULL_DEREF

The verifier rejected a pointer comparison or arithmetic.
Why: a value that may be NULL was used in pointer arithmetic, …
Fix: ensure the pointer is non-null before any arithmetic:
  Ptr<V> p = map.bpf_get(k);
  if (p == null) return 0;
See: cookbook §Nullability
```

The `See:` line points here. If a verifier rejection you keep hitting has
no specific hint, the classifier is falling back to `OTHER` — teaching the
parser a new pattern is a one-line change in
`VerifierLogParser.classify`. Contributions welcome.

## Trusted-pointer field access with `directVal`

**Problem.** A kfunc wants a *trusted* pointer on one of its arguments,
but reading a field through `p.val().field` lowers to `BPF_CORE_READ`,
which strips the trusted mark. The verifier then rejects the call.

**Fix.** Use `p.directVal().field` for the field access. It lowers to
`(*p).field` → `p->field`, preserving the trust:

```java
@BPFFunction
void pinToCpu(Ptr<task_struct> p, int cpu) {
    if (!bpf_cpumask_test_cpu(cpu, p.directVal().cpus_ptr)) return;
    // …
}
```

The plugin enforces one rule: `directVal()` must be *immediately* followed
by a field access. Anything else is a compile error — bind to a local via
`val()` instead. To silence the check for a specific call site (e.g. when
passing the whole struct to a kfunc marked `@TrustedPtr`), annotate the
local with `@AllowDirectVal` or the kfunc parameter with `@TrustedPtr`.

## Arena memory with `@InArena`

**Problem.** You have working data too big for the stack, too structured
for a per-CPU array, and you want pointers into it that survive across
`@BPFFunction` calls.

**Fix.** Declare a `BPFArena` map, allocate pages into it, and hold the
result as an `@InArena Ptr<T>`. The plugin emits the `__arena` qualifier
and the verifier-required per-program arena association helper is
auto-injected — no manual bookkeeping.

```java
@BPFMapDefinition(maxEntries = 1 << 20)
BPFArena workspace;

@InArena
Ptr<Long> counters = BPFJ.bpfArenaAllocPages(workspace, Ptr.ofNull(), 16,
        NUMA_NO_NODE, 0);

@BPFFunction
void bump(int slot) {
    Ptr.of(counters.plus(slot).val()).set(counters.plus(slot).val() + 1);
}
```

The `@InArena` field's initializer **must** be a call to
`bpfArenaAllocPages(<arenaField>, …)`; other shapes are a compile error
because the plugin needs to know which arena a pointer belongs to.

At the Java side, `workspace.mmap()` gives you a `MemorySegment` that
overlaps the same pages, so userspace can read and write the same memory
without a syscall per access.
