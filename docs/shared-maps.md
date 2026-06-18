# Shared maps across BPF programs (`@SharedFrom`)

A single BPF program can only see maps declared in its own ELF object. When
two cooperating programs need to share state in the kernel — e.g. one program
writes, the other reads — they must reuse the **same** kernel-side map. The
`@SharedFrom` annotation is the idiomatic way to express that in Java.

Mechanism: at load time the producer pins each shared map under
`/sys/fs/bpf/<producer-fqn>/<mapName>`. The consumer's generated
`preLoad()` registers the same pin path before `bpf_object__load`, so libbpf
reuses the producer's kernel map instead of creating a new one.

---

## Why split a program at all?

Some BPF program types cannot legally share kfuncs in one ELF. The motivating
case is the `LockHolderBoost` sample: a uprobe handler cannot call
`bpf_task_from_pid` on every kernel, and the verifier rejects mixed
`uprobe + struct_ops` programs. Splitting it into a uprobe **producer** and a
sched_ext **consumer** sidesteps both restrictions while keeping the data
flow direct via a shared map.

---

## Producer — owns the maps

The producer is a normal `@BPF` class. No annotation is required on the
shared field — sharing is declared by consumers.

```java
@BPF(license = "GPL")
public abstract class LockHolderBoostUprobes extends BPFProgram {

    @Type
    public static class BoostState {
        @Unsigned int  waiterCount;
        @Unsigned long lastBoostNs;
        @Unsigned long totalBoostedNs;
        @Unsigned long onCpuStartNs;
    }

    /** Holder tid → boost state. Consumed by the scheduler. */
    @BPFMapDefinition(maxEntries = MAX_HOLDERS)
    BPFHashMap<@Unsigned Long, BoostState> boostState;

    @BPFFunction(section = "uprobe/ObjectMonitor_enter", autoAttach = false)
    public void onMonitorEnter(Ptr<pt_regs> ctx) { /* … writes boostState */ }
}
```

---

## Consumer — `@SharedFrom`

The consumer annotates each imported map with `@SharedFrom(Producer.class)`.
The processor generates a constructor parameter for each distinct producer.

```java
@BPF(license = "GPL")
public abstract class LockHolderBoostScheduler extends SchedulerBase implements Scheduler {

    @SharedFrom(LockHolderBoostUprobes.class)
    @BPFMapDefinition(maxEntries = LockHolderBoostUprobes.MAX_HOLDERS)
    BPFHashMap<@Unsigned Long, LockHolderBoostUprobes.BoostState> boostState;

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        @Unsigned long tid = (long) p.val().pid;
        Ptr<LockHolderBoostUprobes.BoostState> bs = boostState.bpf_get(tid);
        // … route to boosted vs normal DSQ based on bs
    }
}
```

The field name (`boostState`) defaults to the same name on the producer.
Override with `@SharedFrom(value = …, mapName = "otherName")`.

Idiomatic detail: the consumer references the producer's `@Type` directly
(`LockHolderBoostUprobes.BoostState`). This avoids redefining the struct in
the consumer ELF and guarantees byte-identical layout.

---

## Loading

```java
try (var uprobes = BPFProgram.load(LockHolderBoostUprobes.class);
     var sched   = BPFProgram.load(LockHolderBoostScheduler.class, uprobes)) {

    uprobes.attachUprobe(uprobes.getProgramByName("onMonitorEnter"),
                         /*ret=*/false, pid, libjvm, enterSym);
    sched.attachScheduler();
    // … run loop
}
```

Order matters: producers must be loaded before consumers. Try-with-resources
nesting closes them LIFO (consumer first), which is the correct order — the
framework throws `IllegalStateException` if a producer is closed while a
consumer is still alive.

`BPFProgram.load(Class, BPFProgram...)` reflects the impl-class constructors
and selects the one whose parameter list matches the supplied producers.
`BPFProgram.load(Class)` keeps its no-arg fast path for programs without
`@SharedFrom`.

---

## Compile-time type checking

The annotation processor verifies, before generating the impl class:

| Check | Error message gist |
|-------|--------------------|
| Producer has a `@BPFMapDefinition` field with the named map | `producer class X has no @BPFMapDefinition field 'foo'. Producer fields: [a, b, c]` |
| Map type matches (e.g. `BPFHashMap` ↔ `BPFHashMap`) | `field foo is BPFHashMap but producer's 'foo' is BPFLRUHashMap` |
| Key/value types match — same `@Type`, primitive equivalence, or structural equality of two `@Type` classes | `type mismatch on field 'boostState'. Field 'waiterCount' is u32 here but u64 in producer's BoostState. Use BPFHashMap<Long, X.BoostState> to share the definition.` |
| `maxEntries` matches | `maxEntries mismatch: consumer declares N, producer declares M` |

If a consumer redefines its own copy of a struct with byte-identical layout,
the structural check passes and libbpf's pin-reuse succeeds. The recommended
path remains importing the producer's `@Type` directly.

---

## Pin lifecycle

**Fresh on each run.** When a producer loads, its generated constructor
calls `BPFProgram.unpinAllForClass(getClass())` *before*
`bpf_object__open_file`, wiping any leftover pin files from earlier runs.
This avoids the libbpf pin-by-name footgun where a stale pin from a crashed
process is silently reused with whatever schema it had.

**Consumers never delete pins.** Closing a consumer leaves the producer's
pin file in place; only the producer's directory is cleaned up by its own
`unpinAllForClass` on the next load (and by `close()`).

**Inspecting pins.** `bpftool map show pinned /sys/fs/bpf/<fqn>/<mapName>`
or, programmatically:

```java
prog.getPinPath("boostState");        // /sys/fs/bpf/<fqn>/boostState
prog.getPinnedMapNames();             // {"boostState"}
BPFProgram.unpinAllForClass(Foo.class); // wipe a producer's pin dir
```

---

## What `@SharedFrom` does **not** do

- **Global variables.** `GlobalVariable<T>` lives in `.bss`/`.data` and is
  not currently shareable across ELFs. Expose a delegate getter instead.
- **Schema migration.** If you change a producer's `@Type` and forget to
  recompile the consumer, libbpf rejects the load with a size mismatch —
  this is a defense-in-depth backstop, not a substitute for rebuilding.

---

## Worked example — `LockHolderBoost`

The split sample lives at:

- `bpf-samples/.../sched/LockHolderBoostUprobes.java` — uprobes on
  HotSpot's `ObjectMonitor::enter` / `ObjectMonitor::exit`. Owns the
  wait-graph maps and the shared `boostState`.
- `bpf-samples/.../sched/LockHolderBoostScheduler.java` — sched_ext
  scheduler. Imports `boostState` via `@SharedFrom` and routes boosted
  holders onto a priority DSQ.

Run:

```bash
sudo java -cp bpf-samples.jar \
    me.bechberger.ebpf.samples.sched.LockHolderBoostScheduler \
    --pid <jvm-pid>
```

Both programs load, the uprobes attach to `libjvm.so`, and the scheduler
attaches to sched_ext. The scheduler's `enqueue` reads `boostState`
written by the uprobe handlers; their kernel-side maps are the same
object behind a single pin file.
