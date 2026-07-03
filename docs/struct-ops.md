# `@StructOps`: implementing kernel struct_ops in Java

**Blog series:** [Part 15 — Custom scheduler with sched_ext struct_ops](https://mostlynerdless.de/blog/2024/10/17/hello-ebpf-writing-a-custom-scheduler-in-pure-java-15/) · [Part 19 — Scheduler cookbook](https://mostlynerdless.de/blog/2025/01/20/helle-ebpf-a-scheduler-cookbook-19/)
**Javadoc:** [`@StructOps`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/bpf/StructOps.html)

A `@StructOps` interface bundles the kernel's C-level callback table for a
`bpf_struct_ops` kind (sched-ext, TCP congestion control, qdisc, HID) into
a Java interface. Extending a class with the interface, overriding the
callbacks you care about, and loading via `BPFProgram.load(YourClass.class)`
compiles a struct_ops BPF program, attaches it, and registers it with the
kernel — all in one step.

## Supported kinds

| Java interface           | Kernel struct           | Kernel since |
|--------------------------|-------------------------|-------------:|
| `SchedExtOps`            | `sched_ext_ops`         |         6.12 |
| `TcpCongestionControl`   | `tcp_congestion_ops`    |          5.6 |
| `QdiscOps`               | `Qdisc_ops`         |         6.10 |
| `HidBpfOps`              | `hid_bpf_ops`           |         6.11 |

hello-ebpf's kernel floor is 6.14, so all four are available without
compile-time gating.

## The annotation

```java
@StructOps(
    value = "tcp_congestion_ops",       // required — the kernel struct name
    sectionPrefix = "struct_ops/",       // optional — override for non-standard prefixes
    instanceName = ""                    // optional — override the emitted map name
)
public interface TcpCongestionControl { … }
```

Values default to sensible sched-ext / TCP defaults; you rarely need to
override.

## Method-to-field mapping

- Java method name → C field name via camelCase → snake_case (`congAvoid` → `cong_avoid`).
- Return type and arg types validated against the BTF layout at compile time.
- Un-overridden default methods are omitted from the emitted struct — the
  kernel accepts NULL for optional slots.
- A `String name()` method emits `.name = "…"` as a literal initializer,
  not a synthesized program.

## `@Sleepable`

Some struct_ops methods are declared sleepable in their BTF metadata
(e.g. sched-ext's `sched_init`). Mark the Java override with
`@Sleepable` and the plugin emits `SEC("struct_ops.s/<field>")` instead
of `SEC("struct_ops/<field>")`.

```java
@BPF public abstract class MyScheduler extends BPFProgram implements SchedExtOps {
    @Override @Sleepable public int schedInit() { return 0; }
}
```

## Property placeholders (sched-ext only)

Sched-ext historically supports `__property_<name>` placeholders for the
`flags`, `timeout_ms`, and `name` fields — resolved at load time from
`@PropertyDefinition` annotations. These are preserved verbatim by the
struct-ops synthesizer; you don't need to declare them anywhere.

## Runtime attach

`BPFProgram.load(YourClass.class)` handles the full lifecycle:

1. Compile and load the BPF object file (existing behaviour).
2. For each `@StructOps` interface implemented by the class, call
   `bpf_map__attach_struct_ops(…)`.
3. Populate `prog.structOpsInfo()` with `(kernelName, mapName, mapFd, bpfLinkId)`
   entries — useful for diagnostics.
4. On `close()`, all attached links are detached automatically.

If the running kernel doesn't advertise the struct_ops kind (via
`Features.hasStructOps(name)`), load throws
`BPFLoadError.UnsupportedKernel(name, since)` before touching the BPF
object.

## Canonical examples

| Kind                    | Sample                                                                       |
|-------------------------|------------------------------------------------------------------------------|
| `SchedExtOps`           | [`MinimalScheduler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java) |
| `TcpCongestionControl`  | [`HelloCubicSample.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java) |
| `QdiscOps`              | [`QdiscOpsSmokeTest.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/test/java/me/bechberger/ebpf/bpf/structops/QdiscOpsSmokeTest.java) |
| `HidBpfOps`             | [`HidBpfOpsSmokeTest.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/test/java/me/bechberger/ebpf/bpf/structops/HidBpfOpsSmokeTest.java) |

## Escape hatches

- Hand-writing a `SEC("struct_ops/…")` method directly on a `@BPF` class
  (via `@BPFFunction(section = "…", headerTemplate = "…")`) still works.
  The plugin only intercepts methods that are `@Override`s of a
  `@StructOps` interface — a manually annotated method sitting alongside
  is left untouched.
- To emit a struct_ops kind not yet covered by a marker interface,
  declare your own interface annotated `@StructOps("your_kind")`. You
  must also add a `your_kind.json` layout under
  `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/` for BTF
  validation — see `struct-ops-layouts/README.md` for the schema.

## TCP Congestion Control — worked example

The snippet below shows a minimal BIC/Cubic-inspired congestion controller.
It overrides `ssthresh` (reduce window on loss), `congAvoid` (additive
increase), and `name` (kernel registration name) — enough to be loaded and
recognised by the kernel.

```java
@BPF(license = "GPL")
public abstract class MyCubic extends BPFProgram implements TcpCongestionControl {

    // camelCase → snake_case: congAvoid → cong_avoid
    @Override
    public void congAvoid(Ptr<tcp_sock> tp, int ack, int acked) {
        // Read current congestion window via CO-RE
        int cwnd = tp.val().snd_cwnd;
        int ssthresh = tp.val().snd_ssthresh;
        if (cwnd < ssthresh) {
            // Slow start: double each RTT
            tp.val().snd_cwnd = cwnd + acked;
        } else {
            // Congestion avoidance: AIMD increase
            tp.val().snd_cwnd = cwnd + 1;
        }
    }

    @Override
    public int ssthresh(Ptr<tcp_sock> tp) {
        // Reduce window by half on loss (cubic-style floor at 2)
        int cwnd = tp.val().snd_cwnd;
        return Math.max(cwnd >> 1, 2);
    }

    // name() emits .name = "my_cc" — not compiled as a BPF program
    @Override
    public String name() { return "my_cc"; }
}
```

**Key points:**

- The arg is named `tp`, not `ctx`. The `BPF_PROG` tracing macro that
  libbpf expands internally reserves the name `ctx`; using it causes a
  compile error. See [Common pitfalls](#common-pitfalls) below.
- `tp.val().snd_cwnd` uses CO-RE field access; the compiler rewrites it to
  a `BPF_CORE_READ` call automatically.
- `name()` returns a string literal. The synthesiser emits `.name = "my_cc"`
  directly — do not annotate `name()` with `@BPFFunction`.
- Sleepable callbacks (none in TCP CC, but common in sched-ext) need
  `@Sleepable`; see the [`@Sleepable` section](#sleepable) above and
  [timers.md](timers.md) for background on sleepable contexts.

## Common pitfalls

- **Args named `ctx` collide with the `BPF_PROG` macro.** libbpf's
  `BPF_PROG` tracing macro injects a local variable named `ctx` for every
  struct_ops program. If your Java method declares a parameter named `ctx`,
  clang sees a redeclaration and the build fails. Rename to `tp`, `tsk`,
  `hctx`, `sk`, or any other non-`ctx` identifier.

- **`Qdisc_ops` requires all five handlers.** The kernel's
  `bpf_qdisc_reg()` rejects registrations that leave any of `enqueue`,
  `dequeue`, `reset`, `destroy`, or `init` as NULL, returning `ENOENT`.
  Override all five even if the body is a no-op.

- **Forgetting `@Sleepable` on a sleepable slot.** If the kernel BTF marks
  a callback as sleepable (e.g. `sched_ext_ops.init`) but the emitted
  section header says `SEC("struct_ops/init")` instead of
  `SEC("struct_ops.s/init")`, the verifier rejects the program at load
  time. Add `@Sleepable` to the Java override; the plugin then emits the
  correct `.s/` suffix. See [sched-ext/index.md](sched-ext/index.md) for
  a sched-ext example.

- **`name()` must not be annotated with `@BPFFunction`.** The method maps
  to a literal `.name = "…"` field initializer in the kernel struct, not
  to a compiled BPF program. Annotating it with `@BPFFunction` confuses
  the synthesiser and produces an invalid object.
