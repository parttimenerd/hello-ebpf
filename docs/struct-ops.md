# `@StructOps`: implementing kernel struct_ops in Java

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
| `SchedExtOps`           | `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java` |
| `TcpCongestionControl`  | `bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java` |
| `QdiscOps`              | `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/QdiscOpsSmokeTest.java`  |
| `HidBpfOps`             | `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/HidBpfOpsSmokeTest.java` |

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
