# Design: `Features.hasX(...)` — runtime BPF capability detection

A cached, lazy probe API so hello-ebpf programs can ask the kernel
"do you support X?" *before* the syscall fires, and so `load()` can
raise a friendly `BPFLoadError.UnsupportedKernel(...)` instead of a
cryptic verifier reject.

Parent roadmap: `docs/superpowers/specs/2026-07-02-roadmap-t0-plus.md`
§8. Prerequisite for graceful kernel-version gating in `@StructOps`
per-kind checks, `KPROBE.MULTI` availability, kfunc calls, and any
future gated feature.

## 1. Problem

Every peer library exposes a first-class capability probe:

- libbpf's `libbpf_probe_bpf_prog_type`, `libbpf_probe_bpf_map_type`,
  `libbpf_probe_bpf_helper`.
- aya's `Features` struct plus `SysFeatures`.
- libbpfgo's `bpf.HasProgType`.
- libbpf-rs's `libbpf_rs::probes`.

hello-ebpf has none. Consequences:

- User code that *could* graceful-degrade (skip a feature, fall back to
  an older attach type) can't tell whether the target kernel supports
  the feature until it hits a raw verifier reject at load time.
- The `@BPF` load path can't decide whether to skip a program on this
  kernel; every program's failure is fatal.
- Multi-kernel testing (`vng` matrix, distro-user regression) requires
  ad-hoc `uname -r` parsing in Java to gate test cases; there is no
  central capability oracle.
- Every gated feature in this roadmap (§3 `@StructOps` per-kind gate,
  §4 `KPROBE.MULTI` gate) needs a probe API. Without it, each has to
  invent its own gating.

## 2. Goals

- Answer, for a running kernel: does it support this program type / map
  type / helper / kfunc / struct_ops kind / attach type?
- Cache probe results across the JVM lifetime — a probe is one to two
  syscalls; each caller shouldn't pay them repeatedly.
- Distinguish `Unsupported` (kernel doesn't have the feature) from
  `ProbeUnavailable` (the process can't probe due to capabilities /
  LSM lockdown / seccomp). Callers care about the difference.
- Wire load-time detection: `OpenBPFProgram.load()` (§5 of the roadmap)
  walks each program's required features via cached probes and throws
  `BPFLoadError.UnsupportedKernel(...)` before the syscall.
- Return a kernel-version tuple for callers who want to gate on version
  rather than capability (e.g. sample-selector code).

## 3. Non-goals

- **Fallback code generation.** If a kfunc is missing, this API tells
  the caller; it does not automatically swap in a replacement.
- **Cross-kernel probing.** Every probe is against `this` kernel.
- **A capability database.** Kernel-version-to-feature tables belong in
  documentation, not in the probe API.
- **Probing under a different user.** The probe runs as the current
  effective UID with the current caps. Callers who want to know what
  root could do run as root.
- **Feature-negotiation over the wire.** No RPC surface for asking a
  remote kernel about its capabilities.
- **Cache invalidation.** The kernel doesn't gain features between
  syscalls; the cache is JVM-lifetime.

## 4. Architecture

Three pieces:

**`Features` static entry points.** Public API. Every probe is a
static method: `Features.hasProgramType(t)`, `hasMapType(t)`,
`hasHelper(h)`, `hasKfunc(name)`, `hasStructOps(name)`,
`hasAttachType(t)`. Each caches its own result.

**Cache.** A `ConcurrentHashMap<ProbeKey, ProbeResult>` keyed by the
enum value or string. Written on first miss, read on every subsequent
call. `ProbeResult` is a sealed record hierarchy:

```java
public sealed interface ProbeResult {
    record Supported()                          implements ProbeResult {}
    record Unsupported(String reason)           implements ProbeResult {}
    record ProbeUnavailable(String reason)      implements ProbeResult {}
}
```

The `hasX` methods return `boolean` (their contract), but a lower-level
`Features.probeX(...)` returns `ProbeResult` for callers that need the
distinction.

**Probe implementations.** Each probe kind has a distinct kernel
mechanism:

- `hasProgramType(t)` — `bpf(BPF_PROG_LOAD, ...)` a 4-instruction
  program of that type. `EINVAL` → unsupported; `EPERM` → unavailable.
- `hasMapType(t)` — `bpf(BPF_MAP_CREATE, ...)` a 1-slot map of that
  type. Same errno rules.
- `hasHelper(h)` — load a program calling that helper. Not all helpers
  are usable from every program type; the probe picks a program type
  known to allow the helper (e.g. `SOCKET_FILTER` for common helpers).
- `hasKfunc(name)` — look the name up in vmlinux BTF. Loaded once at
  first `Features` call; cached.
- `hasStructOps(name)` — BTF lookup for the struct type; a positive
  hit is authoritative because struct_ops registration is BTF-driven.
- `hasAttachType(t)` — try `bpf(BPF_LINK_CREATE, ...)` in dry-run mode
  (invalid target fd, valid attach type). `EBADF` → attach type
  known, target broken (supported); `EINVAL` on the attach type →
  unsupported.

## 5. Java API

### 5.1 Entry points

```java
package me.bechberger.ebpf.bpf.features;

public final class Features {
    private Features() {}

    // -- Boolean-returning convenience ----------------------------
    public static boolean hasProgramType(BPFProgramType t);
    public static boolean hasMapType(MapTypeId t);
    public static boolean hasHelper(BPFHelper h);
    public static boolean hasKfunc(String name);
    public static boolean hasKfunc(String name, String moduleName);
    public static boolean hasStructOps(String kernelStructName);
    public static boolean hasAttachType(BPFAttachType t);

    // -- Detailed probing -----------------------------------------
    public static ProbeResult probeProgramType(BPFProgramType t);
    public static ProbeResult probeMapType(MapTypeId t);
    public static ProbeResult probeHelper(BPFHelper h);
    public static ProbeResult probeKfunc(String name, @Nullable String moduleName);
    public static ProbeResult probeStructOps(String kernelStructName);
    public static ProbeResult probeAttachType(BPFAttachType t);

    // -- Kernel version -------------------------------------------
    public static KernelVersion kernelVersion();

    // -- Diagnostics ----------------------------------------------
    /** All commonly-probed features + their current cached state. */
    public static Map<String, ProbeResult> snapshot();

    // -- Test hooks -----------------------------------------------
    /** Clear the cache. Test-only. */
    static void resetCacheForTest();
}
```

### 5.2 Supporting types

```java
package me.bechberger.ebpf.bpf.features;

public record KernelVersion(int major, int minor, int patch, String raw) {
    public boolean atLeast(int maj, int min) { ... }
}

public sealed interface ProbeResult {
    record Supported()                     implements ProbeResult {}
    record Unsupported(String reason)      implements ProbeResult {}
    record ProbeUnavailable(String reason) implements ProbeResult {}
}
```

New enums:

```java
package me.bechberger.ebpf.bpf.features;

/** Kernel BPF program types. Values match uapi/linux/bpf.h. */
public enum BPFProgramType {
    UNSPEC(0), SOCKET_FILTER(1), KPROBE(2), SCHED_CLS(3), SCHED_ACT(4),
    TRACEPOINT(5), XDP(6), PERF_EVENT(7), CGROUP_SKB(8), CGROUP_SOCK(9),
    LWT_IN(10), LWT_OUT(11), LWT_XMIT(12), SOCK_OPS(13), SK_SKB(14),
    CGROUP_DEVICE(15), SK_MSG(16), RAW_TRACEPOINT(17), CGROUP_SOCK_ADDR(18),
    LWT_SEG6LOCAL(19), LIRC_MODE2(20), SK_REUSEPORT(21), FLOW_DISSECTOR(22),
    CGROUP_SYSCTL(23), RAW_TRACEPOINT_WRITABLE(24), CGROUP_SOCKOPT(25),
    TRACING(26), STRUCT_OPS(27), EXT(28), LSM(29), SK_LOOKUP(30), SYSCALL(31),
    NETFILTER(32);
    // ...
}

/** BPF attach types (subset most commonly probed). */
public enum BPFAttachType {
    CGROUP_INET_INGRESS, CGROUP_INET_EGRESS, CGROUP_INET_SOCK_CREATE,
    CGROUP_SOCK_OPS, /* ... */,
    // 6.14+ additions worth probing:
    XDP_DEVMAP, XDP_CPUMAP, LSM_MAC, TRACE_FENTRY, TRACE_FEXIT,
    TRACE_RAW_TP, TRACE_ITER, TRACE_UPROBE_MULTI, TRACE_KPROBE_MULTI,
    NETFILTER, TCX_INGRESS, TCX_EGRESS, STRUCT_OPS;
    // ...
}

/** BPF helper enum. Small ~60-entry table of the commonly-checked ones.
 *  Values match the kernel's BPF_FUNC_* numbering. */
public enum BPFHelper {
    MAP_LOOKUP_ELEM(1), MAP_UPDATE_ELEM(2), /* ... */,
    RINGBUF_RESERVE(131), RINGBUF_SUBMIT(132), /* ... */;
    // ...
}
```

### 5.3 Usage examples

```java
// Feature-gate a sample:
if (!Features.hasProgramType(BPFProgramType.STRUCT_OPS)) {
    System.err.println("this kernel doesn't support struct_ops");
    System.exit(1);
}

// Choose between two attach modes:
BPFLink link = Features.hasAttachType(BPFAttachType.TRACE_KPROBE_MULTI)
    ? prog.attachKprobeMulti("tcp_v4_*")
    : prog.attachKprobe("tcp_v4_do_rcv");

// Explain a probe failure to the user:
switch (Features.probeStructOps("hid_bpf_ops")) {
    case ProbeResult.Supported() -> loadHidProgram();
    case ProbeResult.Unsupported(var why) ->
        log.warn("HID BPF not supported: {}", why);
    case ProbeResult.ProbeUnavailable(var why) ->
        log.warn("Cannot probe HID BPF (running unprivileged?): {}", why);
}

// Diagnostic dump:
Features.snapshot().forEach((k, v) -> System.out.println(k + " = " + v));
```

## 6. Probe implementations

### 6.1 Program types

Approach: try to load a trivial "return 0" program of that type.

```c
// Two instructions: r0 = 0; exit.
{ BPF_MOV64_IMM(BPF_REG_0, 0), BPF_EXIT_INSN() }
```

Result mapping:

| errno    | ProbeResult                                          |
|----------|------------------------------------------------------|
| 0 (fd)   | `Supported()`                                        |
| `EINVAL` | `Unsupported("unknown prog_type")`                   |
| `E2BIG`  | `Supported()` — program too big is a features hit    |
| `EPERM`  | `ProbeUnavailable("missing CAP_BPF or CAP_SYS_ADMIN")` |
| others   | `Unsupported("errno=" + n)`                          |

Some prog types require a target BTF (fentry, freplace, lsm). Their
probes attach to a well-known target (`vfs_read` for fentry). If the
target has been renamed in this kernel, the probe fails with
`Unsupported("target function 'vfs_read' not found")` — misleading but
tolerable; the diagnostic reason string carries the truth.

### 6.2 Map types

Approach: `bpf(BPF_MAP_CREATE, ...)` a 1-key/1-value map with default
key/value sizes matching the type's constraints. For per-CPU maps,
`value_size=8`. For `STRUCT_OPS` and `ARENA`, the create probe uses
kind-specific defaults documented per-entry in the probe table.

### 6.3 Helpers

Approach: build a two-instruction program that calls the helper with
zero args, in a program type known to allow the helper. Table maps
helper → probe-carrier program type:

- `MAP_LOOKUP_ELEM`, `MAP_UPDATE_ELEM` → `SOCKET_FILTER`.
- `RINGBUF_*` → `SOCKET_FILTER`.
- `TAIL_CALL` → `SOCKET_FILTER`.
- Helper types only usable from tracing (`get_stack`, `perf_event_read`)
  → `KPROBE`.

Verifier reject with "unknown func" → unsupported. Verifier reject with
"helper not allowed" — the probe used the wrong carrier; retry with the
next candidate. If all carriers fail, `Unsupported("no carrier prog type
allows this helper")`.

### 6.4 Kfuncs

Approach: no syscall at all. Load vmlinux BTF once
(`bpf(BPF_BTF_LOAD, ...)` is not needed — read from `/sys/kernel/btf/vmlinux`).
Walk the BTF `FUNC` records; return `Supported` if the name is
present. Module kfuncs use `/sys/kernel/btf/<module>` if `moduleName`
is set.

Caveat: BTF read via `/sys/kernel/btf/vmlinux` requires the file to be
readable. On locked-down systems it may not be. On failure, return
`ProbeUnavailable("cannot read /sys/kernel/btf/vmlinux")`.

### 6.5 Struct_ops

Approach: BTF-only. Look for a `STRUCT` type whose name is the value
passed to `hasStructOps(...)`. If the struct exists in vmlinux BTF,
the kernel has the type; the registration path always accompanies the
type definition (verified against 6.14 for `sched_ext_ops`,
`tcp_congestion_ops`, `bpf_qdisc_ops`, `hid_bpf_ops`).

Open question: is a BTF-only check enough, or do we also need a
dry-run `BPF_LINK_CREATE`? Recommendation from roadmap §11: BTF alone
is sufficient. If a future kernel adds the struct but disables the
register path, we'll add the syscall check then.

### 6.6 Attach types

Approach: `bpf(BPF_LINK_CREATE, ...)` with a nonsense target fd (say,
`-1`) and the attach type under test. Result:

- `EBADF` — attach type is known, target is broken → `Supported()`.
- `EINVAL` — attach type unknown → `Unsupported()`.
- `EPERM` — probe blocked → `ProbeUnavailable()`.

### 6.7 Kernel version

Read `uname().release` and parse a `major.minor.patch` prefix. Ignore
`-generic` / distro suffixes. Cached alongside probes.

## 7. Cache

Storage: `private static final ConcurrentHashMap<ProbeKey, ProbeResult>`
keyed by a discriminated union of probe kinds:

```java
sealed interface ProbeKey {
    record ProgramTypeKey(BPFProgramType t)          implements ProbeKey {}
    record MapTypeKey(MapTypeId t)                    implements ProbeKey {}
    record HelperKey(BPFHelper h)                     implements ProbeKey {}
    record KfuncKey(String name, @Nullable String mod) implements ProbeKey {}
    record StructOpsKey(String name)                  implements ProbeKey {}
    record AttachTypeKey(BPFAttachType t)             implements ProbeKey {}
}
```

Semantics: single-writer per key ensured by `computeIfAbsent`. Test
hook `resetCacheForTest()` is package-private and only called from the
Features test suite.

## 8. Semantics: eager vs lazy

**Lazy.** Probes fire on first request. Reason: some probes require
capabilities the user may not want to grant at process start (e.g.
loading a KPROBE program). Eager probing would surface those
requirements at unexpected moments.

The load-path integration (§9) means that a program that reaches
`load()` triggers exactly the probes that program needs, no more.
Callers can force-probe via `probeAll()` for diagnostics.

## 9. Integration with `@BPF` load path

Inside `BPFProgram.load()`, before invoking the underlying
`bpf_object__load` syscall, for each declared program:

1. Look up the program's declared attach type. `Features.hasAttachType`
   must return true; otherwise throw
   `BPFLoadError.UnsupportedKernel("attach type X", "since Y.Y")`.
2. For each helper the program calls (statically visible from the
   plugin's C emission), `Features.hasHelper` must return true.
3. For each kfunc the program calls, `Features.hasKfunc` must return
   true.
4. For each map the program uses, `Features.hasMapType` must return
   true.

Every miss short-circuits with a friendly error message. The user
never sees the verifier's cryptic reject unless every probe passes and
the program is still invalid.

## 10. Sample

`bpf-samples/src/main/java/me/bechberger/ebpf/samples/FeatureProbeSample.java`:

- Loads `Features.snapshot()`, prints a formatted table.
- Prints the kernel version.
- Attempts to load a `STRUCT_OPS` program only if
  `hasProgramType(STRUCT_OPS)` and `hasStructOps("sched_ext_ops")`.
- If either fails, prints the reason and exits 0. If both pass, loads
  a minimal sched_ext no-op scheduler for 2 seconds and exits.

## 11. Testing

### 11.1 Unit tests (mac — no kernel needed for parsing / cache tests)

`bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesCacheTest.java`:

- `snapshotReturnsUnmodifiableMap`.
- `resetCacheForTestClears`.
- `probeKeyEquality`.
- `kernelVersionParsesUname`.

### 11.2 Real-kernel tests (thinkstation)

`bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesProbeTest.java`:

- Every `BPFProgramType` known-to-6.14 returns `Supported()`.
- Every `MapTypeId` known-to-6.14 returns `Supported()`.
- Every `BPFHelper` known-to-6.14 returns `Supported()`.
- `probeKfunc("bpf_arena_alloc_pages")` returns `Supported()`.
- `probeKfunc("nonexistent_kfunc_xyz")` returns `Unsupported()`.
- `probeStructOps("sched_ext_ops")` returns `Supported()`.
- `probeStructOps("bpf_qdisc_ops")` returns `Supported()`.
- `probeAttachType(TRACE_KPROBE_MULTI)` returns `Supported()`.
- Cache hit: same probe called twice runs only one syscall (assert via
  a side-channel counter in the probe layer).

### 11.3 Integration test with three-phase load

`bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeatureGatedLoadTest.java`:

- A `@BPF` class declaring a kfunc known to *not* exist on this kernel
  (e.g. `bpf_never_existed`). `openBuilder(cls).open().load()` throws
  `BPFLoadError.MissingKfunc("bpf_never_existed", "<program name>")`
  *before* the syscall.

## 12. Compatibility

- No public API removals. `Features` is a new class.
- No behavioural change for programs that reach `load()` today —
  a passing program still passes; a failing program now fails with a
  more specific error type.
- Kernel floor: 6.14+, matching the rest of the roadmap.

## 13. Risks

- **Probe cost.** Cold JVM, first probe is ~1ms per feature. A worst
  case snapshot of all ~40 commonly-probed features is ~40ms. Cached
  after that. Acceptable.
- **False negatives from restricted probing.** LSM lockdown /
  restricted CAP_BPF may cause probes to return `ProbeUnavailable`
  even for supported features. The `hasX` boolean coalesces this to
  `false` — callers who want to distinguish use `probeX`.
- **BTF read failure.** If `/sys/kernel/btf/vmlinux` can't be read,
  `hasKfunc` and `hasStructOps` all return `false` (via
  `ProbeUnavailable`). Documented behaviour; not a bug.
- **Enum drift.** `BPFHelper` grows as the kernel adds helpers. Only
  helpers hello-ebpf actually uses need entries; adding more is
  purely additive.
- **`hasProgramType` for tracing types requires target BTF.** Fentry
  and lsm probes attach to `vfs_read`; if a kernel renames that
  function, the probe misreports. Fix: pick the most stable known
  targets; keep the reason string informative.

## 14. Success criteria

- `Features.hasProgramType(...)`, `hasMapType(...)`, `hasHelper(...)`,
  `hasKfunc(...)`, `hasStructOps(...)`, `hasAttachType(...)` all return
  `true` for every 6.14+-known feature on thinkstation.
- `Features.snapshot()` completes in under 100ms on a cold JVM.
- `Features.probeX(...)` distinguishes `Unsupported` from
  `ProbeUnavailable` under a `capsh --drop=cap_bpf` shell test.
- `BPFProgram.load()` throws `BPFLoadError.UnsupportedKernel` (not a raw
  verifier reject) for a program that requires a missing feature.
- `FeatureProbeSample` runs to completion, printing a formatted table
  of feature states.

## 15. Handoff

Plan writer: implementation plan at
`docs/superpowers/plans/2026-07-02-feature-detection.md`. Ship this
feature *second* in the roadmap order, after §5 (three-phase
lifecycle), so §9's load-time integration lands with real teeth. The
first plan task inventories which libbpf FFI wrappers already exist
in `bpf/src/main/java/me/bechberger/ebpf/bpf/raw/Lib.java` for
`bpf_object__*` and `bpf_prog__*` and confirms which are missing.
