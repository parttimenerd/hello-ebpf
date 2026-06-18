# Changelog

## 0.1.5 (in development)

### New features

#### `@SharedFrom` — sharing maps across cooperating BPF programs
A new annotation lets one BPF program import a kernel-side map that another
program owns, wired up via libbpf pin reuse. Eliminates the need for
hand-managed pin path strings.

- Producer/consumer split: the consumer annotates a `@BPFMapDefinition` field
  with `@SharedFrom(Producer.class)` and the framework wires both ELFs to the
  same kernel map at load time.
- Compile-time structural type checking: producer field existence,
  map-type equality, key/value-type equivalence (including walking `@Type`
  members), and `maxEntries` parity. Mismatches produce diagnostics naming
  the offending field and recommending the producer's `@Type` import path.
- Pin lifecycle: fresh-on-each-run by default — producers wipe their pin
  directory before opening, avoiding stale-pin reuse from crashed processes.
- Dependent tracking: closing a producer while a consumer is still alive
  throws `IllegalStateException` naming the live consumer.
- New API: `BPFProgram.load(Class, BPFProgram...)`, `BPFProgram.getPinPath`,
  `BPFProgram.getPinnedMapNames`, `BPFProgram.unpinAllForClass`,
  `BPFProgram.unpin`. The two-phase load (`openProgram` + `finalizeLoad`)
  exposes a `preLoad()` hook for setting pin paths before
  `bpf_object__load`.
- `BPFProgramGroup` helper for closing cooperating programs in
  reverse-dependency order.
- See [Shared maps](shared-maps.md) for the full guide.

#### `LockHolderBoostScheduler` sample
A sched_ext scheduler that boosts JVM threads holding contended `synchronized`
monitors, demonstrating cross-program map sharing end-to-end.

- Split into a uprobe **producer** (`LockHolderBoostUprobes`, watches
  `ObjectMonitor::enter_internal` / `::exit` in libjvm.so) and a sched_ext
  **consumer** (`LockHolderBoostScheduler`, routes boosted holders onto a
  priority DSQ). The two halves share a `BPFHashMap<Long, BoostState>` via
  `@SharedFrom`.
- Required because the BPF verifier rejects mixed uprobe + struct_ops
  programs that share kfuncs.
- Targets `enter_internal`, not `enter()`: in JDK 21+ HotSpot the public
  `enter()` symbol is dead code on contended workloads — threads reach the
  slow path via `try_enter → enter_with_contention_mark → enter_internal`.
- CLI via femtocli: `--pid` (required), `--libjvm`, `--enter-symbol`,
  `--exit-symbol`, `--stats-interval`, `--top-n`.

## 0.1.4

### New features

#### CPU profiler (`CPUProfiler`)
A full-featured CPU profiler that samples call stacks across all CPUs using
`SEC("perf_event")` BPF programs and renders results as an interactive HTML
flamegraph powered by [d3-flame-graph](https://github.com/spiermar/d3-flame-graph).

- Attaches to the Linux CPU-clock software event on every online CPU via `perf_event_open(2)`.
- Captures both kernel and user-space call stacks with `bpf_get_stackid`.
- Symbolizes kernel frames via `/proc/kallsyms` and user-space frames via ELF `.dynsym`/`.symtab`
  (parsed with [jelf](https://github.com/fornwall/jelf)).
- Outputs a self-contained HTML file that can be opened directly in any browser.
- Includes a per-method frequency table (total samples + on-top samples).
- CLI via femtocli: `--duration`, `--output`, `--period`, `--pid`, `--no-table`.

#### JVM GC pause tracer (`JvmGcPauseTracer`)
Traces stop-the-world GC pauses in a running JVM by attaching uprobes to
`VM_GC_Operation::notify_gc_begin` and `VM_GC_Operation::notify_gc_end`
inside `libjvm.so`.

- Automatically detects `libjvm.so` path from `/proc/pid/maps`.
- Reports pause type (young/full), PID, TID, and duration in milliseconds.
- Optionally prints a bucketed histogram on exit (`--histogram`).
- CLI via femtocli: `--pid` (required), `--libjvm`, `--histogram`.

#### `PerfEvent` abstraction
`@BPFAbstraction` typed wrapper around `struct bpf_perf_event_data *` context
for `SEC("perf_event")` BPF programs (`bpf/src/main/java/.../bpf/perf/PerfEvent.java`).

- `PerfEvent.of(ctx)` — wraps the raw context pointer.
- `getStackId(map, flags)` — calls `bpf_get_stackid` with architecture-portable flag constants.
- Flag constants: `STACK_USER` (`BPF_F_USER_STACK`), `STACK_REUSE` (`BPF_F_REUSE_STACKID`).

#### `ProbeContext` abstraction
`@BPFAbstraction` typed wrapper around `struct pt_regs *` context for
`SEC("kprobe/...")`, `SEC("kretprobe/...")`, `SEC("fentry/...")`, and `SEC("fexit/...")`
BPF programs (`bpf/src/main/java/.../bpf/probe/ProbeContext.java`).

- Architecture-portable argument accessors: `arg0()` through `arg5()` expand to
  `PT_REGS_PARM1`–`PT_REGS_PARM6`.
- Return-value accessor `retval()` (for kretprobe/fexit).
- Instruction pointer `ip()`, stack pointer `sp()`, raw context `regs()`.
- Safe kernel-memory helpers: `probeRead`, `probeReadStr`, `probeReadUser`, `probeReadUserStr`.

#### `StackSymbolizer` helper
Standalone helper class that translates raw instruction pointers from BPF stack-trace
maps to human-readable symbol strings (`bpf-samples/.../StackSymbolizer.java`).

- Kernel symbols via `/proc/kallsyms` (text and weak symbols only; lazy-loaded and sorted).
- User-space symbols via ELF `.dynsym`/`.symtab` + `/proc/pid/maps` for address layout.
- ELF parsing uses [jelf](https://github.com/fornwall/jelf); results are cached per library path.
- Both kernel and user-space lookups use binary search for O(log n) resolution.

#### `BPFProgram.attachPerfEvent`
New API method to attach a BPF program to a perf event file descriptor:

```java
BPFLink attachPerfEvent(ProgramHandle prog, int pfd)
BPFLink attachPerfEvent(String programName, int pfd)
```

#### `BPFProgram.attachUprobe` / `attachUretprobe`
New API methods for dynamically attaching user-space probes at runtime (no ELF
symbol offset lookup required — libbpf resolves the symbol name):

```java
BPFLink attachUprobe(ProgramHandle prog, boolean retprobe, int pid, String binaryPath, String funcName)
BPFLink attachUprobe(ProgramHandle prog, String binaryPath, String funcName)   // all pids, entry
BPFLink attachUretprobe(ProgramHandle prog, String binaryPath, String funcName) // all pids, return
```

#### `@JavaOnly` annotation
New `@Retention(SOURCE)` annotation for `static final` fields in `@BPF` classes.
Fields annotated `@JavaOnly` are excluded from the generated C `#define` block,
keeping the BPF C source clean when the constant is only needed on the Java side.

```java
@JavaOnly
private static final long __NR_perf_event_open = 298L;
```

### Dependencies added (bpf-samples)
- `net.fornwall:jelf:0.11.0` — ELF file parsing for user-space symbol resolution.
- `me.bechberger.util:femtojson:0.4.2` — JSON serialization for flamegraph output.
- `me.bechberger.util:femtocli:0.4.0` — CLI argument parsing for sample tools.

### Scheduler improvements (sched_ext)
- Added 6 new `sched_ext` callbacks and helpers.
- `FlowScheduler` — Java port of `scx_flow`.
- `PerCpuSchedulerBase` — base class for per-CPU scheduling policies.
- Exit info capture, `printCode`, and `DispatchQueue.isEmpty`.
- Numerous bug fixes for BPF verifier compatibility.

### Bug fixes
- Compiler plugin: inject `@BPFFunction` class methods from superclasses.
- Compiler plugin: emit `return;` for void `BPF_STRUCT_OPS` callbacks.
- CI: hosted test job on Ubuntu 26.04, bpftool installation fixes.
- `BloomFilterMapTest`: skip on kernels where ring buffer consume returns `EOPNOTSUPP`.

---

## 0.1.3 and earlier

See git history. Kernel BTF snapshot diffs are documented in [MIGRATIONS.md](../MIGRATIONS.md).
