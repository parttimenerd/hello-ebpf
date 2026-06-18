# CPU Profiling and JVM GC Tracing

hello-ebpf ships two profiling tools that use `SEC("perf_event")` and uprobe BPF
programs to observe running JVM processes.

## CPU Profiler

`CPUProfiler` samples call stacks across all online CPUs using the Linux
CPU-clock software perf event and produces an interactive HTML flamegraph.

### How it works

1. A `SEC("perf_event")` BPF program is attached to the CPU-clock software event
   on every online CPU via
   [`perf_event_open(2)`](https://man7.org/linux/man-pages/man2/perf_event_open.2.html).
   The kernel fires the program at the configured sampling period.
2. On each sample the BPF program records the kernel and user-space call stacks
   using [`bpf_get_stackid`](https://docs.kernel.org/bpf/map_stack_trace.html)
   and increments a per-(pid, kStackId, uStackId) hit counter.
3. After the sampling window the Java side reads both maps, symbolizes every
   instruction pointer (kernel via `/proc/kallsyms`, user-space via ELF symbols),
   and builds a call tree.
4. The call tree is serialized as JSON and embedded into a self-contained HTML file
   powered by [d3-flame-graph](https://github.com/spiermar/d3-flame-graph).

### Usage

```bash
sudo java -cp bpf-samples.jar me.bechberger.ebpf.samples.CPUProfiler \
    [--duration=10] [--output=flame.html] [--period=1000000] \
    [--pid=<pid>] [--no-table]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--duration` | `10` | Sampling duration in seconds |
| `--output` | `flame.html` | Output HTML file path |
| `--period` | `1000000` | Sampling period in CPU-clock ticks (~1000 samples/s/cpu) |
| `--pid` | `-1` (all) | Restrict output to a single PID |
| `--no-table` | false | Suppress the per-method frequency table |

Open the output file in any browser — no server required.

### Symbol resolution

Kernel frames are resolved via `/proc/kallsyms`. User-space frames are resolved
using ELF `.dynsym` (preferred) or `.symtab` sections, with address layout from
`/proc/PID/maps`. ELF parsing is done with [jelf](https://github.com/fornwall/jelf).
Frames that cannot be resolved fall back to `libname+0xoffset` or `[unknown]+0xip`.

The `StackSymbolizer` helper class handles all symbol resolution and can be reused
independently of `CPUProfiler`:

```java
var sym = new StackSymbolizer();
var ranges = StackSymbolizer.readMaps(pid);  // parse /proc/pid/maps

String kernelSym = sym.symKernel(ip);         // /proc/kallsyms lookup
String userSym   = sym.symUser(ip, ranges);   // ELF lookup
```

### BPF API used

- `PerfEvent.of(ctx)` — wraps the `struct bpf_perf_event_data *` context.
- `PerfEvent.getStackId(map, flags)` — calls `bpf_get_stackid`.
- `BPFProgram.attachPerfEvent(prog, pfd)` — attaches a BPF program to a perf fd.
- `BPFStackTraceMap` — stores instruction-pointer arrays keyed by stack ID.

```java
@BPF(license = "GPL")
abstract class MyProfiler extends BPFProgram {

    @BPFMapDefinition(maxEntries = 10_000)
    BPFStackTraceMap stacks;

    @BPFFunction(section = "perf_event", autoAttach = false)
    public void onSample(Ptr<bpf_perf_event_data> data) {
        PerfEvent pe = PerfEvent.of(data);
        int stackId = (int) pe.getStackId(stacks, PerfEvent.STACK_USER | PerfEvent.STACK_REUSE);
        // ...
    }
}
```

---

## JVM GC Pause Tracer

`JvmGcPauseTracer` measures stop-the-world GC pauses in a running JVM by
attaching uprobes to `libjvm.so`.

### How it works

HotSpot centralizes all GC pause notifications through two C++ methods in
`VM_GC_Operation`:

- `notify_gc_begin(bool full)` — called at the start of every STW pause; the
  `full` parameter distinguishes full (major) from young (minor) collections.
- `notify_gc_end()` — called when the pause ends.

Two BPF probes bracket these calls:

1. **uprobe** on `notify_gc_begin` — records `bpf_ktime_get_ns()` and the `full`
   flag into a per-CPU hash map keyed by CPU id.
2. **uretprobe** on `notify_gc_end` — retrieves the start record, computes
   duration, and emits a `GcEvent` to a ring buffer.

### Usage

```bash
sudo java -cp bpf-samples.jar me.bechberger.ebpf.samples.JvmGcPauseTracer \
    --pid=<jvm-pid> [--libjvm=/path/to/libjvm.so] [--histogram]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--pid` | required | PID of the target JVM process |
| `--libjvm` | auto-detected | Path to `libjvm.so`; auto-found in `/proc/pid/maps` if omitted |
| `--histogram` | false | Print a bucketed pause-duration histogram on exit (Ctrl-C) |

Example output:

```
Attaching to /usr/lib/jvm/java-21/lib/server/libjvm.so for pid 12345
TYPE    PID       TID       DURATION
YOUNG   12345     12350     2.341 ms
YOUNG   12345     12350     1.892 ms
FULL    12345     12350     87.441 ms
```

With `--histogram` (printed on Ctrl-C):

```
===== GC pause histogram =====
Bucket        Young     Full
<1ms              3        0
1–5ms            47        0
5–10ms            8        0
10–50ms           2        1
50–100ms          0        2
100–500ms         0        0
≥500ms            0        0
TOTAL            60        3
```

### Limitations

- The target JVM must be built with debug symbols or at least have non-stripped
  C++ symbols in `libjvm.so` (all standard OpenJDK distributions qualify).
- The uprobe fires on every JVM that uses the same `libjvm.so` binary; the
  `--pid` filter restricts event output to the target PID but the uprobe itself
  is process-wide on that binary.
- Concurrent GC collectors (ZGC, Shenandoah) have shorter STW phases; the tracer
  still captures them but durations will be very short.

### BPF API used

- `BPFProgram.attachUprobe(prog, false, pid, lib, funcName)` — entry probe.
- `BPFProgram.attachUprobe(prog, true, pid, lib, funcName)` — return probe.
- `BPFRingBuffer` — sends completed `GcEvent` records to user space.
- `bpf_ktime_get_ns()` — nanosecond wall-clock for duration measurement.
- `bpf_get_smp_processor_id()` — per-CPU scratch map key.
