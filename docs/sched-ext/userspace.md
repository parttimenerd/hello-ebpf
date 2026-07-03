# Userspace Scheduler

A userspace scheduler moves the scheduling policy to **Java**, running in user space.
The BPF side is a thin transport: it forwards every queued task through a ring buffer,
Java decides where it should run, and the decision flows back through a second ring
buffer for the kernel to dispatch.

This is the "rustland" pattern (cf. `scx_rustland_core`) ported to hello-ebpf: you write
ordinary Java, the framework hides the BPF.

**Blog series** — the userspace scheduler is introduced in
[Part 16: Control task scheduling with a custom scheduler written in Java](https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/)
and the userspace lottery variant in
[Part 18: Writing a lottery scheduler in pure Java with BPF for-each support](https://mostlynerdless.de/blog/2024/12/27/hello-ebpf-writing-a-lottery-scheduler-in-pure-java-with-bpf-for-each-support-18/).

![Tasks enqueue into a scheduling queue; CPUs ask for new tasks and return finished ones; a task-settings map controls policy](https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png)

---

## How it works

```
kernel                                  Java (your policy)
──────                                  ──────────────────
task becomes runnable
  │
  ▼
UserspaceSchedulerBase.enqueue()        ┌─────────────────────┐
  • framework PID? → FRAMEWORK_DSQ      │  runUntilExit()      │
  • kthread fast path? → SHARED_DSQ     │    loop              │
  • else → write QueuedTaskCtx          │      drainBatchOnce()│
      into queued ring buffer  ─────────►        policy(t)     │
                                        │        → cpu         │
UserspaceSchedulerBase.dispatch()  ◄────┤      submitDispatch()│
  • read DispatchedTaskCtx from         │      tick() / 1s     │
      dispatched user ring buffer       └─────────────────────┘
  • scx_bpf_dsq_insert(task, cpu)
  • 50 ms stall fallback if Java stalls
```

There are **two ring buffers** between kernel and Java:

- **`queued` (kernel→Java, `BPFRingBuffer`)** — BPF `enqueue` writes a
  `QueuedTaskCtx` record for every task that needs a scheduling decision. If
  the ring is full the task falls back to `SHARED_DSQ` immediately
  (`ringDropped` counter).
- **`dispatched` (Java→kernel, `BPFUserRingBuffer`)** — Java reserves a slot,
  fills a `DispatchedTaskCtx` (pid, targetCpu, sliceNs, vtime), and commits.
  BPF `dispatch` drains this ring on every `dispatch()` callback.

**Fast paths that bypass Java entirely:**

| Situation | BPF action | Why |
|---|---|---|
| Task is a JVM thread (`frameworkPids` map hit) | → `FRAMEWORK_DSQ` | Drain thread must not wait on itself |
| `kswapd` / `khugepaged` | → `SHARED_DSQ` | Memory reclaim must not stall |
| `selectCPU` finds an idle CPU | dispatch immediately to `LOCAL` | No ring-trip at all |
| Java stalls for > 50 ms | promote from `SHARED_DSQ` | Watchdog safety net |

**The run loop (`runUntilExit`):**

1. Load `UserspaceSchedulerBase` BPF program and attach as `struct_ops`.
2. Seed JVM thread IDs (`/proc/self/task`) into the `frameworkPids` BPF hash map *before* attaching, so the drain thread is never routed through its own ring.
3. Loop:
   - Drain up to `batchSize` records from `queued` ring into a pre-allocated `QueuedTask[]` pool (zero allocation on hot path).
   - Call `policy(t)` for each task; catch exceptions individually.
   - Submit dispatch decisions via `submitDispatch`.
   - Every ~1 s: rescan `/proc/self/task` for new JVM threads; call `tick()`.
4. Exit when `requestExit()` is called or `isAttached()` returns false (kernel detached us).

**Idle-CPU lookup** (`ANY_CPU` path): the framework `mmap`s an arena-backed
bitmap that BPF `updateIdle` keeps current. `pickIdleCpu()` reads that bitmap
with zero syscalls, round-robins to spread load, and falls back to `ANY_CPU`
if no idle CPU is found. You can also call `selectCpu(pid, prevCpu)` from
`policy()` to ask the kernel's own `scx_bpf_select_cpu_dfl` for a recommendation.

**`enqCnt` stale-dispatch prevention:** each task has a per-task `enqCnt`
counter in BPF task storage, incremented on every `enqueue`. The ring record
carries the counter value at enqueue time. When Java submits a dispatch, BPF
checks whether the task's current `enqCnt` still matches — if the task was
re-enqueued in the meantime the dispatch is silently cancelled (`ringCanceled`
counter). This prevents dispatching a task to a stale CPU after it already
woke and was re-queued.

---

## 1. What is this

`UserspaceScheduler` is an abstract class. You subclass it, override
`policy(QueuedTask)` to return a CPU id (or `ANY_CPU`), and call `runUntilExit`. The
framework handles BPF loading, struct_ops attach, task PID bookkeeping, ring-buffer
drain, dispatch submission, the kernel watchdog handshake, JFR events, and stats.

Use it when you want to prototype scheduling policies without touching C or the kernel,
and you are willing to pay the userspace round-trip cost (single-digit microseconds at
p50 on a quiet box).

## 2. Requirements

- Linux kernel **≥ 6.12** built with `CONFIG_SCHED_CLASS_EXT=y`. Verify with
  `ls /sys/kernel/sched_ext` — the directory must exist.
- Capabilities: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`. The simplest path is
  `sudo -E`.
- At most one sched_ext scheduler can be attached at a time. Stop any running
  `scx_*` service first (`systemctl stop scx`).
- **ZGC is strongly recommended.** Default G1 pauses on a multi-GB heap can exceed
  the 30s task-stall watchdog under load. Run with `-XX:+UseZGC -XX:+ZGenerational`.
  The framework warns if it does not detect ZGC at start unless
  `Opts.verifyZgcOnStart = false`.

## 3. Your first scheduler

A minimal FIFO scheduler is six lines of policy:

```java
import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;

public final class MyFifo extends UserspaceScheduler {
    @Override
    protected int policy(QueuedTask t) {
        return ANY_CPU;       // let BPF pick any idle CPU
    }

    public static void main(String[] args) {
        new MyFifo().runUntilExit(Opts.defaults());
    }
}
```

`policy` runs **once per queued task** on the framework's drain thread. Return:

- a non-negative CPU id to pin the task to that CPU,
- `ANY_CPU` (-1) to let the BPF transport place it on the shared DSQ and run on
  any idle CPU.

There is **no `schedule` callback** — the per-task `policy()` returning a CPU *is*
the schedule. If you need periodic work (e.g. recompute weights) override
`tick()`, which fires once per second.

---

## Example: Interactive-vs-batch partitioner

The standout advantage of a userspace scheduler over a kernelspace one is **access
to the full Linux process tree**. BPF can read `comm` (a 15-character kernel thread
name), but it has no way to read `/proc/<pid>/cmdline` — the full command line
including all arguments. A Java process whose `comm` is `java` can be identified
as `gradle`, `mvn`, or `kotlinc` from its cmdline. That identification is
impossible in BPF.

`CmdlineBoostSample` exploits this: it reads `/proc/<pid>/cmdline` once per new
PID (cached), extracts the binary basename, and classifies each task as
*interactive* or *batch*:

- **Interactive** (shells, editors, terminals, browsers) → `ANY_CPU`: sched_ext picks
  any idle CPU for minimum wake-up latency.
- **Batch** (compilers, build tools, test runners) → pinned to the **upper half** of
  available CPUs, leaving the lower half free for interactive work.
- **Everything else** → `ANY_CPU`.

The `tick()` callback runs once per second to purge dead PIDs from the cache by
checking whether `/proc/<pid>` still exists — another thing BPF cannot do cheaply.

```java
import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class CmdlineBoostSample extends UserspaceScheduler {

    private static final Set<String> INTERACTIVE = Set.of(
            "bash", "sh", "zsh", "vim", "nvim", "emacs",
            "alacritty", "kitty", "gnome-terminal", "firefox");

    private static final Set<String> BATCH = Set.of(
            "gcc", "g++", "clang", "make", "ninja",
            "gradle", "mvn", "javac", "cargo", "pytest");

    private final Map<Integer, String> cmdlineCache = new ConcurrentHashMap<>();
    private final Map<Integer, Long>   lastSeen     = new ConcurrentHashMap<>();
    private long tickCount   = 0;
    private int  batchRobin  = 0;

    @Override
    protected int policy(QueuedTask t) {
        String bin = resolveBin(t.pid);
        lastSeen.put(t.pid, tickCount);

        if (bin != null && INTERACTIVE.contains(bin)) return ANY_CPU;
        if (bin != null && BATCH.contains(bin))       return nextBatchCpu();
        return ANY_CPU;
    }

    /** Purge dead PIDs once per second. */
    @Override
    protected void tick() {
        tickCount++;
        Iterator<Map.Entry<Integer, String>> it = cmdlineCache.entrySet().iterator();
        while (it.hasNext()) {
            int pid = it.next().getKey();
            long age = tickCount - lastSeen.getOrDefault(pid, tickCount);
            if (age > 5 || !Files.exists(Path.of("/proc/" + pid))) {
                it.remove();
                lastSeen.remove(pid);
            }
        }
    }

    private String resolveBin(int pid) {
        return cmdlineCache.computeIfAbsent(pid, p -> {
            try {
                byte[] raw = Files.readAllBytes(Path.of("/proc/" + p + "/cmdline"));
                if (raw.length == 0) return null;
                int end = 0;
                while (end < raw.length && raw[end] != 0) end++;
                String argv0 = new String(raw, 0, end);
                int slash = argv0.lastIndexOf('/');
                return slash >= 0 ? argv0.substring(slash + 1) : argv0;
            } catch (IOException e) { return null; }
        });
    }

    private synchronized int nextBatchCpu() {
        int n = Runtime.getRuntime().availableProcessors();
        int batchStart = Math.max(1, n / 2);
        return batchStart + (batchRobin++ % (n - batchStart));
    }
}
```

What's only possible here and not in kernelspace BPF:

| Capability | Userspace | BPF |
|---|---|---|
| Read `/proc/<pid>/cmdline` | `Files.readAllBytes(...)` | Not available |
| Identify `java` as `gradle` vs `mvn` | argv[0] from cmdline | comm is always `java` |
| Check `/proc/<pid>` exists | `Files.exists(...)` | Not available |
| `Runtime.availableProcessors()` | Yes | `scx_bpf_nr_cpu_ids()` (ids, not count) |
| Arbitrary Java data structures | Yes — `HashMap`, trees, etc. | Stack-limited maps only |

Full source with CLI, stats, and shutdown hook:
[`CmdlineBoostSample.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/CmdlineBoostSample.java)

---

## Sample schedulers

| Scheduler | What it demonstrates |
|-----------|---------------------|
| [`RustlandFifoSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandFifoSample.java) | Minimal FIFO with periodic stats |
| [`WeightedRRSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/WeightedRRSample.java) | Per-task state and `QueuedTask.weight` |
| [`LotterySample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LotterySample.java) | Weight-biased probabilistic CPU placement |
| [`VtimeSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/VtimeSample.java) | Batch vtime ordering with `schedule()`, `TreeMap` sort |
| [`RustlandJavaSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandJavaSample.java) | Full scx_rustland port: `deadline = vtime + exec_runtime`, interactive/batch separation |
| [`CmdlineBoostSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/CmdlineBoostSample.java) | `/proc` reads, cmdline classification, CPU partitioning |

## 4. Running

Build and launch with elevated capabilities:

```sh
sudo -E java \
    -XX:+UseZGC -XX:+ZGenerational \
    -cp bpf-samples.jar \
    me.bechberger.ebpf.samples.sched.RustlandFifoSample
```

Expected output:

```
RustlandFifoSample: attaching scheduler (Ctrl-C to detach)...
[stats] drained=312 dropped=0 disp=312/-0 cancel=0 stall=0 kicks=4
[stats] drained=648 dropped=0 disp=648/-0 cancel=0 stall=0 kicks=8
^C
==== Final stats ====
drained=911 dropped=0 disp=911/-0 cancel=0 stall=0 kicks=11
==== Histograms ====
ringConsumeUs       count       distribution
[1, 1]                  3       |*                              |
[2, 3]                 24       |********                       |
[4, 7]                221       |*******************************|
```

Ctrl-C calls `requestExit()` via a shutdown hook; the run loop returns at the next
batch boundary, the scheduler is detached, and the JVM exits cleanly.

## 5. Tuning

All knobs are on [`Opts`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Opts.java).
The defaults are reasonable; only override what you have measured.

| Option | Default | Effect |
|---|---|---|
| `batchSize` | 256 | Max tasks drained per BPF→Java round trip. Higher = better throughput, worse tail latency. |
| `ringPollBudget` | 1024 | Hard cap on ringbuf records consumed per `drainRaw` call. |
| `frameworkPidRescan` | 5 s | How often `/proc/self/task` is rescanned to re-pin JVM threads. |
| `policyExceptionBudgetPerSec` | 100 | Soft budget — exceeding logs loudly but does not abort. |
| `verifyZgcOnStart` | true | Warn if ZGC is not detected. |

JVM flags worth setting:

- `-XX:+UseZGC -XX:+ZGenerational` — keeps GC pauses well under the watchdog.
- `-Xmx<reasonable>` — a 32 GiB heap with G1 can pause for seconds. Don't.
- `-XX:+UnlockDiagnosticVMOptions -XX:+DebugNonSafepoints` — better JFR stacks if
  you record the scheduler.

## 6. Observability

### Stats (cheap, always on)

`scheduler.stats()` returns an immutable
[`SchedStatsSnapshot`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedStatsSnapshot.java)
with counters from both BPF and Java sides:

- `ringEnqueued` — BPF wrote to queued ringbuf
- `ringDropped` — ringbuf was full, task fell back to kernel-side handling
- `ringDrained` — Java consumed from queued ringbuf
- `ringCanceled` — Java consumed but `enqCnt` was stale, so it skipped dispatch
- `dispatched` / `dispatchFailed` — kernel dispatch outcomes
- `stallFallbacks` — tasks rescued by the BPF-side 50 ms stall fallback (means the
  Java drain stopped — investigate)
- `heartbeatKicks` — `SCX_KICK_IDLE` issued by the BPF heartbeat timer

`formatStats()` is a single-line render suitable for periodic stderr prints.

### Histograms (cheap, log2-bucketed)

`scheduler.printHistograms(out)` dumps three log2 histograms:

- **ringConsumeUs** — wall-clock time spent draining one batch (Java side).
- **roundTripUs** — time between BPF enqueue (`stopTs`) and Java dispatch. Only
  populated for tasks that previously ran (i.e. have a non-zero `stopTs`).
- **batchSize** — number of tasks per drain.

### JFR events

Three thresholded events under category `hello-ebpf / userspace-scheduler`:

| Event | Threshold | Payload |
|---|---|---|
| `hellobpf.userspace.Batch` | 200 µs | size, dispatched |
| `hellobpf.userspace.Dispatch` | 100 µs | pid, cpu, rc |
| `hellobpf.userspace.Tick` | 500 µs | heapUsedMb, frameworkPids |

These are off by default in `default.jfc` — enable them in your `.jfc` if you
want them in long-running recordings.

### Where to look when something is wrong

| Symptom | First place to check |
|---|---|
| `dispatched == 0` but `ringEnqueued > 0` | Run loop is alive but `dispatchInternal` is failing — see `dispatchFailed`. |
| `stallFallbacks > 0` | Java drain stalled past 50 ms. Check GC pauses (Tick events), or whether `policy()` is blocking. |
| Scheduler kicked by kernel watchdog (`task X failed to run for 30s`) | Run loop blocked. Check JFR for long Tick/Batch events. Most likely culprit: G1 GC pause on a large heap. |
| `ringDropped > 0` | Java drain is too slow to keep up — increase `batchSize`, check `roundTripUs`. |
| `ringCanceled > 0` consistently | Tasks being rapidly re-enqueued before Java dispatched them. Often benign on a busy system. |

## 7. Troubleshooting

**`Cannot find /sys/kernel/sched_ext`** — kernel was not built with sched_ext, or the
module is gated by a config you didn't enable. You need ≥ 6.12 with `CONFIG_SCHED_CLASS_EXT=y`.

**`operation not permitted` at attach** — missing capabilities. Re-run with `sudo -E`.
The framework needs `CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN`.

**`scheduler is already attached`** — another sched_ext scheduler is loaded.
`systemctl stop scx` and any other scx user, then retry.

**Verifier rejection at load** — wrapped in a
[`UserspaceSchedulerStartupException`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceSchedulerStartupException.java)
with the libbpf log attached. These are framework bugs — open an issue with the log.

**Watchdog kills the scheduler after ~30 s under load** — this is the
`timeout_ms` task-stall watchdog. The Java run loop is not draining fast enough,
typically because:

1. GC pauses (run with ZGC).
2. `policy()` is blocking on I/O. It must not.
3. The drain thread itself is a JVM thread that wasn't seeded into
   `frameworkPids` before attach — this used to be a bug; current code seeds it.
   If you see this on a clean build, file an issue.

## 8. Limitations & non-goals

- **Single-process JVM only.** The framework loads one BPF program; there can be
  one userspace scheduler per machine.
- **No per-cgroup or per-cpuset policy.** The transport is global. If you want
  cgroup-aware scheduling, you do it inside `policy()` by reading
  `/proc/<pid>/cgroup`.
- **No in-flight task migration.** Once a task is dispatched, it runs on the CPU
  you picked until the next sched_ext event (sleep, preemption, completion).
- **Not a replacement for in-kernel schedulers.** Even with ZGC the userspace
  round-trip adds 1–10 µs at p50 and significantly more at p99 under GC pressure.
  Use it where flexibility > microbenchmark latency.
- **`policy()` runs on a single thread.** No concurrency, no shared mutable state
  to worry about — but also no parallelism. Decisions must be cheap (target: < 1 µs
  per call).
