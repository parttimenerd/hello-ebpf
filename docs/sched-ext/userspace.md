# Userspace Scheduler

**Javadoc:** [`UserspaceScheduler`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.html) · [`QueuedTask`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/QueuedTask.html) · [`Opts`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/userspace/Opts.html)

**See also:** [scx_rustland_core](https://github.com/sched-ext/scx/tree/main/rust/scx_rustland_core) (the Rust pattern this port is based on) · [sched_ext kernel docs](https://docs.kernel.org/scheduler/sched-ext.html)

!!! warning "Highly experimental"
    The userspace scheduler is under active development and the API may change between
    releases. It has been tested on Linux 6.12–6.14 (kernel ≥ 6.12 required). If you
    hit issues, please [open an issue](https://github.com/parttimenerd/hello-ebpf/issues)
    with the verifier log attached.

A userspace scheduler moves the scheduling policy to **Java**, running in user space.
The BPF side is a thin transport: it forwards every queued task through a ring buffer,
Java decides where it should run, and the decision flows back through a second ring
buffer for the kernel to dispatch.

This is the "rustland" pattern (cf. `scx_rustland_core`) ported to hello-ebpf: you write
ordinary Java, the framework hides the BPF.

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

### Batch `schedule()` callback (**Experimental**)

For algorithms that need to look at the full batch before assigning CPUs (e.g.
deadline sorting across the whole batch), override `schedule(QueuedTask[], int)`
instead of `policy()`:

```java
@Override
protected void schedule(QueuedTask[] tasks, int count) {
    // Sort by some criteria across the whole batch
    Arrays.sort(tasks, 0, count, Comparator.comparingLong(t -> t.sumExecRuntime));
    for (int i = 0; i < count; i++) {
        dispatchTask(tasks[i], ANY_CPU);
    }
}
```

`dispatchTask(task, cpu)` dispatches a single task — call it once per task in
the batch before returning. Every task in the array **must** be dispatched before
`schedule()` returns (the kernel stall watchdog fires if any task waits > 50 ms).

### Persistent queues with `QueuedTask.copy()` (**Experimental**)

The `QueuedTask[]` array is a **flyweight pool** — each entry is reused across
batches. To store a task in a data structure that persists beyond the current
`schedule()` call, use `QueuedTask.copy()`:

```java
private final ArrayDeque<QueuedTask> deferred = new ArrayDeque<>();

@Override
protected void schedule(QueuedTask[] tasks, int count) {
    for (int i = 0; i < count; i++) {
        deferred.addLast(tasks[i].copy());   // heap copy, safe to keep
    }
    while (!deferred.isEmpty()) {
        dispatchTask(deferred.pollFirst(), ANY_CPU);
    }
}
```

A copied `QueuedTask` is fully dispatchable via `dispatchTask()` in any future
batch. The `enqCnt` stale-dispatch guard still applies — if the copied task was
re-enqueued before you dispatch it, the dispatch is silently cancelled by the BPF
transport and `ringCanceled` is incremented.

### Helper classes (**Experimental**)

Three helpers in `me.bechberger.ebpf.bpf.userspace` remove the boilerplate that
every non-trivial policy re-implements. They are plain Java — no BPF, no kernel.

- **[`DeferredQueue`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/DeferredQueue.java)** —
  a copy-storing heap for sorted or time-gated scheduling. `deferOrdered(t, key)`
  orders by a key (vtime, deadline); `deferUntil(t, notBeforeNs)` holds a task until
  a wall-clock time; `drainEligible(nowNs, max, sink)` pops the eligible front in key
  order. It stores `copy()`s, so entries survive across batches.
- **[`TaskClassifier`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/TaskClassifier.java)** —
  turns "classify a task into a band, then route the band" into a table:
  `builder().classify(fn).policy(BAND, placement).build()`. `classOf(t)` returns the
  band; `decide(t)` classifies and applies that band's placement in one call.
- **[`SchedulerRunner`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerRunner.java)** —
  a one-line `main`: `SchedulerRunner.run(new MyScheduler(), args)` wires the
  shutdown hook and the periodic `--stats-interval` printer, then calls `runUntilExit`.

`LatencyTierEdfSample` shows the canonical shape combining a `TaskClassifier` (tier
lookup) with a `DeferredQueue` (earliest-deadline-first order across the batch).

### Offline testing with `SchedulerHarness` (**Experimental**)

[`SchedulerHarness`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerHarness.java)
runs your `schedule`/`tick` against fabricated tasks in a plain JVM test — no root,
no kernel — and records what was dispatched:

```java
var h = SchedulerHarness.forScheduler(new MyScheduler()).withCpus(8);
h.feed(task(1, 100), task(2, 50)).runBatch();
assertEquals(List.of(1, 2),
        h.dispatches().stream().map(SchedulerHarness.Dispatch::pid).toList());
```

`withCpus(n)` models a machine of any size — the scheduler's dispatch-range
validation and `cpuCount()` follow it, so a CPU-targeting policy can be tested for a
machine larger than the CI host. **Read `cpuCount()`, not
`Runtime.getRuntime().availableProcessors()`,** when computing concrete CPU targets so
placement honours `withCpus`.

For time-dependent policies (rate limiting, EDF deadlines, `deferUntil`) install a
**virtual clock** so tests are deterministic and instant:

```java
var h = SchedulerHarness.forScheduler(sched).withCpus(8).withVirtualClock(0);
h.feed(task(1, 100)).runBatch();       // dispatches at t=0
h.clear();
h.advanceMillis(5).feed().runBatch();  // the gate has now elapsed
```

The virtual clock replaces the scheduler's time source, so this only works if your
scheduler reads time through `nanoTime()` — **never call `System.nanoTime()`
directly** in a scheduler you want to test. (`.feed()` with no arguments runs an empty
batch, which advances time and triggers `schedule` without new arrivals.)

The package-level Javadoc on `me.bechberger.ebpf.bpf.userspace` is the authoring
guide that ties these pieces together.

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
| [`VtimeSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/VtimeSample.java) | Batch vtime ordering with `schedule()`, `TreeMap` sort (**Experimental**) |
| [`RustlandJavaSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandJavaSample.java) | Full scx_rustland port: `deadline = vtime + exec_runtime`, idle-CPU bitmap, interactive/batch separation (**Experimental**) |
| [`FifoQueueSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/FifoQueueSample.java) | Persistent `ArrayDeque` queue across batches using `QueuedTask.copy()` (**Experimental**) |
| [`TwoQueueFifoSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/TwoQueueFifoSample.java) | Two-tier FIFO: interactive (< 10 ms exec) vs batch (**Experimental**) |
| [`CmdlineBoostSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/CmdlineBoostSample.java) | `/proc` reads, cmdline classification, CPU partitioning |
| [`ShowcaseScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/ShowcaseScheduler.java) | Six-tier /proc-powered scheduler: cmdline + cgroup detection + I/O bytes/s + container CPU partition (**Experimental**) |
| [`LatencyTierEdfSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LatencyTierEdfSample.java) | `TaskClassifier` tiers + `DeferredQueue` earliest-deadline-first ordering across the batch (**Experimental**) |
| [`EdfRateLimitSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/EdfRateLimitSample.java) | Time-gated `DeferredQueue.deferUntil` — per-pid rate limiting with a weight-scaled gap (**Experimental**) |
| [`CorePartitionSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/CorePartitionSample.java) | `TaskClassifier` *placement* policies routing interactive vs batch work to disjoint core pools (**Experimental**) |
| [`RustyScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustyScheduler.java) | scx_rusty-style per-LLC-domain push/pull load balancing, single-NUMA (**Experimental**) |

## Porting scx_rusty: domain load balancing

[`RustyScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustyScheduler.java)
is a Java port of the userspace load-balancing core of
[scx_rusty](https://github.com/sched-ext/scx). Upstream rusty groups CPUs into *domains*
(one per last-level cache), tracks each task's load, and periodically pushes load from
overloaded domains to underloaded ones — keeping tasks cache-warm while spreading work. This
port implements that push/pull core at **single-NUMA scope**: the balancing algorithm is faithful
to upstream, but the inter-NUMA layer, infeasible-weight correction, and BPF-side load tracking
are deliberately left out (see *Simplifications* below).

The port is built from three reusable, kernel-free pieces in
`me.bechberger.ebpf.bpf.userspace`, plus the sample that wires them together:

- **[`CpuTopology`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/CpuTopology.java)**
  — reads `/sys/devices/system/cpu/cpuN/cache/indexK/{level,shared_cpu_list}` and groups CPUs
  that share a last-level cache into one domain each. It never throws: missing or unreadable
  cache info falls back to a single domain covering all online CPUs. Inject a fake sysfs root
  (`CpuTopology.detect(Path)`) to build arbitrary topologies in tests.
- **[`RustyLoadTracker`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/RustyLoadTracker.java)**
  — a per-pid decayed duty-cycle metric, the userspace analogue of rusty's BPF ravg buckets.
  Duty cycle is an exponentially-decayed EWMA of `execRuntime / wallTime`, updated on each enqueue
  **and decayed again at read time** so a task that went dormant decays exactly as it would if
  sampled continuously. Task load is `dutyCycle * weight`; the decay half-life is configurable
  (`--half-life-ms`, default 1 s).
- **[`DomainLoadBalancer`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/DomainLoadBalancer.java)**
  — a pure function (no BPF, no I/O) porting rusty's `balance_within_node`. Given a list of
  `Domain`s (each holding a load sum and a list of `TaskLoad{pid, load, domMask, preferredDomMask,
  isKworker}`) and the average load, it pops the most-overloaded push domain, pulls into
  underloaded domains least-loaded-first, and for each pair moves the task whose load is closest
  to `xfer = min(pushImbal, pullImbal) * 0.5` — preferring tasks cache-affine to the pull domain,
  and only if the move reduces the pair's total imbalance. It returns a list of `Migration`s and
  mutates nothing the caller passed in.

`RustyScheduler` itself is thin, because all the policy lives in those three pieces:

- **`schedule()` (hot path):** assign each task a domain (from its `prevCpu`'s domain, or
  round-robin for a brand-new task), record its load via `RustyLoadTracker.onEnqueue`, and
  dispatch it to an idle CPU **inside its assigned domain** — falling back to `ANY_CPU` when the
  domain has no idle CPU.
- **`tick()` (cold path, ~1 s):** decay every tracked task, prune ones dormant past the stale
  threshold, bucket the survivors' load into `Domain`s, run `DomainLoadBalancer.balance`, and
  apply each `Migration` by reassigning the task's target domain. Like upstream rusty, the next
  enqueue is what actually moves the task — `tick()` only sets `target_dom`.

### Correctness evidence

The balancing logic is proved offline, with no kernel or root, under the
[`SchedulerHarness`](#offline-testing-with-schedulerharness-experimental):

- [`DomainLoadBalancerTest`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/DomainLoadBalancerTest.java)
  — the imbalance state machine and the push/pull engine (closest-to-`xfer`, cache-affinity
  preference, infeasible-task and kworker skipping, only-if-reduces-imbalance guard).
- [`CpuTopologyTest`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/CpuTopologyTest.java)
  — LLC grouping and the single-domain fallback, via a fake sysfs tree.
- [`RustyLoadMetricTest`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/RustyLoadMetricTest.java)
  — the load metric: a busy task converges toward its weight, a mostly-sleeping task stays low,
  a dormant task decays toward zero at read time.
- [`RustySchedulerHarnessTest`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/test/java/me/bechberger/ebpf/samples/sched/RustySchedulerHarnessTest.java)
  — end-to-end offline: domain assignment follows `prevCpu`, every fed task is dispatched, and a
  domain piled with busy tasks triggers a real migration after `tick()`.

[`RustySchedulerSmokeTest`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/test/java/me/bechberger/ebpf/samples/sched/RustySchedulerSmokeTest.java)
additionally attaches the scheduler to a real kernel under `virtme-ng` and confirms it stays
attached while draining tasks through the userspace ring.

### Simplifications vs upstream rusty

This is a faithful *core* port, not a bit-for-bit one:

- **Single-NUMA only.** rusty balances within a NUMA node and then across nodes; this port does
  only the within-node (domain) layer.
- **Userspace load, not BPF ravg.** Load is computed in Java from `execRuntime` deltas
  (decay-at-read) rather than read from rusty's BPF-side ravg buckets.
- **No infeasible-weight correction.** rusty rescales weights when a task's affinity makes its
  fair share unachievable; this port models affinity with a simple `domMask` and skips the
  correction.
- **Default weight 100.** Per-pid weight is not tracked through `tick()`; task load uses the
  default weight. This suffices for the common case and keeps the port small.
- **One transfer per (push, pull) pair per round.** Balance converges over repeated `tick()`s;
  a single round's migration count can differ from upstream (documented in
  `DomainLoadBalancer`'s Javadoc).
- **64-CPU domain masks.** `Domain`/`CpuTopology` use a single `long` bitmask per domain, so CPU
  indices ≥ 64 are not represented. Fine for typical single-socket hosts.

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
- `stallFallbacks` — tasks rescued by the BPF-side 50 ms stall fallback. When
  the Java drain loop falls behind, the BPF side promotes waiting tasks from
  `SHARED_DSQ` directly to the local CPU DSQ so they are not starved. A non-zero
  count means the Java thread was too slow to drain: investigate GC pauses
  (check `ringConsumeUs` histogram) or lock contention in the dispatch loop. A
  handful of fallbacks during JVM startup is normal; sustained fallbacks are a bug.
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

### Decision trace & per-class metrics (**Experimental**)

Two opt-in aids for understanding *why* the scheduler did what it did:

- **Decision trace** — set `Opts.decisionTraceCapacity > 0` to keep a bounded ring
  of the most recent decisions (`DISPATCH`, `PREEMPT`, `KICK`, `DROP`), readable via
  `scheduler.recentDecisions()`. Off (capacity 0) by default so it costs nothing.
- **Per-class metrics** — call `scheduler.setClassMetrics(classifier)` once with a
  `TaskClassifier`; then `scheduler.perClass(band)` returns a `ClassMetrics`
  (count, p50, p99 dispatch latency) per band. `ShowcaseScheduler` uses this to print
  a per-tier breakdown from `formatStats()`.

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
- **`policy()` runs on a single thread by default.** Decisions must be cheap
  (target: < 1 µs per call). For CPU-bound policies you can opt into sharded parallel
  dispatch by setting `Opts.workerThreads > 1`, which partitions tasks across worker
  threads by pid affinity (a given pid is always handled by the same worker, so per-pid
  state stays single-writer). Leave it at the default `1` unless you have measured that
  `policy()` is the bottleneck.

---

*Next: [Callbacks Reference](callbacks.md)*
