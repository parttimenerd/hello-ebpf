# Userspace Scheduler

> Design rationale: see [docs/superpowers/specs/2026-06-29-userspace-scheduler-design.md](superpowers/specs/2026-06-29-userspace-scheduler-design.md).

A framework for writing Linux CPU schedulers whose policy lives in **Java**, on top of
sched_ext. The BPF side is a generic transport — it forwards every queued task to
userspace through a ring buffer, the Java side decides where it should run, and the
result flows back through a second ring buffer for the kernel to dispatch.

This is the "rustland" pattern (cf. `scx_rustland_core`) ported to hello-ebpf: you write
ordinary Java, the framework hides the BPF.

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

For a slightly larger example see
[`RustlandFifoSample`](../bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandFifoSample.java)
(periodic stats printing, shutdown hook) and
[`WeightedRRSample`](../bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/WeightedRRSample.java)
(weighted round-robin using `QueuedTask.weight`).

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

All knobs are on [`Opts`](../bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Opts.java).
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
[`SchedStatsSnapshot`](../bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedStatsSnapshot.java)
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
[`UserspaceSchedulerStartupException`](../bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceSchedulerStartupException.java)
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
