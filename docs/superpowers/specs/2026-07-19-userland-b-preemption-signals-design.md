# Sub-project B — Preemption, cross-task signals, multithreaded dispatch

**Status:** Draft
**Date:** 2026-07-19
**Author:** brainstormed with Johannes Bechberger
**Part of:** [userland scheduler improvements](2026-07-19-userland-scheduler-improvements-overview.md)

## Summary

Raise the ceiling on scheduler complexity by adding three capabilities the
current `UserspaceScheduler` lacks:

1. **Preemption API** — Java can force a task/CPU to run *now*
   (`preempt(pid)` / `kick(cpu, flags)`), backed by a dedicated user→kernel
   control ring that the BPF side translates to `scx_bpf_kick_cpu(SCX_KICK_PREEMPT)`.
2. **BPF→Java signals** — a second kernel→user ring carrying typed event
   records; the scheduler overrides `onSignal(Signal)`. BPF-side `emitSignal()`
   is callable from any callback (or a companion kprobe), generalizing the
   `LockHolderBoost` shared-map pattern into a first-class push channel.
3. **Multithreaded dispatch** — opt-in `workerThreads(n)`: the drain loop shards
   tasks by pid-hash to N policy workers, each owning its own dispatch-ring
   producer. Off by default.

## Problem

The current model is: BPF enqueues a task → Java decides a CPU at enqueue time →
BPF dispatches. That is a one-shot, placement-only, single-threaded pipeline.
Complex schedulers need more:

- **Priority inheritance / latency-critical tasks:** "pid X just became critical,
  preempt whatever is running on its target CPU." Impossible today — Java can
  only influence a task the next time it enqueues.
- **Reacting to kernel-observed events:** a task grabs a contended futex, an RT
  task preempts an SCX CPU (`cpuRelease`), a CPU goes idle. Java can't learn
  these except by inference from the enqueue stream. `LockHolderBoostScheduler`
  had to build a bespoke shared map + uprobe producer to get one such signal.
- **Throughput:** one drain thread means one core of scheduling decisions. Fine
  for coarse policies; a bottleneck for per-task-expensive ones (ML inference,
  cross-task comparisons).

## Goals

1. `preempt(int pid)` and `kick(int cpu, KickFlags)` callable from
   `policy`/`schedule`/`tick`/`onSignal`, with sub-batch latency.
2. `onSignal(Signal s)` delivering typed BPF-emitted events; a BPF helper
   `emitSignal(kind, pid, payload)` usable from any scheduler BPF callback.
3. Opt-in `workerThreads(n)` that preserves per-pid decision ordering (a given
   pid is always handled by the same worker) and is race-free against the
   dispatch and control rings.
4. All three default **off/absent** — a scheduler that overrides nothing behaves
   exactly as today.

## Non-goals

- Preempting across cgroup/RT boundaries the kernel forbids — we surface
  `scx_bpf_kick_cpu` semantics honestly, not a stronger guarantee.
- Guaranteed signal delivery — the signal ring is best-effort (drops under
  overflow are counted, like the existing `congestionEvents`).
- Lock-free work-stealing between workers — v1 uses static pid-hash sharding.

## Design

### 1. Preemption / control ring

```
Java policy/onSignal
   │  preempt(pid)  /  kick(cpu, flags)
   ▼
control ring (user→kernel, NEW, separate from dispatch ring)
   │  ControlCtx { kind: PREEMPT|KICK, pid, cpu, flags }
   ▼
BPF drains control ring (in dispatch() or a dedicated timer callback)
   │  PREEMPT → resolve pid→cpu, scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT)
   │  KICK    → scx_bpf_kick_cpu(cpu, flags)
   ▼
kernel preempts / wakes the CPU
```

Why a **separate** ring from `dispatched`: preemption is latency-critical and
must not queue behind a batch of ordinary dispatch decisions; keeping it
separate also leaves the marshalling contract for `DispatchedTaskCtx` untouched.

New API on `UserspaceScheduler`:

```java
/** Preempt whatever is running so {@code pid} can run ASAP. Best-effort. */
public final void preempt(int pid);
/** Kick a CPU (wake it / force reschedule). flags = SCX_KICK_*. */
public final void kick(int cpu, KickFlags flags);
```

Backed by `UserspaceSchedulerBase.submitControl(kind, pid, cpu, flags)` (mirrors
the existing `submitDispatchDecision`), with a `protected submitControl(...)`
seam on the Java side for the offline harness.

### 2. BPF→Java signals

```
any BPF callback (enqueue, cpuRelease, tick, a companion @Kprobe/@Fentry)
   │  emitSignal(kind, pid, payload)
   ▼
signals ring (kernel→user, NEW)
   │  SignalCtx { kind: int, pid: int, payload: long, ts: long }
   ▼
Java run loop drains signals each iteration (before/after drainBatchOnce)
   │
   ▼
scheduler.onSignal(Signal s)   // default no-op
```

- **`SignalKind`** is an author-defined `int` space with a few framework-reserved
  values (`CPU_RELEASED`, `CPU_IDLE`, `TASK_EXIT`) the framework can emit for
  free from existing callbacks. Authors define their own for domain events
  (`LOCK_ACQUIRED`, `GC_PAUSE_BEGIN`).
- **`emitSignal`** is a `@BPFFunction` helper on `SchedulerHelpers` (or a new
  `SignalHelpers` interface) so it is callable from any Scheduler BPF context.
- **Delivery:** the run loop drains the signals ring each iteration with a poll
  budget (like `ringPollBudget`), calling `onSignal` per record. Overflow drops
  are counted in a new stat slot (`SIGNALS_DROPPED`).
- This **subsumes** the `LockHolderBoost` shared-map hack: the uprobe producer
  becomes a companion BPF program that calls `emitSignal(LOCK_ACQUIRED, pid, …)`;
  the scheduler's `onSignal` calls `preempt(pid)` or bumps a boost table.

### 3. Multithreaded dispatch (opt-in)

```
Opts.workerThreads(n)   // default 1 = today's behavior
   │
drain thread: consumeRaw → for each task, route to worker[hash(pid) % n]
   │                        via per-worker SPSC queue (pooled QueuedTask copies)
   ▼
worker[i]: schedule(subBatch) → dispatchTask → its OWN dispatch-ring producer
```

Invariants:

- **Per-pid affinity:** `hash(pid) % n` guarantees a given pid is always handled
  by the same worker, so per-pid policy state (vtime maps, deferred queues) needs
  no locking.
- **Ring producers:** `BPFUserRingBuffer` reserve/submit is single-producer per
  ring. Each worker gets its own control+dispatch ring producer *or* the
  framework serializes submits behind a per-ring lock. **Decision for the plan:**
  prefer N dispatch rings (one per worker) if `BPFUserRingBuffer` supports
  multiple producers cheaply; else a single ring guarded by a lock, measured.
- **Ordering vs. today:** with n=1 the path is byte-identical to the current
  loop (no queue hop). The worker queues only exist when n>1.

### Files touched

```
bpf/.../UserspaceSchedulerBase   control ring, signals ring, emitSignal(),   (edit)
                                 drain-control in dispatch(), enlarge init
bpf/.../UserspaceScheduler       preempt()/kick()/onSignal(), signal drain,  (edit)
                                 worker-thread sharding, submitControl seam
bpf/.../sched/KickFlags          reuse existing                              (—)
bpf/.../userspace/Signal         typed Java signal record + SignalKind       (new, ~40)
bpf/.../userspace/Opts           workerThreads, signalPollBudget             (edit)
bpf/.../userspace/ControlDispatchedMarshallingTest  wire contract           (new)
bpf/.../userspace/SignalDeliveryTest                offline drain→onSignal   (new)
bpf-samples/.../sched/LatencyCriticalSample         preempt() demo           (new, ~70)
bpf-samples/.../sched/LockBoostSignalSample         emitSignal demo, replaces(new, ~90)
                                                    the shared-map hack
```

## Testing

- **Control marshalling:** new `ControlDispatchedMarshallingTest` pins the
  `ControlCtx` wire layout (bit-for-bit, like the existing dispatched test).
- **Signal delivery (offline):** `SignalDeliveryTest` uses the harness seam to
  feed synthetic `SignalCtx` records and asserts `onSignal` sees them in order,
  drops are counted on overflow. No kernel.
- **Preemption (kernel):** `LatencyCriticalSample` smoke test on thinkstation —
  a low-priority CPU hog plus a latency-critical task; assert the critical task's
  wake-to-run latency drops when `preempt` is enabled vs. disabled.
- **Multithreading:** a harness test with `workerThreads(4)` asserts per-pid
  affinity (same pid → same worker) and that total dispatched count matches
  single-threaded for the same input. Kernel throughput smoke test on
  thinkstation.
- **Lock-boost via signals:** port `LockHolderBoostScheduler`'s assertion to
  `LockBoostSignalSample`; assert boosted holders get preempted-in.

## Risks

- **Verifier / kfunc mixing:** the `LockHolderBoost` work found the verifier
  rejects mixed uprobe + struct_ops sharing kfuncs. The signal companion program
  stays a *separate* BPF object communicating via the signals ring, not shared
  kfuncs — confirm this satisfies the verifier (it should; rings are maps).
- **Multi-producer rings:** `BPFUserRingBuffer` may be single-producer only.
  The plan must measure the lock-guarded single-ring path before committing to
  N-ring; document whichever wins.
- **Preemption storms:** unbounded `preempt` calls could thrash. Add a per-CPU
  rate note; not a hard limiter in v1 but counted in stats.
- **Reference leaks:** resolving pid→task for preempt must use raw
  `bpf_task_from_pid`/`bpf_task_release` correctly (see repo memory on cpumask
  reference leaks) — bound and release in every path.
