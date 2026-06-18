# sched_ext — Extensible CPU Scheduler

sched_ext is a Linux scheduling class introduced in kernel 6.11 that lets you implement
CPU schedulers entirely in BPF. Instead of patching the kernel, you can prototype and
deploy custom scheduling policies from a user-space Java program.

## Prerequisites

- Kernel ≥ 6.11 with `CONFIG_SCHED_CLASS_EXT=y`
- Verify: `ls /sys/kernel/sched_ext` should exist
- At most one sched_ext scheduler can be active at a time — stop any running scx service
  with `systemctl stop scx` before attaching your own.

## Why sched_ext?

Traditional kernel schedulers require kernel patches, reboots, and deep kernel expertise.
sched_ext lets you:

- Prototype scheduling algorithms in minutes
- Deploy different schedulers per workload
- Roll back instantly if a scheduler misbehaves (watchdog auto-detaches in `timeout_ms`)
- Ship schedulers as ordinary jar files

## Quick start

The minimal requirement is two annotations and one method:

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

@BPF(license = "GPL")
@Property(name = "sched_name", value = "my_scheduler")
public abstract class MyScheduler extends SchedulerBase implements Scheduler {

    // Attach to the shared DSQ created by SchedulerBase.init() — no extra create needed.
    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    public static void main(String[] args) throws Exception {
        try (var sched = BPFProgram.load(MyScheduler.class)) {
            sched.runSchedulerLoop();   // attach + block until Ctrl-C
        }
    }
}
```

`SchedulerBase` provides:
- A pre-created shared DSQ at `SHARED_DSQ_ID = 0`
- A default `init()` that creates that DSQ
- A default `dispatch()` that moves tasks from the shared DSQ to the local CPU queue
- A default `exit()` that captures the exit code for `getExitCode()`

You only need to override `enqueue()`.

## The `@Property` annotation

| Name | Default | Meaning |
|------|---------|---------|
| `sched_name` | `"hello"` | Name shown in `/sys/kernel/sched_ext/root/ops` |
| `timeout_ms` | `30000` | Watchdog: auto-detaches scheduler if any task is not dispatched for this long |
| `extra_flags` | `0` | Additional `SCX_OPS_*` flags, e.g. `"SCX_OPS_ENQ_MIGRATION_DISABLED"` |

```java
@Property(name = "sched_name",  value = "my_sched")
@Property(name = "timeout_ms",  value = "5000")
@Property(name = "extra_flags", value = "SCX_OPS_ENQ_MIGRATION_DISABLED")
public abstract class MyScheduler extends SchedulerBase { ... }
```

## DispatchQueue — typed DSQ wrapper

`DispatchQueue` is the primary API for working with DSQs (Dispatch Queues).  It is a
pure compile-time abstraction — no C struct is emitted; every method call is inlined by
the BPF compiler plugin at the call site.

### Creating a DSQ

```java
// Attach to an already-existing DSQ (e.g. the one SchedulerBase.init() created):
final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

// Create a new custom DSQ — scx_bpf_create_dsq() is automatically lifted to init():
static final long MY_DSQ = 1L;
final DispatchQueue myDsq = new DispatchQueue(MY_DSQ);

// Auto-assigned id (≥ 0x1_0000_0000, unique per program):
final DispatchQueue auto = new DispatchQueue();
```

When a `new DispatchQueue(id)` field is declared, the annotation processor automatically
injects the `scx_bpf_create_dsq(id, -1)` call into the program's `init()` method — you
don't need to write it yourself.

> **`init()` override required for `BPFProgram` subclasses**
>
> The prologue is injected into the `init()` method *declared* on the concrete `@BPF` class.
> If your scheduler extends `SchedulerBase`, its inherited `init()` qualifies automatically.
> If it extends `BPFProgram` directly, you **must** declare an explicit `init()` override —
> otherwise the `scx_bpf_create_dsq` call is never emitted and the scheduler detaches
> immediately after loading:
>
> ```java
> final DispatchQueue shared = new DispatchQueue(SHARED_DSQ_ID);
>
> @Override
> public int init() {
>     // scx_bpf_create_dsq(SHARED_DSQ_ID, -1) injected here by the compiler plugin.
>     return 0;
> }
> ```

### Inserting tasks (FIFO)

```java
// FIFO: explicit slice
shared.insert(p, SCX_SLICE_DFL.value(), EnqFlags.passThrough(enq_flags));

// FIFO: slice scaled by current queue depth (good default)
shared.insertScaled(p, EnqFlags.passThrough(enq_flags));

// Fast-path from selectCPU: skip enqueue/dispatch if CPU is idle
DispatchQueue.insertToLocalIfIdle(p, is_idle, SCX_SLICE_DFL.value());
```

### Inserting tasks (vtime / weighted-fair)

```java
// Explicit vtime — e.g. EDF: use absolute deadline as vtime key
shared.insertVtime(p, SCX_SLICE_DFL.value(), deadline, EnqFlags.passThrough(enq_flags));

// Clamped vtime (WFQ): prevents sleeping tasks from accumulating credit
shared.insertVtimeClamped(p, vtimeNow.get(), EnqFlags.passThrough(enq_flags));
```

**Never mix FIFO and vtime insertions on the same DSQ.**

### Dispatching

```java
@Override
public void dispatch(int cpu, Ptr<task_struct> prev) {
    shared.moveToLocal();   // move one task to the current CPU's local queue
}
```

### Inspection and timing

```java
shared.nonEmpty()          // true when tasks are waiting
shared.nrQueued()          // count of waiting tasks
DispatchQueue.now()        // current monotonic time in ns (scx_bpf_now())
DispatchQueue.nrCpuIds()   // number of possible CPU ids
```

### EnqFlags

`EnqFlags` wraps the raw `enq_flags` long from the `enqueue()` callback:

```java
EnqFlags f = EnqFlags.passThrough(enq_flags); // wrap kernel-supplied flags
EnqFlags f = EnqFlags.empty();                // no flags
boolean isWakeup = f.isWakeup();              // SCX_ENQ_WAKEUP set?
boolean isLast   = f.isLast();                // last runnable task on this CPU?
```

### Built-in DSQs

```java
DispatchQueue.local()          // SCX_DSQ_LOCAL — current CPU's local queue
DispatchQueue.localOn(cpu)     // SCX_DSQ_LOCAL_ON | cpu
DispatchQueue.global()         // SCX_DSQ_GLOBAL
```

### KickFlags

`KickFlags` wraps the flags argument of `DispatchQueue.kickCpu()`:

```java
DispatchQueue.kickCpu(nestCpu, KickFlags.idle());     // wake only if idle
DispatchQueue.kickCpu(cpu,     KickFlags.preempt());  // preempt whatever is running
DispatchQueue.kickCpu(cpu,     KickFlags.idle().or(KickFlags.waitForKick()));
```

| Factory | C value | Meaning |
|---------|---------|---------|
| `KickFlags.none()` | `0` | No flags |
| `KickFlags.idle()` | `SCX_KICK_IDLE` | Wake only if the CPU is idle |
| `KickFlags.preempt()` | `SCX_KICK_PREEMPT` | Preempt whatever is running |
| `KickFlags.waitForKick()` | `SCX_KICK_WAIT` | Wait for the kick to be processed |

### DSQ iteration

Iterate over all tasks in a DSQ — useful for work-stealing or re-prioritisation:

```java
import me.bechberger.ebpf.bpf.BPFJ;
import static me.bechberger.ebpf.runtime.ScxDefinitions.bpf_iter_scx_dsq;

// Forward iteration (lowest vtime first):
shared.forEach(it, p -> {
    if (!CpuMask.ofTask(p).test(cpu)) return; // skip affinity-constrained tasks
    shared.moveFrom(it, p, EnqFlags.empty());
    BPFJ._break();
});

// Reverse iteration (highest vtime first):
shared.forEachReverse(it, p -> {
    shared.moveFrom(it, p, EnqFlags.empty());
    BPFJ._break();
});
```

`BPFJ._break()` and `BPFJ._continue()` work inside the lambda body.
The iterator `it` is available for `moveFrom`, `moveFromVtime`, `setMoveSlice`, and
`setMoveVtime`.

## CpuMask — typed CPU affinity wrapper

`CpuMask` wraps a read-only `const struct cpumask *`.  It is a pure compile-time
abstraction (`@BPFAbstraction`) that must be used as a **local variable** inside a
`@BPFFunction` body — never as a class field.

**Always release borrowed masks** with `releaseIdle()` or `release()` when done.

```java
import me.bechberger.ebpf.bpf.sched.CpuMask;

@Override
public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
    // Pick any idle CPU from the idle mask
    CpuMask idle = CpuMask.idle();
    int cpu = idle.pickIdle(0);
    idle.releaseIdle();            // always release

    if (cpu >= 0) return cpu;
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(false));
}
```

### Factories

| Factory | Release needed | C expression |
|---------|---------------|-------------|
| `CpuMask.idle()` | `releaseIdle()` | `scx_bpf_get_idle_cpumask()` |
| `CpuMask.idleSmt()` | `releaseIdle()` | `scx_bpf_get_idle_smtmask()` |
| `CpuMask.idleOnNode(n)` | `releaseIdle()` | `scx_bpf_get_idle_cpumask_node(n)` |
| `CpuMask.online()` | `release()` | `scx_bpf_get_online_cpumask()` |
| `CpuMask.possible()` | `release()` | `scx_bpf_get_possible_cpumask()` |
| `CpuMask.ofTask(p)` | none | `p->cpus_ptr` |

### Operations

```java
CpuMask idle = CpuMask.idle();

idle.test(cpu)          // true if cpu is set
idle.weight()           // number of set CPUs
idle.first()            // lowest-numbered set CPU
idle.isEmpty()          // true if no CPUs set
idle.intersects(other)  // true if at least one CPU in common
idle.pickIdle(0)        // pick and claim an idle CPU, or -EBUSY
idle.pickAny(0)         // pick any CPU, preferring idle ones

idle.releaseIdle();     // release — always call when done
```

### Checking task affinity

`CpuMask.ofTask(p)` gives a direct view into the task's `cpus_ptr` — no release needed:

```java
CpuMask allowed = CpuMask.ofTask(p);
if (allowed.test(cpu)) {
    // task can run on this cpu
}
```

### Nest-CPU example (selectCPU + dispatch + tick)

```java
@Override
public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
    CpuMask idle = CpuMask.idle();
    int nestCpu = findIdleNestCpu(idle);
    idle.releaseIdle();
    if (nestCpu >= 0) {
        DispatchQueue.localOn(nestCpu).insert(p, SCX_SLICE_DFL.value(), EnqFlags.empty());
        return nestCpu;
    }
    boolean is_idle = false;
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
}

@Override
public void dispatch(int cpu, Ptr<task_struct> prev) {
    shared.moveToLocal();
    Ptr<Integer> nestFlag = inNest.bpf_get(cpu);
    if (nestFlag != null && nestFlag.val() == 0) {
        CpuMask idle = CpuMask.idle();
        int nestCpu = findIdleNestCpu(idle);
        idle.releaseIdle();
        if (nestCpu >= 0) {
            DispatchQueue.kickCpu(nestCpu, KickFlags.idle());
        }
    }
}
```

See `NestScheduler` in `bpf-samples/` for the full runnable example.

## Key scx kfuncs (low-level, use DispatchQueue instead)

The raw kfuncs are still accessible directly when you need them.  Prefer `DispatchQueue`
for new code.

| Function | DispatchQueue equivalent |
|----------|--------------------------|
| `scx_bpf_dsq_insert(p, id, slice, flags)` | `dsq.insert(p, slice, flags)` |
| `scx_bpf_dsq_insert_vtime(p, id, slice, vtime, flags)` | `dsq.insertVtime(p, slice, vtime, flags)` |
| `scx_bpf_dsq_move_to_local(id)` | `dsq.moveToLocal()` |
| `scx_bpf_select_cpu_dfl(p, prev, flags, &idle)` | still used directly |
| `scx_bpf_create_dsq(id, node)` | auto-lifted from `new DispatchQueue(id)` |
| `scx_bpf_destroy_dsq(id)` | `dsq.destroy()` |
| `scx_bpf_dsq_nr_queued(id)` | `dsq.nrQueued()` / `dsq.nonEmpty()` |
| `scx_bpf_kick_cpu(cpu, flags)` | `DispatchQueue.kickCpu(cpu, KickFlags.idle())` |
| `scx_bpf_now()` | `DispatchQueue.now()` |
| `scx_bpf_cpuperf_set(cpu, perf)` | `DispatchQueue.cpuperfSet(cpu, perf)` |
| `scx_bpf_task_cpu(p)` | still used directly |
| `scx_bpf_nr_cpu_ids()` | `DispatchQueue.nrCpuIds()` |

Helper methods available on any `Scheduler` implementor (no import needed):

**CPU selection**
- `selectCpuDfl(p, prev_cpu, wake_flags)` — default idle-CPU selection; returns CPU, no pre-dispatch (safe for vtime DSQs)
- `selectCpuDefault(p, prev_cpu, wake_flags)` — like `selectCpuDfl` but pre-dispatches to `SCX_DSQ_LOCAL` if idle
- `selectCpuFifoIdleOrFallback(p, prev_cpu, wake_flags, dsq_id)` — idle-CPU selection + fast-path local dispatch (FIFO DSQs only)

**Enqueue helpers (deprecated — prefer `DispatchQueue`)**
- `dsqInsert(p, enq_flags)` — *deprecated*; use `shared.insertScaled(p, EnqFlags.passThrough(enq_flags))`
- `vtimeEnqueue(p, enq_flags, vtime_now)` — *deprecated*; use `shared.insertVtimeClamped(p, vtimeNow, EnqFlags.passThrough(enq_flags))`

**Stopping / charging**
- `vtimeCharge(p)` — charge elapsed slice to `p.scx.dsq_vtime`
- `scaleByTaskWeight(p, value)` — scale `value` inversely by task weight (useful for vtime accounting)

**Filtering**
- `hasSchedulingConstraints(p)` — true if the task has cpumask/affinity constraints; fast-path it to avoid DSQ starvation
- `isDescendantOf(p, targetTgid)` — true if `p` is in the process group rooted at `targetTgid`
- `isMigrationDisabled(p)` — true if the task cannot migrate between CPUs

**Iteration**
- `bpf_for_each_dsq(dsq_id, iter, flags, lambda)` — iterate over tasks in a DSQ (read-only)
- `tryDispatchToLocalCpu(iter, p, dsq_id, vtime, enq_flags)` — dispatch a specific task from a DSQ iteration

**Comparison**
- `isSmaller(a, b)` — unsigned less-than; required for correct vtime comparisons on 64-bit wraparound

## Scheduler callback reference

| Method | Required | Description |
|--------|----------|-------------|
| `enqueue(p, flags)` | **Yes** | Task becomes runnable; insert it into a DSQ |
| `dispatch(cpu, prev)` | **Yes** (if not using `SchedulerBase`) | CPU needs work; move tasks from DSQs to local |
| `init()` | No | Called once at load; create DSQs here |
| `exit(ei)` | No | Called when the scheduler is detached |
| `selectCPU(p, prev_cpu, wake_flags)` | No | Choose which CPU to wake for this task |
| `runnable(p, flags)` | No | Task became runnable (before `enqueue`) |
| `running(p)` | No | Task is about to execute on CPU |
| `stopping(p, runnable)` | No | Task left the CPU |
| `enable(p)` | No | Task entered SCX scheduling |
| `disable(p)` | No | Task left SCX scheduling |
| `tick(p)` | No | Periodic callback (every 1/HZ seconds) |
| `initTask(p, args)` | No | New task created; initialize per-task state |
| `exitTask(p, args)` | No | Task leaving the scheduler; free per-task state created in `initTask` |
| `dequeue(p, flags)` | No | Task removed from scheduler (e.g. priority change) |
| `runnable(p, flags)` | No | Task became runnable (counterpart to `quiescent`) |
| `quiescent(p, flags)` | No | Task became blocked/quiescent (counterpart to `runnable`) |
| `updateIdle(cpu, idle)` | No | CPU idle state changed |
| `cpuAcquire(cpu, args)` | No | CPU returned to SCX after preemption |
| `cpuRelease(cpu, args)` | No | CPU preempted by RT/deadline task; call `scx_bpf_reenqueue_local()` |
| `cpuOnline(cpu)` | No | CPU came online (hotplug) |
| `cpuOffline(cpu)` | No | CPU went offline (hotplug) |
| `yield(from, to)` | No | Task called `sched_yield()`; return `true` to honour, `false` to ignore |
| `setWeight(p, weight)` | No | Task scheduling weight changed (e.g. `setpriority(2)`) |
| `setCpumask(p, cpumask)` | No | Task CPU affinity changed (e.g. `sched_setaffinity(2)`) |
| `coreSchedBefore(a, b)` | No | Core scheduling priority: return `true` if `a` should run before `b` on a shared physical core |
| `dump(ctx)` | No | Global scheduler state dump (sched-ext debug interface) |
| `dumpCpu(ctx, cpu, idle)` | No | Per-CPU state dump |
| `dumpTask(ctx, p)` | No | Per-task state dump |

Cgroup-aware schedulers can also implement `cgroupInit`, `cgroupExit`, `cgroupPrepMove`,
`cgroupCancelMove`, `cgroupMove`, `cgroupSetWeight`, and `cgroupSetBandwidth`.

Callbacks are ordinary Java method overrides — no `@BPFFunction` needed.
The annotation processor generates all necessary BPF struct_ops wiring.

## Stats and observability

Use `SchedulerStats` to add per-CPU enqueue/dispatch counters with a few lines:

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "my_sched")
public abstract class MyScheduler extends SchedulerBase implements Scheduler {

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> enqueuedCounts;

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> dispatchedCounts;

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
        SchedulerStats.incrementEnqueued(enqueuedCounts);    // BPF-side
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();
        SchedulerStats.incrementDispatched(dispatchedCounts); // BPF-side
    }

    // Java-side reads
    public long getTotalEnqueued()   { return SchedulerStats.totalEnqueued(enqueuedCounts); }
    public long getTotalDispatched() { return SchedulerStats.totalDispatched(dispatchedCounts); }
}
```

Use `GlobalVariable<T>` for any other BPF ↔ Java shared state:

```java
final GlobalVariable<Boolean> fifoMode = new GlobalVariable<>(true);

// In BPF: read/write via fifoMode.get() / fifoMode.set(v)
// In Java: same API — read/write from user space while the scheduler is running
```

## Per-task storage

Use `BPFTaskStorage<T>` for per-task metadata (kernel-managed, safe under concurrent
task creation/destruction):

```java
@Type
record TaskCtx(long vruntime) {}

@BPFMapDefinition(maxEntries = 1)
BPFTaskStorage<TaskCtx> taskCtx;

final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

@Override
public void enable(Ptr<task_struct> p) {
    taskCtx.bpf_task_storage_get(p, new TaskCtx(vtimeNow.get()),
            BPF_LOCAL_STORAGE_GET_F_CREATE);
}

@Override
public void enqueue(Ptr<task_struct> p, long enq_flags) {
    EnqFlags f = EnqFlags.passThrough(enq_flags);
    Ptr<TaskCtx> ctx = taskCtx.bpf_task_storage_get(p, null, 0);
    if (ctx == null) {
        shared.insertScaled(p, f);
        return;
    }
    shared.insertVtime(p, SCX_SLICE_DFL.value(), ctx.val().vruntime(), f);
}
```

Or use a plain `BPFHashMap<Integer, TaskCtx>` keyed by `p.val().pid` if you prefer
explicit map management.

## Loading and running

```java
// Attach and block until the user presses Ctrl-C:
try (var sched = BPFProgram.load(MyScheduler.class)) {
    sched.runSchedulerLoop();
}
// Closing the program atomically restores the previous scheduler.

// Or manual lifecycle (useful for tests):
try (var sched = BPFProgram.load(MyScheduler.class)) {
    sched.attachScheduler();
    System.out.println(sched.isSchedulerAttachedProperly()); // true
    Thread.sleep(5000);
}  // detaches on close
```

Check attachment status (e.g. verify watchdog hasn't fired):

```java
sched.isSchedulerAttachedProperly()          // reads /sys/kernel/sched_ext/root/ops
sched.waitWhileSchedulerIsAttachedProperly() // blocks until detached
```

> **Danger — scheduler bugs can hang the system**
>
> If `enqueue()` never inserts a task, or `dispatch()` never consumes one, tasks starve
> and the system may become unresponsive. Always test in a VM first (e.g. via `vng`).
> The `timeout_ms` watchdog auto-detaches a misbehaving scheduler, but only after the
> timeout elapses — during which the system may be sluggish.

## Exit info

`SchedulerBase` captures the kernel's exit code when the scheduler is detached. After
`runSchedulerLoop()` returns (or after closing the program), you can inspect it:

```java
try (var sched = BPFProgram.load(MyScheduler.class)) {
    sched.runSchedulerLoop();
    long code = sched.getExitCode();
    // 0 = normal exit; non-zero = error (e.g. watchdog stall)
}
```

Override `onSchedulerExit(long exitCode)` to react inline:

```java
@Override
public void onSchedulerExit(long exitCode) {
    if (exitCode != 0) {
        System.err.println("Scheduler exited with error: 0x" + Long.toHexString(exitCode));
    }
}
```

The default implementation logs a warning when the exit code is non-zero.

> **Note:** `SCX_EXIT_ERROR_STALL` in the exit code means the watchdog fired
> (the scheduler did not dispatch for `timeout_ms` milliseconds).

## PerCpuSchedulerBase — per-CPU DSQ layout

`PerCpuSchedulerBase` extends `SchedulerBase` with one dedicated DSQ per logical CPU
plus the shared fallback DSQ:

```
CPU 0 DSQ (id = PER_CPU_DSQ_BASE + 0)  ─┐
CPU 1 DSQ (id = PER_CPU_DSQ_BASE + 1)  ─┤─ drained first by dispatch()
...                                      ─┘
Shared DSQ (id = SHARED_DSQ_ID = 0)   ──── fallback if per-CPU DSQ is empty
```

`dispatch()` drains the per-CPU DSQ for the calling CPU first; if empty, it falls back to
the shared DSQ.

Use `dsqInsertLocal(p, enq_flags)` to insert into the DSQ of the CPU that `p` is currently
pinned to. Use the inherited `dsqInsert(p, enq_flags)` for migratable tasks that can run
anywhere.

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "my_per_cpu_sched")
public abstract class MyScheduler extends PerCpuSchedulerBase implements Scheduler {

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        if (isMigrationDisabled(p)) {
            dsqInsertLocal(p, enq_flags);   // stays on its CPU
        } else {
            dsqInsert(p, enq_flags);        // can migrate freely
        }
    }
}
```

See `PerCpuSchedulerSample` in `bpf-samples/` for a runnable example.

## Boosting a process tree for performance testing

`BoostedScheduler` gives nominated process trees maximum scheduling priority
and long time slices, while everything else gets normal weighted-fair scheduling.
Priority and the set of boosted processes can be changed at any time while the
scheduler is running.

### How it works

Two vtime-ordered DSQs sit behind every `dispatch()` call:

```
BOOSTED_DSQ (id 1) ─── always drained first
NORMAL_DSQ  (id 2) ─── drained only when BOOSTED_DSQ is empty
```

When boost mode is active, `enqueue()` checks whether the task belongs to any
registered process tree via `isBoosted()`:

```java
EnqFlags f = EnqFlags.passThrough(enq_flags);
if (boostEnabled.get() && isBoosted(p)) {
    // vtime=0 sorts boosted tasks ahead of every normal task
    boosted.insertVtime(p, BOOSTED_SLICE_NS, 0, f);
} else {
    // standard weighted-fair insert into the normal DSQ
    normal.insertVtimeClamped(p, vtimeNow.get(), f);
}
```

`isBoosted()` walks up the `real_parent` chain (up to 8 levels, bounded for the
BPF verifier) and checks each ancestor's `tgid` against the `boostedTgids` map.
Registering a TGID automatically covers every thread in that group **and** any
child processes it forks.

### Usage from a test harness

```java
try (var sched = BPFProgram.load(BoostedScheduler.class)) {
    // Register the process tree to boost.
    // Use the TGID (= group-leader PID = what getpid(2) returns).
    sched.boostTgid((int) ProcessHandle.current().pid());
    sched.setBoostEnabled(true);
    sched.attachScheduler();

    runBenchmark();   // this JVM and all its children run at max priority

    sched.setBoostEnabled(false);   // instant — no restart needed
    sched.clearBoostedTgids();
}
```

`setBoostEnabled(false)` writes to a `GlobalVariable<Boolean>` BPF map; the
next `enqueue()` call in the kernel sees the new value immediately, so normal
fair scheduling resumes without any detach/reload cycle.

### Java-side API

| Method | Description |
|--------|-------------|
| `boostTgid(int tgid)` | Add a TGID (and its whole descendant tree) to the boost set |
| `unboostTgid(int tgid)` | Remove a TGID from the boost set |
| `clearBoostedTgids()` | Remove all boosted TGIDs |
| `setBoostEnabled(boolean)` | Enable or disable boost mode at runtime |
| `isBoostEnabled()` | Return current boost mode state |

### Caveats

- While boost mode is active, boosted tasks can starve normal tasks if they
  keep all CPUs busy — keep boost windows short (the duration of your benchmark).
- `boostedTgids` holds at most 64 entries (`MAX_BOOSTED`); attempting to insert
  more silently fails at the BPF map level.
- The 20 ms slice (`BOOSTED_SLICE_NS`) minimises context-switch overhead during
  tight loops. Adjust the constant if your workload needs coarser or finer
  granularity.

## Inspecting generated BPF C code

The compiler plugin translates your Java scheduler into BPF C before loading.
To see the generated code without root:

```java
BPFProgram.printCode(MyScheduler.class);   // prints to stdout
```

Or at load time via an environment variable:

```bash
BPF_PRINT_CODE=1 sudo ./run.sh MyScheduler
```

This is useful for debugging compiler plugin output or verifying that helper methods
are being inlined correctly.

## Sample schedulers

Eighteen ready-to-run schedulers are available in
`bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/`:

| Class | Strategy | Highlights |
|-------|----------|-----------|
| `MinimalScheduler` | FIFO | Fewest lines; only `enqueue()` needed |
| `SimpleScheduler` | FIFO / vtime | Runtime-switchable; stats tracking |
| `VTimeScheduler` | Weighted fair queuing | Idle budget clamping |
| `FCFSScheduler` | FIFO | First-come first-served |
| `LotteryScheduler` | Random slice | Proportional via random time slices |
| `PriorityScheduler` | Weight-based queues | 5 DSQs mapped by task weight |
| `CPU0Scheduler` | Single-core | All work concentrated on CPU 0 |
| `PrevCpuScheduler` | Sticky CPUs | Bias towards last-used CPU |
| `CentralScheduler` | Central DSQ | Centralised dispatch |
| `DeadlineScheduler` | EDF | Earliest-deadline-first via per-task storage |
| `SMTPairScheduler` | SMT pairing | Related tasks on sibling threads |
| `NestScheduler` | Hierarchical | Nested DSQ group scheduling |
| `TaskStorageScheduler` | vtime + per-task | `BPFTaskStorage<T>` demo |
| `RunnableScheduler` | FIFO | `runnable()` callback + migration disabled |
| `FlowScheduler` | Work-conserving | Port of `scx_flow`; weight-based CPU affinity |
| `ChaosScheduler` | Fuzzing | Random vtimes, CPU throttling, per-task state machine |
| `PerCpuSchedulerSample` | Per-CPU FIFO | `PerCpuSchedulerBase` demo; pinned vs migratable routing |
| `BoostedScheduler` | Priority boost | Nominated process trees get max priority + long slices; runtime toggle |
