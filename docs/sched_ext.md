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

## Implementing a scheduler — quick start

The minimal requirement is three annotations and one method:

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.SchedulerBase;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

@BPF(license = "GPL")
@Property(name = "sched_name", value = "my_scheduler")
public abstract class MyScheduler extends SchedulerBase {   // ← extend SchedulerBase

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        dsqInsert(p, enq_flags);   // insert into the shared FIFO DSQ
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(MyScheduler.class)) {
            prog.runSchedulerLoop();   // attach + block until detached
        }
    }
}
```

`SchedulerBase` provides:
- A pre-created shared DSQ at `SHARED_DSQ_ID = 0`
- A default `init()` that creates that DSQ
- A default `dispatch()` that moves tasks from the shared DSQ to the local CPU queue

You only need to override `enqueue()`.

## The `@Property` annotation

| Name | Default | Meaning |
|------|---------|---------|
| `sched_name` | `"hello"` | Name shown in `/sys/kernel/sched_ext/root/ops` |
| `timeout_ms` | `30000` | Watchdog: auto-detaches scheduler if it blocks for this long |
| `extra_flags` | `0` | Additional `SCX_OPS_*` flags, e.g. `"SCX_OPS_ENQ_MIGRATION_DISABLED"` |

```java
@Property(name = "sched_name",  value = "my_sched")
@Property(name = "timeout_ms",  value = "5000")
@Property(name = "extra_flags", value = "SCX_OPS_ENQ_MIGRATION_DISABLED")
public abstract class MyScheduler extends SchedulerBase { ... }
```

## DSQ — Dispatch Queue

The DSQ (Dispatch Queue) is the fundamental unit of the sched_ext scheduling model.

```
Task becomes runnable
        │
        ▼
  enqueue(task, flags)     ← you call scx_bpf_dsq_insert(task, dsq_id, ...)
        │
        ▼
   Your DSQ(s)
        │
        ▼
  dispatch(cpu, prev)      ← you call scx_bpf_dsq_move_to_local(dsq_id)
        │
        ▼
  CPU local DSQ  →  task runs
```

Built-in DSQ IDs:
- `SCX_DSQ_GLOBAL` — single global queue shared by all CPUs
- `SCX_DSQ_LOCAL` — current CPU's local queue (for immediate dispatch)
- Custom IDs: any value 0–(2⁶³−1) that doesn't use the reserved high bits

Create custom DSQs in `init()`:

```java
@Override
public int init() {
    return scx_bpf_create_dsq(MY_DSQ_ID, -1);  // -1 = any NUMA node
}
```

## Key scx kfuncs

| Function | Description |
|----------|-------------|
| `scx_bpf_dsq_insert(p, dsq_id, slice_ns, flags)` | Insert task into a DSQ with a time slice |
| `scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns, vtime, flags)` | Insert with virtual time (WFQ) |
| `scx_bpf_dsq_move_to_local(dsq_id)` | Move one task from DSQ to current CPU's local queue |
| `scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, is_idle)` | Default idle-preferring CPU selection |
| `scx_bpf_create_dsq(dsq_id, numa_node)` | Create a custom DSQ |
| `scx_bpf_destroy_dsq(dsq_id)` | Destroy a custom DSQ |
| `scx_bpf_dsq_nr_queued(dsq_id)` | Number of tasks currently in a DSQ |
| `scx_bpf_kick_cpu(cpu, flags)` | Wake up a specific CPU |

Helper methods available on any `Scheduler` implementor (no import needed):

**CPU selection**
- `selectCpuDfl(p, prev_cpu, wake_flags)` — default idle-CPU selection; returns CPU, no pre-dispatch (safe for vtime DSQs)
- `selectCpuDefault(p, prev_cpu, wake_flags)` — like `selectCpuDfl` but pre-dispatches to `SCX_DSQ_LOCAL` if idle
- `selectCpuFifoIdleOrFallback(p, prev_cpu, wake_flags, dsq_id)` — idle-CPU selection + fast-path local dispatch (FIFO DSQs only; do not use with vtime DSQs)

**Enqueue helpers**
- `dsqInsert(p, enq_flags)` — insert into `SHARED_DSQ_ID` with auto-scaled slice
- `vtimeEnqueue(p, enq_flags, vtime_now)` — vtime-ordered insert with idle budget clamping

**Stopping / charging**
- `vtimeCharge(p)` — charge elapsed slice to `p.scx.dsq_vtime`

**Filtering**
- `hasSchedulingConstraints(p)` — true if the task has cpumask/affinity constraints; fast-path it to avoid DSQ starvation
- `isDescendantOf(p, targetTgid)` — true if `p` is in the process group rooted at `targetTgid`

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
| `dequeue(p, flags)` | No | Task removed from scheduler (e.g. priority change) |
| `updateIdle(cpu, idle)` | No | CPU idle state changed |
| `cpuAcquire(cpu, args)` | No | CPU returned to SCX after preemption |
| `cpuRelease(cpu, args)` | No | CPU preempted by RT/deadline task; call `scx_bpf_reenqueue_local()` |
| `yield(from, to)` | No | Task called `sched_yield()`; return `true` to honour, `false` to ignore |
| `setWeight(p, weight)` | No | Task scheduling weight changed (e.g. `setpriority(2)`) |
| `setCpumask(p, cpumask)` | No | Task CPU affinity changed (e.g. `sched_setaffinity(2)`) |

Callbacks are ordinary Java method overrides — no `@BPFFunction` needed.
The annotation processor generates all necessary BPF struct_ops wiring.

## Stats and observability

Use `SchedulerStats` to add per-CPU enqueue/dispatch counters with a few lines:

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "my_sched")
public abstract class MyScheduler extends SchedulerBase {

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> enqueuedCounts;

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> dispatchedCounts;

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        dsqInsert(p, enq_flags);
        SchedulerStats.incrementEnqueued(enqueuedCounts);    // BPF-side
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        super.dispatch(cpu, prev);
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
// In Java: same API — read/write from user space
```

## Per-task storage

Use `BPFTaskStorage<T>` for per-task metadata (kernel-managed, safe under concurrent
task creation/destruction):

```java
@Type
record TaskCtx(long vruntime) {}

@BPFMapDefinition(maxEntries = 1)
BPFTaskStorage<TaskCtx> taskCtx;

@Override
public void enable(Ptr<task_struct> p) {
    taskCtx.bpf_task_storage_get(p, new TaskCtx(vtimeNow.get()),
            BPF_LOCAL_STORAGE_GET_F_CREATE);
}

@Override
public void enqueue(Ptr<task_struct> p, long enq_flags) {
    Ptr<TaskCtx> ctx = taskCtx.bpf_task_storage_get(p, null, 0);
    if (ctx == null) {
        dsqInsert(p, enq_flags);
        return;
    }
    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ_ID, SCX_SLICE_DFL.value(),
            ctx.val().vruntime(), enq_flags);
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
sched.isSchedulerAttachedProperly()         // reads /sys/kernel/sched_ext/root/ops
sched.waitWhileSchedulerIsAttachedProperly() // blocks until detached
```

> **Danger — scheduler bugs can hang the system**
>
> If `enqueue()` never inserts a task, or `dispatch()` never consumes one, tasks starve
> and the system may become unresponsive. Always test in a VM first (e.g. via `vng`).
> The `timeout_ms` watchdog auto-detaches a misbehaving scheduler, but it only fires
> after the timeout elapses — during which the system may be sluggish.

## Sample schedulers

Fifteen ready-to-run schedulers are available in
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
| `ChaosScheduler` | Fuzzing | Random vtimes, CPU throttling, per-task state machine |
