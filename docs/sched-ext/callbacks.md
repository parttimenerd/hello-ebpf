# sched_ext — Callback Reference

**Javadoc:** [`Scheduler`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/Scheduler.html) · [`SchedulerBase`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/SchedulerBase.html) · [`DispatchQueue`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/sched/DispatchQueue.html)  
**BPF reference:** [sched_ext_ops — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/sched_ext_ops/) · [sched-ext kernel docs](https://docs.kernel.org/scheduler/sched-ext.html)  
**Source:** [`Scheduler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java) · [`SchedulerBase.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/SchedulerBase.java)  
**See also:** [Overview](index.md) · [Writing a Scheduler](guide.md) · [Cookbook](cookbook.md)

## How callbacks work

Every sched_ext scheduler is a Java class that extends `SchedulerBase` and implements the
`Scheduler` interface (which wraps the kernel's `sched_ext_ops` struct_ops). Each method
you override in Java becomes a BPF callback wired into the kernel at load time. The
annotation processor generates the struct_ops skeleton and all glue code automatically —
you do not annotate callback overrides with `@BPFFunction`. Method names follow a strict
camelCase-to-snake_case mapping: `selectCPU` becomes `select_cpu`, `initTask` becomes
`init_task`, and so on.

The minimal scheduler overrides exactly two methods: `enqueue` and `dispatch`. Everything
else is optional. `SchedulerBase` provides working default implementations for `dispatch`
and `init`, so many schedulers only need to override `enqueue`.

---

## Callback reference table

| Method | Required | Description |
|--------|----------|-------------|
| `enqueue(p, flags)` | **Yes** | Task becomes runnable; insert it into a DSQ |
| `dispatch(cpu, prev)` | **Yes** (if not using `SchedulerBase`) | CPU needs work; move tasks from DSQs to the local DSQ |
| `init()` | No | Called once at load; create DSQs here |
| `exit(ei)` | No | Called when the scheduler is detached |
| `selectCPU(p, prev_cpu, wake_flags)` | No | Choose which CPU to wake for this task |
| `runnable(p, flags)` | No | Task became runnable (fires before `enqueue`) |
| `running(p)` | No | Task is about to execute on a CPU |
| `stopping(p, runnable)` | No | Task left the CPU |
| `enable(p)` | No | Task entered SCX scheduling |
| `disable(p)` | No | Task left SCX scheduling |
| `tick(p)` | No | Periodic callback (fires roughly every 1/HZ seconds) |
| `initTask(p, args)` | No | New task created; initialize per-task state |
| `exitTask(p, args)` | No | Task exiting; free per-task state created in `initTask` |
| `dequeue(p, flags)` | No | Task removed from the scheduler (e.g. priority change) |
| `quiescent(p, flags)` | No | Task became blocked; counterpart to `runnable` |
| `updateIdle(cpu, idle)` | No | CPU idle state changed |
| `cpuAcquire(cpu, args)` | No | CPU returned to SCX after being preempted |
| `cpuRelease(cpu, args)` | No | CPU preempted by RT/deadline task; call `scx_bpf_reenqueue_local()` |
| `cpuOnline(cpu)` | No | CPU came online (hotplug) |
| `cpuOffline(cpu)` | No | CPU went offline (hotplug) |
| `yield(from, to)` | No | Task called `sched_yield()`; return `true` to honour, `false` to ignore |
| `setWeight(p, weight)` | No | Task scheduling weight changed (e.g. via `setpriority(2)`) |
| `setCpumask(p, cpumask)` | No | Task CPU affinity changed (e.g. via `sched_setaffinity(2)`) |
| `coreSchedBefore(a, b)` | No | Core scheduling: return `true` if `a` should run before `b` on a shared physical core |
| `dump(ctx)` | No | Global scheduler state dump (sched-ext debug interface) |
| `dumpCpu(ctx, cpu, idle)` | No | Per-CPU state dump |
| `dumpTask(ctx, p)` | No | Per-task state dump |

Cgroup-aware schedulers can additionally implement `cgroupInit`, `cgroupExit`,
`cgroupPrepMove`, `cgroupCancelMove`, `cgroupMove`, `cgroupSetWeight`, and
`cgroupSetBandwidth`. See the [sched-ext overview](index.md) for details.

---

## The core loop: enqueue and dispatch

These two callbacks are the heart of every scheduler. The kernel calls `enqueue` whenever
a task becomes runnable and calls `dispatch` whenever a CPU runs out of work.

### enqueue

`enqueue` receives a pointer to the task (`p`) and a flags bitmask. Its only
responsibility is to place the task into a dispatch queue (DSQ). If `enqueue` returns
without inserting the task, the sched_ext watchdog detects the stall and detaches the
scheduler.

The simplest implementation inserts every task into the global shared DSQ:

```java
@Override
public void enqueue(Ptr<task_struct> p, long flags) {
    scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, flags);
}
```

A scheduler with its own DSQ (id stored in `SHARED_DSQ`) inserts there instead:

```java
@Override
public void enqueue(Ptr<task_struct> p, long flags) {
    scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, flags);
}
```

### dispatch

`dispatch` receives the id of the CPU that needs work and a pointer to the task that just
stopped running (`prev`, may be null). Its job is to move tasks from a DSQ into the
CPU's local DSQ so the kernel can execute them.

`SchedulerBase` provides a default implementation that consumes from `SCX_DSQ_GLOBAL`,
which is sufficient for most simple schedulers. Override it when you maintain your own
DSQs:

```java
@Override
public void dispatch(int cpu, Ptr<task_struct> prev) {
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}
```

For round-robin or weighted dispatch across multiple DSQs, call
`scx_bpf_dsq_move_to_local` once per DSQ until the local queue is satisfied.

---

## Lifecycle: init and exit

### init

`init` is annotated `@Sleepable` by `SchedulerBase`, which means it runs in a sleepable
BPF context and may call helpers that can block. This is the correct place to create
custom DSQs and initialize global state.

```java
@Override
@Sleepable
public int init() {
    int rc = super.init();
    if (rc != 0) return rc;
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}
```

`super.init()` sets up the built-in DSQs used by `SchedulerBase`; call it first unless
you are managing everything yourself.

### exit

`exit` receives a pointer to an `scx_exit_info` struct with two useful fields: `.reason`
(an integer code) and `.msg` (a null-terminated string describing why the scheduler was
detached). Use them for diagnostics or clean shutdown logic.

```java
@Override
public void exit(Ptr<scx_exit_info> ei) {
    int reason = ei.val().reason;
    BPFHelpers.bpf_printk("scheduler exiting, reason=%d", reason);
}
```

---

## Per-task state: initTask and exitTask

`initTask` and `exitTask` are the BPF equivalent of per-task memory allocation. The
kernel calls `initTask` when a task first enters SCX scheduling and `exitTask` when it
leaves. Use a `BPFHashMap` keyed by PID (the task's `pid` field, typed `int` but stored
as `long` to fit the map key type) to associate state with each task.

```java
@BPFMapDefinition(maxEntries = 4096)
BPFHashMap<Integer, TaskData> taskData = BPFHashMap.newInstance();

@Override
public void initTask(Ptr<task_struct> p, Ptr<scx_init_task_args> args) {
    TaskData td = new TaskData();
    td.vruntime = 0;
    taskData.bpf_put(p.val().pid, td);
}

@Override
public void exitTask(Ptr<task_struct> p, Ptr<scx_exit_task_args> args) {
    taskData.bpf_delete(p.val().pid);
}
```

Failing to clean up in `exitTask` leaks map entries. BPF hash maps have a fixed maximum
size set at creation time, so leaks eventually cause `bpf_put` to fail with `-E2BIG`.

---

## CPU lifecycle callbacks

### Hotplug: cpuOnline and cpuOffline

`cpuOnline` fires when a CPU is brought online and `cpuOffline` fires just before one
goes offline. Use these to adjust bitmasks or per-CPU data structures that track which
CPUs are available for scheduling.

```java
@Override
public void cpuOnline(int cpu) {
    BPFHelpers.bpf_printk("cpu %d online", cpu);
}

@Override
public void cpuOffline(int cpu) {
    BPFHelpers.bpf_printk("cpu %d offline", cpu);
}
```

### RT preemption: cpuAcquire and cpuRelease

`cpuRelease` fires when a real-time or deadline task preempts a CPU away from SCX.
Any tasks that were queued in that CPU's local DSQ are stranded; call
`scx_bpf_reenqueue_local()` to move them back to a global or shared DSQ so other CPUs
can pick them up.

`cpuAcquire` fires when the CPU is returned to SCX after the RT task finishes. Use it
to re-seed the CPU's local DSQ if your scheduler maintains per-CPU state.

```java
@Override
public void cpuRelease(int cpu, Ptr<scx_cpu_release_args> args) {
    scx_bpf_reenqueue_local();
}
```

---

## Cgroup callbacks

Schedulers that participate in cgroup-based resource control implement a second set of
callbacks: `cgroupInit`, `cgroupExit`, `cgroupPrepMove`, `cgroupCancelMove`,
`cgroupMove`, `cgroupSetWeight`, and `cgroupSetBandwidth`. These mirror the cgroup
lifecycle (creation, destruction, task migration, and weight/bandwidth updates) and
receive pointers to the relevant `cgroup` and task structs alongside a flags or weight
argument.

Cgroup support requires the scheduler to declare it at load time. See the
[sched-ext overview](index.md) for the full setup and an annotated example.

---

*Next: [Cookbook](cookbook.md)*
