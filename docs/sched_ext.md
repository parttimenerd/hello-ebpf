# sched_ext — Extensible CPU Scheduler

sched_ext is a Linux scheduling class introduced in kernel 6.11 that allows implementing
CPU schedulers entirely in BPF. Instead of modifying kernel source, you can prototype and
deploy custom scheduling policies from user-space programs.

## Prerequisites

- Kernel ≥6.11 with `CONFIG_SCHED_CLASS_EXT=y`
- Verify: `ls /sys/kernel/sched_ext` should exist

## Why sched_ext?

Traditional kernel schedulers are hard to experiment with — they require kernel patches,
reboots, and deep kernel expertise. sched_ext lets you:

- Prototype scheduling algorithms in minutes
- Deploy different schedulers per workload
- Roll back instantly if a scheduler misbehaves (BPF verifier catches most bugs)
- Share schedulers as jar files

## Implementing a scheduler

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.bpf.raw.Lib_1.*;

@BPF(license = "GPL")
public abstract class RoundRobinScheduler extends BPFProgram implements Scheduler {

    static final int NR_CPUS = 256;

    /** Single shared dispatch queue */
    static final long SHARED_DSQ_ID = 0;

    @Override
    @BPFFunction
    public int schedInit(Ptr<scx_init_task_args> args) {
        // Called for every new task
        return 0;
    }

    @Override
    @BPFFunction
    public void schedEnqueue(Ptr<task_struct> p, long enqFlags) {
        // Enqueue task p into our DSQ with default slice
        scx_bpf_dsq_insert(p, SHARED_DSQ_ID, SCX_SLICE_DFL, enqFlags);
    }

    @Override
    @BPFFunction
    public void schedDispatch(int cpu, Ptr<task_struct> prev) {
        // Consume from our DSQ onto this CPU
        scx_bpf_consume(SHARED_DSQ_ID);
    }

    @Override
    @BPFFunction
    public int schedSelectCPU(Ptr<task_struct> p, int prevCpu, long wakeFlags) {
        // Use default CPU selection (idle CPU preferred)
        boolean[] isIdle = {false};
        return scx_bpf_select_cpu_dfl(p, prevCpu, wakeFlags, isIdle);
    }

    @Override
    @BPFFunction
    public void schedExit(Ptr<scx_exit_info> info) {
        // Called when scheduler is unloaded; log reason
        BPFJ.bpf_trace_printk("scheduler exiting\n");
    }
}
```

## DSQ — Dispatch Queue

The DSQ (Dispatch Queue) is the fundamental unit of the sched_ext scheduling model:

- Every CPU has a **local DSQ** (id = `SCX_DSQ_LOCAL`)
- There is a **global DSQ** (id = `SCX_DSQ_GLOBAL`) shared by all CPUs
- You can create **custom DSQs** with any non-reserved ID

Tasks move: `enqueue` → DSQ → `dispatch` → CPU local DSQ → running

```
Task arrives
    │
    ▼
schedEnqueue()    ← you call scx_bpf_dsq_insert(task, dsq_id, ...)
    │
    ▼
Your DSQ(s)
    │
    ▼
schedDispatch()   ← you call scx_bpf_consume(dsq_id) to pull from DSQ to local
    │
    ▼
CPU runs task
```

## Key scx kfuncs

| Function | Description |
|----------|-------------|
| `scx_bpf_dsq_insert(p, dsq_id, slice_ns, enq_flags)` | Insert task into a DSQ with a time slice |
| `scx_bpf_consume(dsq_id)` | Move a task from DSQ to current CPU's local queue |
| `scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, is_idle)` | Default CPU selection (picks idle CPUs) |
| `scx_bpf_create_dsq(dsq_id, numa_node)` | Create a custom DSQ |
| `scx_bpf_destroy_dsq(dsq_id)` | Destroy a custom DSQ |
| `scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns, vtime, enq_flags)` | Insert with virtual time for WFQ |
| `scx_bpf_dsq_move_to_local(dsq_id)` | Alias for consume in newer kernels |
| `scx_bpf_get_idle_cpumask()` | Returns cpumask of currently idle CPUs |
| `scx_bpf_kick_cpu(cpu, flags)` | Wake up a specific CPU |

## Scheduler callbacks reference

| Callback | Required | Description |
|----------|---------|-------------|
| `schedEnqueue(task, flags)` | Yes | Task becomes runnable; you must enqueue it |
| `schedDispatch(cpu, prev)` | Yes | CPU needs work; consume from your DSQs |
| `schedSelectCPU(task, prevCpu, wakeFlags)` | No | Choose which CPU to wake for this task |
| `schedInit(args)` | No | New task created; initialize per-task state |
| `schedExit(exitInfo)` | No | Scheduler is being unloaded |
| `schedRunningTask(task)` | No | Task starts running on CPU |
| `schedStoppingTask(task, runnable)` | No | Task stops running |
| `schedTaskDying(task)` | No | Task is being destroyed |
| `schedCPUOnline(cpu)` | No | CPU came online |
| `schedCPUOffline(cpu)` | No | CPU went offline |

## Loading and running

```java
public static void main(String[] args) throws Exception {
    try (RoundRobinScheduler sched = BPFProgram.load(RoundRobinScheduler.class)) {
        sched.autoAttachPrograms();
        System.out.println("Scheduler loaded. All tasks now use round-robin.");
        System.out.println("Press Ctrl-C to restore default scheduler.");
        Thread.currentThread().join();
    }
    // Closing the program atomically restores the previous scheduler
}
```

!!! danger "Scheduler bugs can hang the system"
    If `schedEnqueue` never enqueues a task or `schedDispatch` never consumes one,
    tasks starve and the system may become unresponsive. The BPF verifier helps but
    cannot catch all logical bugs. Always test in a VM first.

## Per-task storage

Use `BPFHashMap` keyed by PID or use the sched_ext per-task storage API:

```java
@Type
record TaskCtx(long vruntime, int weight) {}

@BPFMapDefinition(maxEntries = 1 << 17)
final BPFHashMap<Integer, TaskCtx> taskCtxMap = BPFHashMap.newInstance();

@BPFFunction
public int schedInit(Ptr<scx_init_task_args> args) {
    TaskCtx ctx = new TaskCtx();
    ctx.vruntime = 0;
    ctx.weight = 1;
    taskCtxMap.bpf_put(args.val().p.val().pid, ctx);
    return 0;
}
```

## Example — weighted fair queuing

```java
@BPFFunction
public void schedEnqueue(Ptr<task_struct> p, long enqFlags) {
    Ptr<TaskCtx> ctx = taskCtxMap.bpf_get(p.val().pid);
    if (ctx == null) {
        scx_bpf_dsq_insert(p, SHARED_DSQ_ID, SCX_SLICE_DFL, enqFlags);
        return;
    }
    // Insert with virtual time — lower vtime = higher priority
    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ_ID,
        SCX_SLICE_DFL, ctx.val().vruntime, enqFlags);
    // Advance vruntime inversely proportional to weight
    long slice = SCX_SLICE_DFL / ctx.val().weight;
    Ptr.of(ctx.val().vruntime).set(ctx.val().vruntime + slice);
}
```
