# Writing a Scheduler — Step-by-step Guide

**Blog series:** [Part 15 — Custom scheduler basics](https://mostlynerdless.de/blog/2024/10/17/hello-ebpf-writing-a-custom-scheduler-in-pure-java-15/) · [Part 17 — Lottery scheduler](https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/)  
**Talk:** [Writing a Linux Scheduler in Java (eBPF Summit 2024)](https://speakerdeck.com/parttimenerd/writing-a-linux-scheduler-in-java-with-ebpf) · [Sound of Scheduling (CLT 2025)](https://speakerdeck.com/parttimenerd/sound-of-scheduling-writing-linux-schedulers-in-java-with-ebpf)  
**Javadoc:** [`SchedulerBase`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/SchedulerBase.html) · [`Scheduler`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/Scheduler.html) · [`DispatchQueue`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/sched/DispatchQueue.html)  
**See also:** [Overview](index.md) · [Callbacks Reference](callbacks.md) · [Cookbook](cookbook.md)

This guide walks you through building a sched_ext scheduler in Java, starting from
the simplest possible program and progressively adding vtime scheduling, per-task
state, and observability.

Prerequisites: kernel ≥ 6.14 with `CONFIG_SCHED_CLASS_EXT=y`. Verify:

```bash
ls /sys/kernel/sched_ext    # must exist
```

---

## Step 1 — Minimal FIFO scheduler

The minimum viable scheduler overrides only `enqueue`. `SchedulerBase` provides
`dispatch` (drains the global DSQ) and `init` (creates the shared DSQ).

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
@Property(name = "sched_name", value = "my_fifo")
public abstract class MyFifoScheduler extends SchedulerBase implements Scheduler {

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    public static void main(String[] args) throws Exception {
        try (var sched = BPFProgram.load(MyFifoScheduler.class)) {
            sched.runSchedulerLoop();
        }
    }
}
```

`insertScaled` automatically scales the time slice by the current queue depth — a
reasonable default for FIFO schedulers. Run as root:

```bash
sudo java -cp target/my-app.jar com.example.MyFifoScheduler
```

The scheduler replaces the system scheduler while running and restores the previous
one on exit (or on watchdog timeout).

---

## Step 2 — Add stats

Add per-CPU counters using `SchedulerStats` and `BPFPerCpuArray`:

```java
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.SchedulerStats;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;

@BPF(license = "GPL")
@Property(name = "sched_name", value = "my_fifo_stats")
public abstract class MyFifoScheduler extends SchedulerBase implements Scheduler {

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> enqueuedCounts;

    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Long> dispatchedCounts;

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
        SchedulerStats.incrementEnqueued(enqueuedCounts);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();
        SchedulerStats.incrementDispatched(dispatchedCounts);
    }

    public long totalEnqueued()   { return SchedulerStats.totalEnqueued(enqueuedCounts); }
    public long totalDispatched() { return SchedulerStats.totalDispatched(dispatchedCounts); }

    public static void main(String[] args) throws Exception {
        try (var sched = BPFProgram.load(MyFifoScheduler.class)) {
            sched.attachScheduler();
            while (sched.isSchedulerAttachedProperly()) {
                System.out.printf("enq=%d disp=%d%n",
                    sched.totalEnqueued(), sched.totalDispatched());
                Thread.sleep(1000);
            }
        }
    }
}
```

---

## Step 3 — Weighted fair-queuing with vtime

Virtual-time scheduling assigns tasks a `vtime` key proportional to their weight:
higher-priority tasks advance more slowly and therefore run first.

```java
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.bpf.GlobalVariable;

@BPF(license = "GPL")
@Property(name = "sched_name", value = "my_vtime")
public abstract class MyVTimeScheduler extends SchedulerBase implements Scheduler {

    final GlobalVariable<@Unsigned Long> vtimeNow = new GlobalVariable<>(0L);

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        // insertVtimeClamped ensures sleeping tasks don't accumulate credit
        shared.insertVtimeClamped(p, vtimeNow.get(), EnqFlags.passThrough(enq_flags));
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        // charge the elapsed slice to the task's vtime, then advance the global clock
        vtimeCharge(p);
        vtimeNow.set(p.val().scx.dsq_vtime);
    }
}
```

**Never mix FIFO and vtime insertions on the same DSQ.**

---

## Step 4 — Per-task state with `BPFTaskStorage`

`BPFTaskStorage` is a kernel-managed map that associates data with each `task_struct`.
It is safer than `BPFHashMap<Integer, T>` because the kernel handles concurrent
task creation and destruction automatically.

```java
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.bpf.map.BPFTaskStorage;
import static me.bechberger.ebpf.runtime.BpfDefinitions.BPF_LOCAL_STORAGE_GET_F_CREATE;

@Type
record TaskCtx(long vruntime) {}

@BPFMapDefinition(maxEntries = 1)
BPFTaskStorage<TaskCtx> taskCtx;

@Override
public void enable(Ptr<task_struct> p) {
    // initialise per-task state when the task enters SCX scheduling
    taskCtx.bpf_task_storage_get(p, new TaskCtx(vtimeNow.get()),
            BPF_LOCAL_STORAGE_GET_F_CREATE);
}

@Override
public void enqueue(Ptr<task_struct> p, long enq_flags) {
    Ptr<TaskCtx> ctx = taskCtx.bpf_task_storage_get(p, null, 0);
    if (ctx == null) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
        return;
    }
    shared.insertVtime(p, SCX_SLICE_DFL.value(),
            ctx.val().vruntime(), EnqFlags.passThrough(enq_flags));
}
```

---

## Step 5 — CPU affinity with `CpuMask`

`CpuMask` lets you pick idle CPUs and check task affinity constraints. Always
call `releaseIdle()` or `release()` when done — failing to release leaks a
kernel reference.

```java
import me.bechberger.ebpf.bpf.sched.CpuMask;

@Override
public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
    boolean is_idle = false;
    CpuMask idle = CpuMask.idle();
    int cpu = idle.pickIdle(0);
    idle.releaseIdle();

    if (cpu >= 0) {
        // fast-path: dispatch directly to the idle CPU's local queue
        DispatchQueue.localOn(cpu).insert(p, SCX_SLICE_DFL.value(),
                EnqFlags.passThrough(wake_flags));
        return cpu;
    }
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
}
```

---

## Step 6 — Runtime control with `GlobalVariable`

`GlobalVariable<T>` creates a shared BPF array that both BPF code and Java code
can read and write while the scheduler is running:

```java
final GlobalVariable<Boolean> fifoMode = new GlobalVariable<>(true);

@Override
public void enqueue(Ptr<task_struct> p, long enq_flags) {
    if (fifoMode.get()) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    } else {
        shared.insertVtimeClamped(p, vtimeNow.get(), EnqFlags.passThrough(enq_flags));
    }
}

// Java-side: toggle scheduling mode at runtime
public void setFifoMode(boolean fifo) {
    fifoMode.set(fifo);
}
```

---

## Step 7 — Run, test, and inspect

**Run in a VM first.** A buggy `enqueue` can stall all tasks and freeze the system.
Use `vng` or any KVM-based VM. The watchdog (`timeout_ms`, default 30 s) auto-detaches
a misbehaving scheduler, but the system may be sluggish until it fires.

**Inspect the generated BPF C:**

```java
// Without root — print the generated C to stdout:
BPFProgram.printCode(MyScheduler.class);
```

```bash
# With root — print at load time:
BPF_PRINT_CODE=1 sudo java -cp ... com.example.MyScheduler
```

**Check attachment:**

```bash
cat /sys/kernel/sched_ext/root/ops   # shows scheduler name while attached
```

**Check exit code after detachment:**

```java
long code = sched.getExitCode();
// 0 = normal; SCX_EXIT_ERROR_STALL = watchdog fired
```

---

## Examples

The `bpf-samples` module contains progressively more complex schedulers:

| Scheduler | What it demonstrates |
|-----------|---------------------|
| [`MinimalScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java) | Minimum viable FIFO scheduler |
| [`SimpleScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/SimpleScheduler.java) | FIFO + vtime + stats, mirrors `scx_simple` |
| [`VTimeScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/VTimeScheduler.java) | Weighted fair-queuing |
| [`NestScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/NestScheduler.java) | Idle-CPU nesting with `CpuMask` |
| [`TaskStorageScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/TaskStorageScheduler.java) | Per-task state via `BPFTaskStorage` |
| [`PriorityScheduler`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/PriorityScheduler.java) | Multiple priority DSQs |
| [`PerCpuSchedulerSample`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/PerCpuSchedulerSample.java) | Per-CPU DSQ layout via `PerCpuSchedulerBase` |

---

*Next: [Kernelspace Scheduler](kernel-side.md)*
