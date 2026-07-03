# sched_ext — Overview

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
