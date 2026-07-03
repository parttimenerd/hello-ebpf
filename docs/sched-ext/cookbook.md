# sched_ext — Cookbook

With sched_ext (available since Linux 6.11), you can replace the kernel's default
process scheduler with your own policy — written entirely in Java, compiled to BPF
under the hood, and deployed without rebooting or touching kernel source.

## Prerequisites

You need a kernel ≥ 6.11 built with `CONFIG_SCHED_CLASS_EXT=y`. Check with:

```bash
ls /sys/kernel/sched_ext   # should exist
```

Add the hello-ebpf Maven dependency to your project:

```xml
<dependency>
  <groupId>me.bechberger</groupId>
  <artifactId>bpf</artifactId>
  <version>0.1.3</version>
</dependency>
```

## Hello, Scheduler

Here is the smallest possible scheduler — it replaces the entire kernel scheduler
with a global FIFO queue:

```java
@BPF(license = "GPL")                             // ① marks this as a BPF program
@Property(name = "sched_name", value = "hello")   // ② name shown in /sys/kernel/sched_ext/
public abstract class HelloScheduler extends SchedulerBase implements Scheduler {

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        dsqInsert(p, enq_flags);  // put the task in the shared FIFO queue
    }

    public static void main(String[] args) throws Exception {
        try (var sched = BPFProgram.load(HelloScheduler.class)) {
            sched.runSchedulerLoop();  // attach + block until Ctrl-C
        }
    }
}
```

Run it as root:

```bash
sudo java -jar hello-scheduler.jar
# All processes on this machine are now scheduled by your code.
# Press Ctrl-C to restore the default scheduler.
```

That's it. The annotation processor compiles `enqueue` to BPF bytecode, the BPF
verifier checks it for safety, and the kernel atomically swaps in your scheduler.
`SchedulerBase` handles `init()` (creates one shared FIFO DSQ) and `dispatch()`
(drains it to the current CPU). You only need `enqueue()`.

## How it works: the DSQ model

Every CPU scheduler's job is to answer one question: *which task runs next?*
sched_ext answers it through **Dispatch Queues (DSQs)**:

```
Task becomes runnable
        │
        ▼
  enqueue(task, flags)  ← your code; insert task into a DSQ
        │
        ▼
   DSQ (ordered queue)
        │
        ▼
  dispatch(cpu, prev)   ← your code; move task from DSQ to CPU's local queue
        │
        ▼
  CPU runs task
```

For finer control, skip `SchedulerBase` and implement `Scheduler` directly:

```java
public abstract class MyScheduler extends BPFProgram implements Scheduler {

    static final long MY_DSQ = 1;

    @Override
    public int init() { return scx_bpf_create_dsq(MY_DSQ, -1); }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        scx_bpf_dsq_insert(p, MY_DSQ, SCX_SLICE_DFL.value(), enq_flags);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_dsq_move_to_local(MY_DSQ);
    }
}
```

## Adding fairness: virtual-time scheduling

FIFO is simple but unfair — a CPU-hungry process starves interactive ones.
Virtual-time scheduling fixes this: every task accumulates "virtual time" as it
runs; the task with the smallest vtime runs next.

`SchedulerBase` provides helpers that make this straightforward:

```java
@Override
public void enqueue(Ptr<task_struct> p, long enq_flags) {
    vtimeEnqueue(p, enq_flags, vtimeNow.get());  // vtime-ordered insert
}

@Override
public void running(Ptr<task_struct> p) {
    // Advance global vtime so newly-woken tasks don't accumulate unfair budget.
    @Unsigned long vtime = p.val().scx.dsq_vtime;
    if (isSmaller(vtimeNow.get(), vtime)) {
        vtimeNow.set(vtime);
    }
}

@Override
public void stopping(Ptr<task_struct> p, boolean runnable) {
    vtimeCharge(p);  // charge elapsed slice to p.scx.dsq_vtime
}

@Override
public void enable(Ptr<task_struct> p) {
    p.val().scx.dsq_vtime = vtimeNow.get();  // start fair for new tasks
}
```

`isSmaller(a, b)` does unsigned comparison — important because vtime wraps around
after 2⁶⁴ nanoseconds and a naive `<` would give wrong results.

See `SimpleScheduler` for a complete FIFO/vtime scheduler with a runtime switch:

```java
// Toggle mode at runtime from Java (while the scheduler is running!):
sched.setFifoMode(false);   // switch to vtime
sched.setFifoMode(true);    // switch back to FIFO
```

The `GlobalVariable<Boolean>` behind `setFifoMode` is a BPF map that both the BPF
program and the Java side can read and write — no restart required.

## Per-CPU scheduling

For workloads where tasks should stay on their CPU (real-time, NUMA-sensitive, or
migration-disabled tasks), use `PerCpuSchedulerBase` instead of `SchedulerBase`:

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "per_cpu")
public abstract class MyScheduler extends PerCpuSchedulerBase implements Scheduler {

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        if (isMigrationDisabled(p)) {
            dsqInsertLocal(p, enq_flags);  // pin to the task's current CPU
        } else {
            dsqInsert(p, enq_flags);       // allow migration via shared DSQ
        }
    }
}
```

`PerCpuSchedulerBase` creates one DSQ per CPU (IDs `PER_CPU_DSQ_BASE + cpu`) plus
the shared fallback. `dispatch()` drains the per-CPU DSQ first, then falls back.
`isMigrationDisabled(p)` returns true for tasks pinned via affinity or kernel flags.

## Stats and observability

Add enqueue/dispatch counters with three lines:

```java
@BPFMapDefinition(maxEntries = 1) BPFPerCpuArray<Long> enqueuedCounts;
@BPFMapDefinition(maxEntries = 1) BPFPerCpuArray<Long> dispatchedCounts;

// In BPF callbacks:
SchedulerStats.incrementEnqueued(enqueuedCounts);
SchedulerStats.incrementDispatched(dispatchedCounts);

// Read from Java:
long total = SchedulerStats.totalEnqueued(enqueuedCounts);
```

The per-CPU arrays avoid false sharing between cores; `totalEnqueued()` sums
across all CPUs on the Java side.

For arbitrary shared state, use `GlobalVariable<T>`:

```java
final GlobalVariable<Long> vtimeNow = new GlobalVariable<>(0L);

// In BPF:  vtimeNow.get() / vtimeNow.set(v)
// In Java: same — readable and writable while the scheduler runs
```

## Per-task storage

Use `BPFTaskStorage<T>` to attach a struct to each task (kernel-managed lifecycle,
safe under concurrent task creation and destruction):

```java
@Type record TaskCtx(@Unsigned long deadline) {}

@BPFMapDefinition(maxEntries = 1)
BPFTaskStorage<TaskCtx> taskCtx;

@Override
public void enable(Ptr<task_struct> p) {
    taskCtx.bpf_task_storage_get(p, new TaskCtx(0L),
            BPF_LOCAL_STORAGE_GET_F_CREATE);
}

@Override
public void enqueue(Ptr<task_struct> p, long enq_flags) {
    Ptr<TaskCtx> ctx = taskCtx.bpf_task_storage_get(p, null, 0);
    long dl = (ctx != null) ? ctx.val().deadline() : scx_bpf_now();
    scx_bpf_dsq_insert_vtime(p, SHARED_DSQ_ID, SCX_SLICE_DFL.value(), dl, enq_flags);
}
```

See `DeadlineScheduler` and `TaskStorageScheduler` for complete examples.

## The watchdog

Every scheduler should set a timeout:

```java
@Property(name = "timeout_ms", value = "5000")
```

If the scheduler fails to dispatch any task for longer than `timeout_ms` milliseconds,
the kernel automatically detaches it and restores the previous scheduler. This turns
a "system hung" scenario into a brief slowdown.

After the scheduler detaches (for any reason), `getExitCode()` returns the kernel's
exit code. Non-zero typically means an error; `SCX_EXIT_ERROR_STALL` means the
watchdog fired.

```java
try (var sched = BPFProgram.load(MyScheduler.class)) {
    sched.runSchedulerLoop();
    if (sched.getExitCode() != 0) {
        System.err.println("Exited with code: 0x" + Long.toHexString(sched.getExitCode()));
    }
}
```

Override `onSchedulerExit(long exitCode)` to handle specific codes inline.

## Testing your scheduler

The framework ships a JUnit 5 extension that handles the load → attach → test →
close lifecycle:

```java
@ExtendWith(SchedulerExtension.class)
class MySchedulerTest {

    @Test
    @Timeout(15)
    @TestScheduler(HelloScheduler.class)
    void schedulerAttachesAndRuns(HelloScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly());
    }
}
```

For deeper assertions, attach, drive a workload, then read back stats:

```java
@Test
@TestScheduler(SimpleScheduler.class)
void statsGrowUnderLoad(SimpleScheduler sched) throws Exception {
    long before = sched.getTotalEnqueued();
    new Thread(() -> { for (int i = 0; i < 1_000_000; i++) {} }).start();
    Thread.sleep(400);
    assertTrue(sched.getTotalEnqueued() > before);
}
```

If you need to configure the scheduler before attaching (e.g. set CPU topology), use
`autoAttach = false`:

```java
@TestScheduler(value = SMTPairScheduler.class, autoAttach = false)
void smtTest(SMTPairScheduler sched) throws Exception {
    sched.configure(ncpus, ncpus / 2);
    sched.attachScheduler();
    Thread.sleep(300);
    assertTrue(sched.isSchedulerAttachedProperly());
}
```

Run tests inside a VM (recommended — a buggy scheduler can stall the host):

```bash
./scripts/run-tests-vng.sh MySchedulerTest
```

## Inspecting generated BPF C code

The annotation processor translates your Java scheduler into BPF C before compiling
to bytecode. To see the generated code without root:

```java
BPFProgram.printCode(MyScheduler.class);   // prints to stdout
```

Or at load time:

```bash
BPF_PRINT_CODE=1 sudo ./run.sh MyScheduler
```

This is invaluable when debugging verifier errors — the `#line N "File.java"` markers
in the output map each BPF instruction back to the original Java source line.

## Where to go next

- **Reference**: [`docs/sched_ext.md`](../sched_ext.md) — full callback table, DSQ
  kfunc reference, `@Property` options, per-task storage patterns, exit info API
- **18 sample schedulers** in `bpf-samples/src/main/java/…/samples/sched/`,
  ranging from `MinimalScheduler` (one method) to `ChaosScheduler` (random vtimes,
  CPU throttling, per-task state machines), `FlowScheduler` (weight-based CPU
  affinity, port of `scx_flow`), and `BoostedScheduler` (priority boost for
  nominated process trees — useful for performance testing)
- **Behavioral tests** in `SchedulerBehaviorTest` — show how to assert on stats,
  callback invocations, and mode switches in a real kernel environment

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
