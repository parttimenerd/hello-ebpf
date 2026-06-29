# UserspaceScheduler: rustland-style userspace policy schedulers in hello-ebpf

**Status:** Draft (v1)
**Date:** 2026-06-29
**Author:** brainstormed with Johannes Bechberger

## Summary

Add a `UserspaceScheduler` framework to hello-ebpf that mirrors `scx_rustland_core`: BPF acts as a thin transport between the kernel `sched_ext` ops and a Java userspace process that decides per-task CPU/slice/vtime. The framework comprises a new user-ringbuf map wrapper, a BPF-side base class for sched_ext programs, a Java-side run-loop framework, and one sample policy (RL-FIFO equivalent). Out-of-scope features (CPU topology, cgroup awareness) are deferred to followups.

## Goals

1. Demonstrate that a sched_ext scheduler can credibly run its policy in Java userspace.
2. Provide a reusable framework — future Java userspace schedulers extend `UserspaceSchedulerBase` and `UserspaceScheduler` rather than reimplementing the transport.
3. Match `scx_rustland_core`'s feature surface, minus genuinely advanced bits (topology, cgroups, custom allocator).
4. Ship one working sample (RL-FIFO) with smoke-test coverage.

## Non-goals

- CPU topology / sibling map awareness
- cgroup-aware scheduling
- GraalVM native-image build
- A latency-benchmark harness (worthwhile, but separate PR)
- A second sample policy proving the framework generalises (could be a followup)
- Performance parity with `scx_rustland` — Java will have higher tail latency than Rust; we accept this honestly

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  bpf/src/main/java/me/bechberger/ebpf/                  │
│  ├─ bpf/map/BPFUserRingBuffer<E>          (new, ~150)   │
│  └─ bpf/UserspaceSchedulerBase             (new, ~300)  │
│        extends SchedulerBase implements Scheduler       │
│        wires select_cpu/enqueue/dispatch to ringbufs    │
│                                                          │
│  bpf-runtime/.../sched/UserspaceScheduler  (new, ~400)  │
│        run-loop, idle-map view, stats, zero-alloc       │
│        batching; used by Java userspace                 │
│                                                          │
│  bpf-samples/.../sched/RustlandFifoSample (new, ~150)   │
│        RL-FIFO policy on top of the framework           │
└─────────────────────────────────────────────────────────┘
```

### Data flow

```
kernel task wakeup
   ↓
BPF enqueue()  ── reserve queued_task_ctx in kernel→user ringbuf, submit
   ↓ (libbpf ringbuf wakeup, epoll)
Java run loop ── dequeueBatch(N) ── policy() ── per task:
                                                user-ringbuf reserve
                                                fill dispatched_task_ctx
                                                user-ringbuf submit
   ↓ (kernel notified)
BPF dispatch(cpu) ── bpf_user_ringbuf_drain(callback) ── route to per-CPU DSQ
   ↓
task runs on CPU
```

### What stays in BPF (kernel-land)

These cannot go through Java without risking GC/safepoint-induced deadlock:

- **`select_cpu` ops** — always `scx_bpf_select_cpu_dfl`. Java is never consulted on initial CPU selection; rustland makes the same choice in Rust for the same reason.
- **Framework-thread dispatch.** The Java scheduler's own threads (main loop, GC, JIT, JFR, finalizer) are routed to `FRAMEWORK_DSQ` by `enqueue()` and drained first in `dispatch()` with **unbounded priority**. If the scheduler is misbehaving, the system suffers — same trade-off rustland accepts.
- **Stall fallback.** If `bpf_user_ringbuf_drain` returns zero work and the last successful drain was more than `STALL_FALLBACK_NS` (1 ms) ago, BPF promotes from `SHARED_DSQ_ID`. Keeps the kernel alive when Java is unresponsive.
- **Preemption-on-IRQ decisions.** IRQ context cannot wait on Java; stays in BPF (no userspace override path exposed).

### What goes to Java userspace

- Per-task target CPU, slice, vtime, dispatch flags — for all non-framework tasks.
- Statistics aggregation and any policy-level adaptive logic.

## Components

### 1. `BPFUserRingBuffer<E>` (new, ~150 LOC)

Path: `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFUserRingBuffer.java`

A typed Java wrapper for `BPF_MAP_TYPE_USER_RINGBUF` (libbpf 1.2+, already in the jextract-generated `Lib` bindings shipped via the `rawbpf` module).

```java
public class BPFUserRingBuffer<E> extends BPFBaseMap<...> {

    /** Construct from a map fd; called by BPFProgram during bind. */
    public BPFUserRingBuffer(MemorySegment mapPtr, StructType<E> elementType);

    /**
     * Reserve a slot of size sizeof(E). Returns a typed Ptr<E> backed by the
     * ringbuf's internal memory, or null if the buffer is full. The element
     * MUST be either submitted or discarded before the next reserve in this
     * thread. The Ptr is invalidated after submit/discard.
     */
    public Ptr<E> reserve();

    /** Commit a reserved element. The ringbuf becomes visible to the kernel. */
    public void submit(Ptr<E> ptr);

    /** Abandon a reserved element without making it visible. */
    public void discard(Ptr<E> ptr);

    /** Close the handle. Called from BPFProgram.close() automatically. */
    public void close();

    // ─── BPF-side method (compiled by the compiler plugin) ───
    // Note: the drain callback in libbpf signature takes a (Ptr<bpf_dynptr>, Ptr<?> ctx).
    // We expose a typed BPFUserRingbufCallback<E> that the compiler plugin lowers to
    // a (bpf_dynptr*, ctx*) thunk that reads sizeof(E) bytes into a typed Ptr<E>.
    @BuiltinBPFFunction("bpf_user_ringbuf_drain(&$this, $arg1, $arg2, 0)")
    public int drain(BPFUserRingbufCallback<E> callback, Ptr<?> ctx) {
        throw new MethodIsBPFRelatedFunction();
    }
}
```

**FFI:** uses `Lib.user_ring_buffer__new`, `user_ring_buffer__reserve`, `user_ring_buffer__submit`, `user_ring_buffer__discard`, `user_ring_buffer__free` (all already extracted by jextract via `rawbpf/misc/bpf_headers.h`).

**Compiler plugin / map registration:**

- Add `BPF_MAP_TYPE_USER_RINGBUF` (id 31) to `MapTypeId` enum.
- Compiler plugin: emit `__uint(type, BPF_MAP_TYPE_USER_RINGBUF)` for fields of this type — likely a one-line table entry. If `BPFRingBuffer<E>`'s emission path doesn't cleanly generalise, allow ~50 LOC of plugin work.
- `@SharedFrom` support: not required for the basic version (the scheduler's two ringbufs are owned by a single program), but should drop in for free given the plugin handles other map types uniformly.

### 2. `UserspaceSchedulerBase` (new, ~300 LOC)

Path: `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java`

Sister to the existing `SchedulerBase`; extends it, implements `Scheduler`. Concrete sched_ext samples extend this class.

```java
@BPF(license = "GPL")
public abstract class UserspaceSchedulerBase extends SchedulerBase implements Scheduler {

    static final long FRAMEWORK_DSQ      = 1;
    static final long STALL_FALLBACK_NS  = 1_000_000L;   // 1 ms
    static final int  RL_CPU_ANY         = 1 << 20;
    static final int  MAX_CPUS           = 1024;

    // ─── Maps ────────────────────────────────────────────────────
    @BPFMapDefinition(maxEntries = 16384)
    BPFRingBuffer<QueuedTaskCtx> queued;              // kernel→user

    @BPFMapDefinition(maxEntries = 16384)
    BPFUserRingBuffer<DispatchedTaskCtx> dispatched;  // user→kernel

    @BPFMapDefinition(maxEntries = MAX_CPUS / 64 + 1, flags = BPF_F_MMAPABLE)
    BPFArray<@Unsigned Long> idleMask;                // bitmap, mmap'd from Java

    @BPFMapDefinition(maxEntries = 1, flags = BPF_F_MMAPABLE)
    BPFArray<SchedStats> stats;                       // mmap'd from Java

    @BPFMapDefinition(maxEntries = 1024)
    BPFHashMap<Integer, Byte> frameworkPids;          // set; value is ignored

    final GlobalVariable<Integer> schedulerPid       = new GlobalVariable<>(0);
    final GlobalVariable<@Unsigned Long> lastUserDispatchNs = new GlobalVariable<>(0L);

    final DispatchQueue framework = new DispatchQueue(FRAMEWORK_DSQ);
    final DispatchQueue shared    = DispatchQueue.attach(SHARED_DSQ_ID);

    // ─── sched_ext ops ───────────────────────────────────────────
    @Override
    public int init() {
        return scx_bpf_create_dsq(FRAMEWORK_DSQ, -1)
             | scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        return selectCpuDfl(p, prev_cpu, wake_flags);
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        int pid = p.val().pid;
        if (frameworkPids.bpf_get(pid) != null) {
            framework.insertScaled(p, EnqFlags.passThrough(enq_flags));
            incStat(STAT_FRAMEWORK_ENQUEUES, 1);
            return;
        }
        Ptr<QueuedTaskCtx> evt = queued.reserve();
        if (evt == null) {
            incStat(STAT_CONGESTION_EVENTS, 1);
            shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
            return;
        }
        fillQueuedCtx(evt, p, enq_flags);
        queued.submit(evt);
        incStat(STAT_ENQUEUE_COUNT, 1);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        // 1. Drain framework DSQ first — unbounded priority
        if (framework.moveToLocal()) return;

        // 2. Drain Java decisions via user ringbuf
        int drained = dispatched.drain(this::dispatchOne, null);
        if (drained > 0) {
            lastUserDispatchNs.set(bpf_ktime_get_ns());
            return;
        }

        // 3. Stall fallback: Java unresponsive → consume shared DSQ
        if (bpf_ktime_get_ns() - lastUserDispatchNs.get() > STALL_FALLBACK_NS) {
            if (shared.moveToLocal()) {
                incStat(STAT_KERNEL_DISPATCHES, 1);
                return;
            }
        }
    }

    @Override
    public void updateIdle(int cpu, boolean idle) {
        setBit(idleMask, cpu, idle);
        if (idle) decStat(STAT_RUNNING_TASKS, 1);
        else      incStat(STAT_RUNNING_TASKS, 1);
    }

    // ─── Internal: drain callback ────────────────────────────────
    int dispatchOne(Ptr<DispatchedTaskCtx> d) {
        Ptr<task_struct> p = bpf_task_from_pid(d.val().pid);
        if (p == null) { incStat(STAT_BOUNCED_DISPATCHES, 1); return 0; }
        long slice = d.val().sliceNs == 0 ? 5_000_000L : d.val().sliceNs;
        if (d.val().cpu == RL_CPU_ANY) {
            scx_bpf_dispatch(p, SHARED_DSQ_ID, slice, d.val().flags);
        } else {
            scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | d.val().cpu, slice, d.val().flags);
        }
        bpf_task_release(p);
        incStat(STAT_USER_DISPATCHES, 1);
        return 0;
    }
}
```

Plus a sibling **tracepoint sub-program** that auto-registers child threads of the scheduler process into `frameworkPids`:

```java
@Tracepoint(category = "sched", name = "sched_process_fork")
int onFork(Ptr<TracepointSchedProcessFork> ctx) {
    if (ctx.val().parent_tgid == schedulerPid.get()) {
        byte one = 1;
        frameworkPids.bpf_update(ctx.val().child_pid, one, BPF_ANY);
    }
    return 0;
}
```

### 3. `UserspaceScheduler<TQ, TD>` (new, ~400 LOC)

Path: `bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/sched/UserspaceScheduler.java`

Java-side framework. Subclasses implement `policy()` for per-task decisions.

```java
public abstract class UserspaceScheduler<TQ, TD> implements AutoCloseable {

    protected final BPFProgram program;
    protected final BPFRingBuffer<TQ> queued;
    protected final BPFUserRingBuffer<TD> dispatched;
    protected final MemorySegment idleMaskView;     // mmap'd
    protected final MemorySegment statsView;        // mmap'd

    private final TQ[] batchBuf;          // preallocated, length = batchSize
    private final int batchSize;
    private final ScheduledExecutorService rescanner;

    protected UserspaceScheduler(BPFProgram prog, int batchSize) { ... }

    public final void run() {
        populateFrameworkPidsInitial();
        rescanner.scheduleAtFixedRate(this::rescanFrameworkPids, 1, 1, SECONDS);
        try { mainLoop(); } finally { rescanner.shutdownNow(); }
    }

    private void mainLoop() {
        while (!Thread.currentThread().isInterrupted()) {
            int n = dequeueBatch(batchBuf, batchSize);  // blocks via epoll
            for (int i = 0; i < n; i++) {
                try {
                    policy(batchBuf[i]);
                } catch (Throwable t) {
                    incStat(STAT_POLICY_EXCEPTIONS, 1);
                    log.warn("policy() threw", t);
                }
            }
            tick();
        }
    }

    // ─── Hot-path API for subclasses ─────────────────────────────
    protected final int dequeueBatch(TQ[] out, int max);

    /** Zero-alloc dispatch: writes straight into the user ringbuf. */
    protected final boolean dispatch(int pid, int cpu, long slice, long vtime, long flags) {
        Ptr<TD> p = dispatched.reserve();
        if (p == null) return false;
        fillDispatched(p, pid, cpu, slice, vtime, flags);
        dispatched.submit(p);
        return true;
    }

    /** Read idle CPU bitmap (mmap, zero-syscall) and return any idle CPU, or -1. */
    protected final int pickIdleCpu();

    /** Copy stats into caller-provided record. */
    protected final void readStatsInto(SchedStatsSnapshot dest);

    // ─── To be implemented ───────────────────────────────────────
    protected abstract void policy(TQ task);
    protected void tick() {}

    // ─── Framework PID maintenance ───────────────────────────────
    private void populateFrameworkPidsInitial() {
        int myPid = (int) ProcessHandle.current().pid();
        program.setGlobalVariable("schedulerPid", myPid);
        rescanFrameworkPids();
    }

    private void rescanFrameworkPids() {
        try (var tasks = Files.list(Path.of("/proc/self/task"))) {
            BPFHashMap<Integer, Byte> map = program.getMap("frameworkPids");
            tasks.forEach(t ->
                map.put(Integer.parseInt(t.getFileName().toString()), (byte) 1));
        } catch (IOException e) { log.warn("framework-PID rescan failed", e); }
    }
}
```

The framework cannot enforce JVM tuning. Its class javadoc and the dedicated `docs/userspace-scheduler.md` page document the required flags (see [JVM tuning](#jvm-tuning) below). The sample's `main()` checks for ZGC and emits a warning if it is not active — flag-only, not fatal.

### 4. `RustlandFifoSample` (new, ~150 LOC)

Path: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandFifoSample.java`

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "rustland_fifo_java")
@Property(name = "timeout_ms", value = "10000")
public abstract class RustlandFifoSample extends UserspaceSchedulerBase {

    public static void main(String[] args) throws Exception {
        verifyZgcOrWarn();
        try (var prog = BPFProgram.load(RustlandFifoSample.class)) {
            new FifoPolicy(prog).run();
        }
    }
}

class FifoPolicy extends UserspaceScheduler<QueuedTaskCtx, DispatchedTaskCtx> {

    private final SchedStatsSnapshot snap = new SchedStatsSnapshot();
    private long loopCount;

    FifoPolicy(BPFProgram prog) { super(prog, /*batchSize=*/ 64); }

    @Override
    protected void policy(QueuedTaskCtx task) {
        int cpu = pickIdleCpu();
        if (cpu < 0) cpu = RL_CPU_ANY;
        dispatch(task.pid(), cpu, /*slice=*/ 0, /*vtime=*/ 0, /*flags=*/ 0);
    }

    @Override
    protected void tick() {
        if (loopCount++ % 5_000 == 0) {
            readStatsInto(snap);
            System.out.printf("enqueued=%d user=%d kernel=%d fail=%d exc=%d%n",
                snap.enqueueCount, snap.userDispatches, snap.kernelDispatches,
                snap.failedDispatches, snap.policyExceptions);
        }
    }
}
```

## Data structures

### `QueuedTaskCtx` (kernel→user)

Matches `scx_rustland_core`'s `queued_task_ctx` exactly.

| Field             | Type    | Notes                                                  |
|-------------------|---------|--------------------------------------------------------|
| `pid`             | int     | task PID                                               |
| `cpu`             | int     | CPU it last ran on, or -1                              |
| `nrCpusAllowed`   | long    | cpumask weight                                         |
| `flags`           | long    | sched_ext enqueue flags, passed through                |
| `startTs`         | long    | last cpu-acquire timestamp (boot ns)                   |
| `stopTs`          | long    | last cpu-release timestamp                             |
| `execRuntime`     | long    | cumulative runtime since last sleep                    |
| `weight`          | long    | task static priority weight                            |
| `vtime`           | long    | task's vruntime                                        |
| `enqCnt`          | long    | monotonic counter for this task                        |
| `comm[16]`        | byte[]  | /proc-style command name                               |

### `DispatchedTaskCtx` (user→kernel)

| Field      | Type | Notes                                              |
|------------|------|----------------------------------------------------|
| `pid`      | int  | task to dispatch                                   |
| `cpu`      | int  | target CPU, or `RL_CPU_ANY` (0x100000) for shared  |
| `flags`    | long | dispatch flags (e.g. `SCX_ENQ_PREEMPT`)            |
| `sliceNs`  | long | time slice; 0 means framework default (5 ms)       |
| `vtime`    | long | vtime to dispatch with; 0 means monotonic          |

### `SchedStats` (mmap'd from Java)

12 counters. BPF increments use `__sync_fetch_and_add` (atomic on 8-byte words). Java reads use `VarHandle.getOpaque()` on `MemorySegment`-derived handles — ordered enough for monotonic counters where staleness of one cycle is acceptable, no fence cost. Not consistent across counters (a snapshot is not an atomic snapshot of all 12) — fine for diagnostics.

| #  | Field                    | Description                                       |
|----|--------------------------|---------------------------------------------------|
| 1  | `onlineCpus`             | current online CPU count                          |
| 2  | `runningTasks`           | tasks currently on a CPU                          |
| 3  | `enqueueCount`           | cumulative count of `enqueue` events (counter)    |
| 4  | `nrScheduled`            | cumulative count of submits from Java             |
| 5  | `userDispatches`         | cumulative dispatches via Java path               |
| 6  | `kernelDispatches`       | cumulative dispatches via BPF stall-fallback path |
| 7  | `failedDispatches`       | DSQ insert failed                                 |
| 8  | `bouncedDispatches`      | task became ineligible (e.g. CPU offline)         |
| 9  | `cancelledDispatches`    | Java reserve→discard, or reserve returned null   |
| 10 | `congestionEvents`       | enqueue saw full ringbuf                          |
| 11 | `frameworkEnqueues`      | tasks routed to FRAMEWORK_DSQ in enqueue          |
| 12 | `policyExceptions`       | Java `policy()` threw and was caught              |

### `schedulerPid` propagation

`schedulerPid` is a BPF global variable (not a per-CPU map, not a hash map slot) holding the Java scheduler's tgid. Lifecycle:

1. JVM starts; GC and JIT threads already exist as children of the JVM tgid.
2. Java calls `BPFProgram.load(...)`; BPF program is verified and attached, all globals at their zero initialiser.
3. Before the tracepoint can possibly fire (i.e. before the first new fork), Java writes the current tgid to `schedulerPid` via the existing `GlobalVariable.set(...)` API.
4. Java then runs the initial `/proc/self/task/` rescan; this catches the GC/JIT threads that existed in step 1.
5. From now on: any new fork by the Java process triggers the tracepoint, which sees a matching `parent_tgid` and registers the child.

The 1-second periodic rescan exists as belt-and-suspenders: if the tracepoint misses anything (race on `frameworkPids` insertion, kernel quirk, or a thread that exits and a new one reuses the TID), the rescan picks it up within ~1 s.

**Verify during implementation:** that `GlobalVariable.set(int)` is callable from Java post-load (some hello-ebpf globals are BPF-only). If not, replace `schedulerPid` with slot 0 of a 1-entry `BPFArray<Integer>` and read/write via the regular map API.

### Idle CPU bitmap

`BPFArray<@Unsigned Long>`, length `(MAX_CPUS + 63) / 64`. Bit *i* in word *i / 64* = 1 iff CPU *i* is currently idle.

- BPF side: `updateIdle` callback sets/clears a single bit using `__sync_fetch_and_or` / `__sync_fetch_and_and` (atomic, BPF-supported).
- Java side: mmap'd via `BPFArray.asMemorySegment()`. Reads are direct memory loads, no syscall.
- **No seqlock.** A torn read can at worst report a CPU as idle when it isn't (or vice versa) for one scheduling cycle, causing one suboptimal dispatch decision. The stall fallback and subsequent updates recover within microseconds. Adding seqlock infrastructure (extra header word, write barriers) is not justified for this granularity of staleness.

## Error handling

| Condition                                     | Side    | Action                                                                       |
|-----------------------------------------------|---------|------------------------------------------------------------------------------|
| `kernel→user` ringbuf full in `enqueue`       | BPF     | Increment `congestionEvents`; route task directly to `SHARED_DSQ`.           |
| Drain callback: `bpf_task_from_pid` returns 0 | BPF     | Increment `bouncedDispatches`; drop.                                         |
| Java `policy()` throws                        | Java    | Catch in run loop, log, increment `policyExceptions`, continue with next.    |
| `user→kernel` ringbuf full on Java reserve    | Java    | `dispatch()` returns `false`; policy may retry or drop. Sample drops; increments `cancelledDispatches`. Stall fallback eventually rescues task. |
| Map mmap fails at startup                     | Java    | Fatal — `RuntimeException`. We cannot run.                                   |
| `schedulerPid` global never set               | both    | Tracepoint becomes a no-op (no match); rescan still works. Log warning when initial rescan finds empty map post-startup. |
| Scheduler-loop thread interrupted             | Java    | Clean shutdown: unload BPF program, close ringbufs.                          |

## Testing strategy

Three layers, all run on the thinkstation (per project memory — local mac cannot run BPF tests).

1. **Unit:** `BPFUserRingBufferTest` — reserve/submit/discard cycles, full-buffer behavior, double-submit detection, close cleanup. No BPF program required; calls libbpf via Panama against a standalone-created user-ringbuf map. Lives under `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/map/`.

2. **Compiler-plugin:** `UserRingBufferCompilationTest` in `bpf-compiler-plugin-test/` — verifies a class declaring `BPFUserRingBuffer<X>` field compiles, emits the correct map definition (`__uint(type, BPF_MAP_TYPE_USER_RINGBUF)`), and that `drain()` lowers correctly to `bpf_user_ringbuf_drain`. Pattern matches existing `SharedFromTest`.

3. **Integration:** `RustlandFifoSampleSmokeTest` in `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/`, modelled on `SchedulerSmokeTest`. Uses `SchedulerExtension` (vng harness) to:
   - Load `RustlandFifoSample`
   - Run `stress-ng --cpu 4 --timeout 3s` in the guest
   - Assert: `userDispatches > 0`, `policyExceptions == 0`, no verifier errors, scheduler unloads cleanly
   - Assert: `frameworkPids` map non-empty within 1s of startup

## JVM tuning

Documented in `UserspaceScheduler`'s class javadoc and `docs/userspace-scheduler.md`. The framework does not enforce these — they are JVM concerns the user must set when launching:

- **`-XX:+UseZGC -XX:+ZGenerational`** — sub-millisecond GC pauses; default for any serious userspace scheduler.
- **`-XX:GuaranteedSafepointInterval=0`** — suppress periodic safepoints that would briefly stall the hot thread.
- **`-Xms == -Xmx`** — fix heap size so no resize events occur.
- **`taskset`/`isolcpus`** — optionally pin the scheduler thread to an isolated CPU; document the pattern.
- **`--enable-native-access=ALL-UNNAMED`** — required for Panama; already standard in hello-ebpf.

The sample's `main()` checks `ManagementFactory.getGarbageCollectorMXBeans()` for ZGC presence and warns once if absent. Not fatal — the warning is enough.

## Zero-alloc hot path

The framework is designed so the steady-state per-task path performs **zero allocations** on the Java side. Patterns the framework embodies (documented in javadoc and the docs page):

- `batchBuf` is allocated once at `UserspaceScheduler` construction (length `batchSize`, default 64).
- `dispatch(int, int, long, long, long)` takes primitives only and writes directly into the user ringbuf's `MemorySegment` via Panama. No boxing.
- `pickIdleCpu()` operates on `MemorySegment` slices and returns an `int`. No allocation.
- `readStatsInto(SchedStatsSnapshot)` writes into a caller-owned record; no allocation per read.
- `policy()` is called per task; subclasses must keep its body allocation-free (no lambdas with captures, no `new` on hot paths, no autoboxing).

The framework cannot statically prove `policy()` is allocation-free. The class javadoc and `docs/userspace-scheduler.md` discuss the rules; users who care about tail latency should validate with `-XX:+PrintCompilation` / JFR allocation profiling.

## Out of scope (deferred)

- CPU topology / sibling map
- cgroup-aware decisions
- A second sample policy (e.g. weighted RR using `weight` field) — followup PR
- Latency-benchmark harness (round-trip histogram) — followup PR
- GraalVM native-image build
- `@SharedFrom` interaction (out of basic-version scope; should drop in cleanly later)

## Implementation order (suggested)

1. `BPFUserRingBuffer<E>` Java wrapper + `MapTypeId` entry + compiler-plugin map-type wiring
2. `BPFUserRingBufferTest` (unit)
3. `UserRingBufferCompilationTest` (plugin)
4. `UserspaceSchedulerBase` (BPF side) with the tracepoint sub-program
5. `UserspaceScheduler` (Java side) including framework-PID maintenance
6. `RustlandFifoSample` + `verifyZgcOrWarn`
7. `RustlandFifoSampleSmokeTest`
8. `docs/userspace-scheduler.md` + javadoc passes

## Risks

- **User ringbuf compiler-plugin emission** is the only meaningful unknown. If `BPFRingBuffer<E>`'s emission path doesn't generalise cleanly, expect ~50 LOC of plugin work and an extra integration test. Should be discovered in step 1.
- **`BPFUserRingbufCallback<E>` lowering.** The kernel callback signature is `(struct bpf_dynptr *dynptr, void *ctx)`. The plugin must lower a typed Java callback into a thunk that reads `sizeof(E)` bytes from the dynptr into a stack-allocated `E` and invokes the user lambda. If this lowering path doesn't exist yet for any callback type, expect ~80 LOC plugin work.
- **Tracepoint argument names** (`parent_tgid`, `child_pid`) come from the kernel's `sched_process_fork` event format and must match what hello-ebpf's `TraceDefinitions` exposes. Verify before implementing the tracepoint program; on some kernels the field is `parent_pid` (which is the tgid in tracepoint context anyway).
- **`GlobalVariable.set(...)` from Java post-load** — verify before implementing `schedulerPid`. Fallback: 1-entry `BPFArray<Integer>` (already established pattern).
- **`BPFArray.asMemorySegment()`** — verify exists. Fallback: syscall reads of the idle map for the basic version with a `TODO` to mmap later.
- **`@BPFMapDefinition(flags=...)`** — verify the annotation supports a `flags=` parameter for `BPF_F_MMAPABLE`. If not, this is a small annotation + plugin change to plumb the flag through to the emitted `__uint(map_flags, BPF_F_MMAPABLE)` line.
- **Java thread interrupt semantics during ringbuf poll** — confirm `BPFRingBuffer.consumeBatch` (or whatever we end up calling) is interruptible. If not, add an fd-based wakeup pipe.
