# UserspaceScheduler: rustland-style userspace policy schedulers in hello-ebpf

**Status:** Draft (v2)
**Date:** 2026-06-29
**Author:** brainstormed with Johannes Bechberger

## Summary

Add a `UserspaceScheduler` framework to hello-ebpf that mirrors `scx_rustland_core`'s *transport and ergonomics* (not its full feature surface — see Non-goals): BPF acts as a thin transport between the kernel `sched_ext` ops and a Java userspace process that decides per-task CPU/slice/vtime. The framework comprises a new user-ringbuf map wrapper, a BPF-side base class for sched_ext programs, a Java-side run-loop framework, and one sample policy (RL-FIFO equivalent). Out-of-scope features (CPU topology, cgroup awareness) are deferred to followups.

The Java API surface closely follows rustland's ergonomics: mutable-public-field `QueuedTask` / `DispatchedTask` records, `scratch.fillFrom(task)` as the one-line zero-alloc constructor pattern, a single `runUntilExit()` entry point, an `exited()` predicate that collapses all shutdown sources into one bool, and a two-tier override model (`policy(QueuedTask)` for simple per-task decisions, `schedule()` for batch-then-sort patterns). The minimal user sample is ~15 lines.

## Goals

1. Demonstrate that a sched_ext scheduler can credibly run its policy in Java userspace.
2. Provide a reusable framework — future Java userspace schedulers extend `UserspaceSchedulerBase` and `UserspaceScheduler` rather than reimplementing the transport.
3. Cover the core feature surface of `scx_rustland_core` (kernel↔user transport, per-task CPU/slice/vtime decisions, idle bitmap, stats, framework-thread priority, stall fallback). Topology, cgroups, custom allocator, and other advanced bits are explicitly out of scope.
4. Ship one working sample (RL-FIFO) with smoke-test coverage.
5. Reuse existing hello-ebpf infrastructure (`SchedulerBase`, `BPFArena`/`BPFTypedArena`, `BPFRingBuffer`, `Scheduler` helpers) rather than introducing parallel mechanisms.

## Non-goals

- CPU topology / sibling map awareness
- cgroup-aware scheduling
- GraalVM native-image build
- Performance parity with `scx_rustland` — Java will have higher tail latency than Rust; we accept this honestly

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  bpf/src/main/java/me/bechberger/ebpf/                  │
│  ├─ bpf/map/BPFUserRingBuffer<E>          (new, ~150)   │
│  ├─ bpf/UserspaceSchedulerBase             (new, ~300)  │
│  │     extends SchedulerBase implements Scheduler       │
│  │     wires select_cpu/enqueue/dispatch to ringbufs    │
│  └─ bpf/UserspaceScheduler                 (new, ~250)  │
│        Java-side run-loop, idle-map view, stats,        │
│        zero-alloc batching                              │
│                                                          │
│  bpf-samples/.../sched/RustlandFifoSample (new, ~80)    │
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

- **`select_cpu` ops** — always `scx_bpf_select_cpu_dfl`. Java is never consulted on initial CPU selection; rustland makes the same choice in Rust for the same reason. **Idle fast path:** when the kernel default reports a known-idle CPU, the task is pre-dispatched straight to that CPU's `SCX_DSQ_LOCAL` and `enqueue()` is skipped entirely. Only tasks that find no idle CPU travel through Java. This matches rustland and dramatically reduces round-trip count on lightly loaded systems.
- **Kthread fast path.** Per-CPU kernel threads (`PF_KTHREAD && nr_cpus_allowed == 1`) and the well-known mm helpers (`kswapd`, `khugepaged` — Java looks up their PIDs at startup and writes them into BPF global variables) bypass userspace and are inserted directly into their last CPU's local DSQ. Routing `ksoftirqd`/`rcuop`/etc. through Java would be a latency footgun; rustland makes the same carve-out.
- **Per-task lifecycle ops (`init_task`/`running`/`stopping`).** BPF maintains a `task_storage` map of `(enqCnt, startTs, stopTs, execRuntime)` per task — populated on `init_task`, stamped by `running`/`stopping`. The `enqCnt` is bumped on every `enqueue` and copied into the kernel→user record; the dispatch callback drops dispatches with a stale `enqCnt` (the task was re-queued while Java was deciding) via `scx_bpf_dispatch_cancel`. Without this, `QueuedTask.startTs`/`stopTs`/`execRuntime` would be dead fields and fuzzers / latency-sensitive policies would see ghost dispatches.
- **Heartbeat timer.** A 1 s `bpf_timer` calls `scx_bpf_kick_cpu(schedulerCpu, SCX_KICK_IDLE)` so that a fully idle machine still wakes the Java loop before the sched_ext watchdog kills the scheduler. Distinct from the stall fallback (which handles "Java is wedged"); this handles "the whole system is idle and nobody is calling enqueue".
- **Framework-thread dispatch.** The Java scheduler's own threads (main loop, GC, JIT, JFR, finalizer) are routed to `FRAMEWORK_DSQ` by `enqueue()` and drained first in `dispatch()` with **unbounded priority**. If the scheduler is misbehaving, the system suffers — same trade-off rustland accepts.
- **Stall fallback.** If `bpf_user_ringbuf_drain` returns zero work and the last successful drain was more than `STALL_FALLBACK_NS` (50 ms) ago, BPF promotes from `SHARED_DSQ_ID`. Keeps the kernel alive when Java is unresponsive. The 50 ms default is a compromise: rustland's 5 s lets visible workload stalls accumulate, while a sub-millisecond threshold trips on routine JIT/class-loading safepoints. 50 ms is long enough that a well-tuned ZGC-generational JVM never trips it, short enough that a wedged scheduler is recovered within a single user-perceptible interval.
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
- **Typed-callback lowering:** the `BPFUserRingbufCallback<E>` thunk that wraps the libbpf `(bpf_dynptr*, ctx*)` signature is new plugin work — neither `BPFRingBuffer` nor existing map callbacks have an equivalent shape. Plan budget ~80 LOC across `MethodTemplate` (a new `$ringbufThunk:T` placeholder) and the callback-emission visitor. If the typed thunk turns out to be expensive, an acceptable v1 fallback is to expose `drain` only as a raw `(Ptr<bpf_dynptr>, Ptr<?> ctx) -> int` callback and let `UserspaceSchedulerBase` cast inside the lambda body — uglier but unblocks the rest of the work.
- `@SharedFrom` support: not required for the basic version (the scheduler's two ringbufs are owned by a single program), but should drop in for free given the plugin handles other map types uniformly.

### 2. `UserspaceSchedulerBase` (new, ~300 LOC)

Path: `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java`

Sister to the existing `SchedulerBase`; extends it, implements `Scheduler`. Concrete sched_ext samples extend this class.

```java
@BPF(license = "GPL")
public abstract class UserspaceSchedulerBase extends SchedulerBase implements Scheduler {

    static final long FRAMEWORK_DSQ      = 1;
    static final long STALL_FALLBACK_NS  = 50_000_000L;  // 50 ms — see §What stays in BPF for rationale
    static final int  ANY_CPU             = -1;           // wire-compatible with rustland's RL_CPU_ANY sentinel
    static final int  MAX_CPUS           = 1024;
    static final long HEARTBEAT_NS        = 1_000_000_000L; // 1 s — matches rustland's bpf_timer period

    // ─── Per-task storage ─────────────────────────────────────────
    /**
     * Per-task storage allocated lazily in {@link #initTask} and freed in
     * {@code exitTask}. The {@code enqCnt} counter is bumped on every
     * {@link #enqueue} and copied into the kernel→user record; on dispatch
     * the callback compares the record's {@code enqCnt} against the
     * task's *current* {@code enqCnt} and calls {@code scx_bpf_dispatch_cancel}
     * if they diverge (the task was re-queued while Java was deciding).
     * This is rustland's stale-dispatch cancellation path — fuzzers and any
     * latency-sensitive policy depend on it.
     */
    @Type
    record TaskCtx(@Unsigned long enqCnt, @Unsigned long startTs,
                   @Unsigned long stopTs, @Unsigned long execRuntime) {}

    @BPFMapDefinition(maxEntries = 0)   // BPF_MAP_TYPE_TASK_STORAGE — kernel sizes by task count
    BPFTaskStorage<TaskCtx> taskCtx;

    // ─── Maps ────────────────────────────────────────────────────
    // Ringbuf sizes are bytes (kernel requirement: multiple of page size,
    // power of two). 4 MiB ≈ 52k QueuedTaskCtx records at ~80 B each — large
    // enough to absorb fork-storm scenarios (kernel-build, JVM thread bursts)
    // without back-pressuring into SHARED_DSQ. RLIMIT_MEMLOCK cost is 4 MiB
    // per direction = 8 MiB total per scheduler, well below any sane limit.
    //
    // The size is a compile-time @BPFMapDefinition constant; subclasses that
    // need a different size (huge hosts, low-memory targets) override the
    // field with a different maxEntries via @BPFMapDefinition shadowing. This
    // is a class-level decision rather than an Opts knob because the BPF
    // program is sealed at compile time.
    @BPFMapDefinition(maxEntries = 4 * 1024 * 1024)
    BPFRingBuffer<QueuedTaskCtx> queued;              // kernel→user

    @BPFMapDefinition(maxEntries = 4 * 1024 * 1024)
    BPFUserRingBuffer<DispatchedTaskCtx> dispatched;  // user→kernel

    // Arenas are mmap-able by construction (BPFArena emits BPF_F_MMAPABLE).
    // No @BPFMapDefinition(flags=...) plumbing required.
    // NOTE: BPFArena.maxEntries counts PAGES (4 KiB each), not bytes.
    @BPFMapDefinition(maxEntries = 1)                  // 1 page = 4 KiB; holds 128 CPU bits ×… ample
    BPFArena idleMask;                                 // bitmap, mmap'd from Java

    @BPFMapDefinition(maxEntries = 1)                  // 1 page = 4 KiB; SchedStats is 96 B
    BPFTypedArena<SchedStats> stats;                   // mmap'd from Java

    @BPFMapDefinition(maxEntries = 8192)
    BPFHashMap<Integer, Byte> frameworkPids;          // set; value is ignored

    // Per-CPU drain budget — counted down inside dispatchOne so each dispatch()
    // call can't consume more slots than scx_bpf_dispatch_nr_slots() reports.
    // Single-entry array keyed by 0; the BPFPerCpuArray template stamps one
    // counter per CPU automatically.
    @BPFMapDefinition(maxEntries = 1)
    BPFPerCpuArray<Integer> dispatchBudget;

    // Named tgid (not pid) because the comparison in onFork is against the
    // forking thread's *thread-group id*, which is what "scheduler process"
    // means here. The Java side writes ProcessHandle.current().pid() into it
    // (on Linux that returns tgid, despite the method name).
    final GlobalVariable<Integer> schedulerTgid      = new GlobalVariable<>(0);
    final GlobalVariable<@Unsigned Long> lastUserDispatchNs = new GlobalVariable<>(0L);
    final GlobalVariable<@Unsigned Long> lastEnqueueNs      = new GlobalVariable<>(0L);

    // Hint from Java side: "I still have N pending tasks to process".
    // Updated by UserspaceScheduler.notifyComplete(pending). BPF reads this
    // in enqueue() to decide whether to bother waking userspace (if there's
    // still pending work, the kernel→user ringbuf wakeup is suppressed).
    final GlobalVariable<@Unsigned Long> nrUserPending = new GlobalVariable<>(0L);

    final DispatchQueue framework = new DispatchQueue(FRAMEWORK_DSQ);
    final DispatchQueue shared    = DispatchQueue.attach(SHARED_DSQ_ID);

    // ─── sched_ext ops ───────────────────────────────────────────
    // SchedulerBase.init() already creates SHARED_DSQ_ID. We only add FRAMEWORK_DSQ.
    @Override
    public int init() {
        int rc = super.init();
        return rc != 0 ? rc : scx_bpf_create_dsq(FRAMEWORK_DSQ, -1);
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        // Idle short-circuit: when the kernel reports a known-idle CPU, pre-dispatch
        // straight to its SCX_DSQ_LOCAL queue and skip Java entirely. enqueue() will
        // not be called for this task. Mirrors what rustland does in Rust.
        // Falls back to "let enqueue() ship to Java" when no idle CPU is available.
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL.value(), SCX_SLICE_DFL.value(), 0);
            incStat(STAT_IDLE_FAST_PATH, 1);
        }
        return cpu;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        int pid = p.val().pid;
        if (frameworkPids.bpf_get(pid) != null) {
            framework.insertScaled(p, EnqFlags.passThrough(enq_flags));
            incStat(STAT_FRAMEWORK_ENQUEUES, 1);
            return;
        }
        // Kthread fast path: per-CPU kernel threads and the well-known mm
        // helpers (kswapd, khugepaged — their PIDs are written into rodata
        // constants by Java at startup via @ConfigOnStartup) bypass userspace
        // and go straight to the task's last CPU. Routing ksoftirqd/rcuop
        // through Java is a latency footgun rustland explicitly avoids.
        boolean isPerCpuKthread = (p.val().flags & PF_KTHREAD) != 0
                                  && p.val().nr_cpus_allowed == 1;
        if (isPerCpuKthread || pid == kswapdPid.get() || pid == khugepageDPid.get()) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | p.val().scx.cpu,
                               SCX_SLICE_DFL.value(), enq_flags);
            return;
        }
        lastEnqueueNs.set(bpf_ktime_get_ns());
        // Bump the task's enqCnt and stamp it into the record. The drain
        // callback compares this against the task's current enqCnt — if the
        // task was re-queued while in userspace, BPF cancels the stale
        // dispatch via scx_bpf_dispatch_cancel.
        Ptr<TaskCtx> tctx = taskCtx.bpf_get(p);
        if (tctx != null) tctx.val().enqCnt += 1;
        // Wake-suppression hint: if Java's pending backlog (set by
        // notifyComplete) is non-zero, we know Java is already busy and
        // about to read more records — submit without an extra wakeup.
        // Implementation: BPFRingBuffer.submit() takes an optional flags
        // arg; the framework forwards BPF_RB_NO_WAKEUP when nrUserPending > 0,
        // and 0 otherwise. Saves one syscall per task under load.
        Ptr<QueuedTaskCtx> evt = queued.reserve();
        if (evt == null) {
            incStat(STAT_CONGESTION_EVENTS, 1);
            shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
            return;
        }
        fillQueuedCtx(evt, p, enq_flags);     // copies enqCnt from tctx
        if (nrUserPending.get() > 0) queued.submitNoWakeup(evt);
        else                          queued.submit(evt);
        incStat(STAT_NR_QUEUED, 1);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        // `prev` is the task being preempted; we don't need it (the kernel
        // handles re-enqueue of `prev` itself when we don't dispatch it).
        // 1. Drain framework DSQ first — unbounded priority
        if (framework.moveToLocal()) return;

        // 2. Drain Java decisions via user ringbuf. The drain callback dispatches
        //    each record via scx_bpf_dsq_insert; we bound the per-call work to
        //    scx_bpf_dispatch_nr_slots() via a counter in the per-CPU
        //    dispatchBudget array. The callback decrements it and returns 1
        //    (stop) once it hits zero; remaining records stay in the user
        //    ringbuf and drain on the next dispatch() invocation.
        //    Inline lambda (not a method reference) — the compiler plugin's
        //    $lambdaM:code template supports inline (arg) -> { ... } unambiguously.
        int zero = 0;
        Ptr<Integer> budget = dispatchBudget.bpf_lookup_elem(Ptr.of(zero));
        if (budget == null) return;                     // verifier appeasement
        budget.set(scx_bpf_dispatch_nr_slots());
        int drained = dispatched.drain(d -> dispatchOne(d, budget), null);
        // drain returns -errno on hard failure (e.g. -EBUSY mid-iteration).
        // Treat anything > 0 as forward progress; < 0 falls through to the
        // stall path so we don't pretend we made progress when we didn't.
        if (drained > 0) {
            lastUserDispatchNs.set(bpf_ktime_get_ns());
            return;
        }

        // 3. Stall fallback: if there are recent enqueues but Java hasn't
        //    dispatched anything for STALL_FALLBACK_NS, promote from SHARED_DSQ.
        //    Comparing enqueue→dispatch timestamps (not just elapsed since last
        //    dispatch) catches the case where dispatch() is called rarely.
        long now = bpf_ktime_get_ns();
        if (lastEnqueueNs.get() > lastUserDispatchNs.get() &&
            now - lastUserDispatchNs.get() > STALL_FALLBACK_NS) {
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
    // BPF callbacks are static functions (not closures): the compiler plugin
    // lowers `this::dispatchOne` into a free function and threads `this` via
    // the drain `ctx` argument (null here means we only touch program globals
    // and maps, both of which are reachable without `this`).
    //
    // Returns 0 to continue draining, 1 to stop. The drain budget is
    // decremented on each call; when it hits zero we return 1 and the
    // remaining records stay in the user ringbuf for the next dispatch().
    int dispatchOne(Ptr<DispatchedTaskCtx> d, Ptr<Integer> budget) {
        Ptr<task_struct> p = bpf_task_from_pid(d.val().pid);
        if (p == null) { incStat(STAT_BOUNCED_DISPATCHES, 1); return 0; }
        // Stale-dispatch cancellation: the task was re-queued while Java was
        // deciding, so this dispatch is for an obsolete state. Drop and bump
        // bouncedDispatches; the new enqueue will produce a fresh record.
        Ptr<TaskCtx> tctx = taskCtx.bpf_get(p);
        if (tctx != null && tctx.val().enqCnt != d.val().enqCnt) {
            bpf_task_release(p);
            incStat(STAT_BOUNCED_DISPATCHES, 1);
            int remaining0 = budget.val() - 1;
            budget.set(remaining0);
            return remaining0 <= 0 ? 1 : 0;
        }
        long slice = d.val().sliceNs == 0 ? 5_000_000L : d.val().sliceNs;
        int targetCpu = d.val().targetCpu;
        if (targetCpu < 0) {                                // ANY_CPU sentinel
            scx_bpf_dsq_insert(p, SHARED_DSQ_ID, slice, d.val().flags);
            // Without this kick, an ANY_CPU dispatch can sit in SHARED_DSQ
            // until something else wakes a CPU — visible as inflated
            // dispatchToRunningNs. Matches rustland's kick_task_cpu().
            scx_bpf_kick_cpu(p.val().scx.cpu, SCX_KICK_IDLE);
        } else {
            // Affinity validation: a policy can pick a CPU that's no longer
            // in the task's cpumask (cpuset change, hotplug). Fall back to
            // the task's prev_cpu rather than letting the kernel reject the
            // dispatch silently.
            if (!bpf_cpumask_test_cpu(targetCpu, p.val().cpus_ptr)) {
                targetCpu = p.val().scx.cpu;
                incStat(STAT_BOUNCED_DISPATCHES, 1);
            }
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | targetCpu, slice, d.val().flags);
        }
        bpf_task_release(p);
        incStat(STAT_USER_DISPATCHES, 1);
        int remaining = budget.val() - 1;
        budget.set(remaining);
        return remaining <= 0 ? 1 : 0;
    }

    // ─── Per-task lifecycle ops ──────────────────────────────────
    // running/stopping/runnable populate QueuedTask.startTs/stopTs/execRuntime/weight.
    // Without these, those fields are dead (rustland wires them all up; the spec
    // surfaces them in @Type so subclasses can sort/filter on them).

    @Override
    public int initTask(Ptr<task_struct> p, Ptr<scx_init_task_args> args) {
        Ptr<TaskCtx> t = taskCtx.bpf_get_or_create(p);
        if (t == null) return -ENOMEM;
        t.val().enqCnt = 0;
        t.val().startTs = 0;
        t.val().stopTs  = 0;
        t.val().execRuntime = 0;
        return 0;
    }

    @Override
    public void runnable(Ptr<task_struct> p, long enq_flags) {
        // No-op for the framework; subclasses can override. Present so
        // policies that want "task is now runnable" notifications can hook
        // into the same call site rustland exposes.
    }

    @Override
    public void running(Ptr<task_struct> p) {
        Ptr<TaskCtx> t = taskCtx.bpf_get(p);
        if (t != null) t.val().startTs = bpf_ktime_get_ns();
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        Ptr<TaskCtx> t = taskCtx.bpf_get(p);
        if (t == null) return;
        @Unsigned long now = bpf_ktime_get_ns();
        t.val().stopTs = now;
        if (t.val().startTs != 0) {
            t.val().execRuntime += now - t.val().startTs;
            t.val().startTs = 0;
        }
    }

    // exitTask: task_storage maps are freed automatically by the kernel
    // on task exit, so no manual cleanup is required.

    // ─── Heartbeat timer ─────────────────────────────────────────
    // A periodic bpf_timer kicks the scheduler's CPU once per HEARTBEAT_NS.
    // On a fully idle system (no wakeups, no enqueues) the Java run loop can
    // otherwise starve and trip the sched_ext watchdog before STALL_FALLBACK_NS
    // ever fires. Rustland calls this exact mechanism out as load-bearing.
    @BPFMapDefinition(maxEntries = 1)
    BPFArray<bpf_timer> heartbeat;

    @BPFFunction
    int heartbeatTick(Ptr<bpf_timer> t) {
        // Wake whichever CPU is most likely to pick up the Java loop next.
        // The framework records the scheduler thread's last CPU on each
        // poll-return; SCX_KICK_IDLE rather than SCX_KICK_PREEMPT keeps
        // the cost trivial on a busy machine.
        scx_bpf_kick_cpu(schedulerCpu.get(), SCX_KICK_IDLE);
        bpf_timer_start(t, HEARTBEAT_NS, 0);
        return 0;
    }
    // initHeartbeat() is called from init(): bpf_timer_init + bpf_timer_set_callback
    // + bpf_timer_start(HEARTBEAT_NS). Boilerplate, omitted here for brevity.

    final GlobalVariable<Integer> schedulerCpu = new GlobalVariable<>(0);
    // Well-known kthread PIDs, populated by Java at startup via /proc lookup.
    // 0 means "not found" — the comparison in enqueue() naturally skips it.
    final GlobalVariable<Integer> kswapdPid      = new GlobalVariable<>(0);
    final GlobalVariable<Integer> khugepageDPid  = new GlobalVariable<>(0);
}
```

Plus a sibling **tracepoint sub-program** that auto-registers child *threads* (not *processes*) of the scheduler into `frameworkPids`. The tracepoint lives in the *same* BPF program as the struct_ops — verified working in `TracepointAnnotationTest` (mixed sections compile and load together). Attachment, however, is split: `attachScheduler()` only wires the struct_ops; the tracepoint needs `autoAttachPrograms()`:

```java
@Tracepoint(category = "sched", name = "sched_process_fork")
int onFork(Ptr<TracepointSchedProcessFork> ctx) {
    // CLONE_THREAD: child tgid == parent tgid → same Java process → register.
    // Fork creating a new process (e.g. test JVM exec'ing stress-ng): different
    // tgid → MUST NOT register, or the workload itself gets framework priority.
    int parentTgid = ctx.val().parent_tgid;
    int childTgid  = ctx.val().child_tgid;
    if (parentTgid == schedulerTgid.get() && childTgid == parentTgid) {
        byte one = 1;
        frameworkPids.bpf_update(ctx.val().child_pid, one, BPF_ANY);
    }
    return 0;
}
```

The same-tgid filter is **load-bearing**: without it, `stress-ng --cpu 4` (forked by the test JVM during the smoke test) would be registered as framework threads and given priority over its own workload. The Java-side `rescanFrameworkPids` also filters: `/proc/self/task/` only ever contains *threads of the current process*, so it's correct by construction.

### 3. `UserspaceScheduler` (new, ~250 LOC)

Path: `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceScheduler.java`

(Lives in the `bpf` module next to `Scheduler.java` and `SchedulerBase.java`. The `bpf-runtime` module is reserved for generated kernel struct definitions.)

Java-side framework. Subclasses pick **one** of two override styles:

- **`policy(QueuedTask)`** — easy path. Framework drains the kernel→user ringbuf, calls `policy()` per task, and notifies the BPF side at the end of each batch. Modelled on the `scx_rlfifo` ergonomic.
- **`schedule()`** — low-level pull-loop. Override this when the policy needs to drain all queued tasks, sort them, then dispatch (the `scx_rustland` deadline-ordering pattern). The user calls `dequeueTask()` / `dispatch(...)` / `notifyComplete(pending)` themselves.

Only one of the two needs to be overridden. The default `schedule()` body is the per-task-callback wrapper.

```java
public abstract class UserspaceScheduler implements AutoCloseable {

    // ANY_CPU sentinel lives on DispatchedTask (the only place it's assigned to)
    // so there's one canonical location, not two.

    // Held as the concrete base class so the framework can reach typed map and
    // global fields directly (queued, dispatched, idleMask, stats, schedulerTgid)
    // without string-keyed lookups. Private + final: the framework writes
    // schedulerTgid exactly once, in the load→attach sequence; subclasses
    // should NOT touch it. The protected accessor below covers the rare
    // case where a subclass needs program-level access (e.g. tracepoint
    // handles via getProgramByName).
    private final UserspaceSchedulerBase prog;

    /**
     * Read-only handle to the underlying BPF program. Use sparingly — the
     * framework owns the {@code schedulerTgid} write and all map-lifecycle
     * concerns. Exposed for {@code getProgramByName} / explicit attach calls
     * a subclass might need.
     */
    protected final UserspaceSchedulerBase program() { return prog; }

    private final ScheduledExecutorService rescanner;
    private final AtomicBoolean shutdownRequested = new AtomicBoolean(false);

    // Pooled DispatchedTask for the framework path; user policies that want
    // their own pool can ignore this and pass freshly-constructed records.
    private final DispatchedTask pooledDispatched = new DispatchedTask();

    protected UserspaceScheduler(UserspaceSchedulerBase prog, Opts opts) { ... }

    /** Convenience overload: uses {@link Opts#defaults()}. */
    protected UserspaceScheduler(UserspaceSchedulerBase prog) {
        this(prog, Opts.defaults());
    }

    // ─── Single-call entry point ─────────────────────────────────
    /**
     * Start the scheduler and block until {@link #exited()} returns true.
     * When {@code Opts.installShutdownHook} is true (default) the framework
     * registers a {@link Runtime#addShutdownHook} that flips
     * {@code shutdownRequested} and waits for the loop to drain — this is
     * the portable replacement for {@code sun.misc.Signal} (which is an
     * encapsulated API on JDK 21+). Ctrl-C therefore triggers a clean exit
     * with no opens-to-internal-API warnings.
     *
     * <p>The framework handles the load-bearing attach ordering (set
     * schedulerTgid → autoAttachPrograms → attachScheduler → initial rescan
     * → periodic rescan), then enters the schedule loop.
     */
    public final void runUntilExit() {
        if (opts.installShutdownHook) installShutdownHook();
        prog.schedulerTgid.set((int) ProcessHandle.current().pid());
        prog.autoAttachPrograms();
        prog.attachScheduler();
        rescanFrameworkPids();
        rescanner.scheduleAtFixedRate(this::rescanFrameworkPids, 1, 1, SECONDS);
        try {
            while (!exited()) {
                schedule();
            }
        } finally {
            rescanner.shutdownNow();
        }
    }

    /**
     * True when shutdown should commence. ORs together: SIGINT received,
     * BPF UEI set, or the struct_ops detached ({@code isSchedulerAttachedProperly() == false}).
     * Mirrors rustland's {@code BpfScheduler::exited()} — one predicate covers
     * all paths.
     */
    public final boolean exited() {
        return shutdownRequested.get()
            || prog.getExitCode() != 0
            || !prog.isSchedulerAttachedProperly();
    }

    // ─── User-overridable hooks ──────────────────────────────────
    /**
     * Per-task callback. Default behaviour for batch users: dispatch every
     * queued task to the kernel's idle pick (or SHARED on miss), with
     * framework-default slice. Override to customise per-task decisions.
     *
     * <p>If you need batched ordering (sort all queued tasks before
     * dispatching), override {@link #schedule()} instead.
     */
    protected void policy(QueuedTask task) {
        dispatch(task);                          // kernel-pick CPU, default slice
    }

    /**
     * One iteration of the schedule loop. The default body drains the
     * kernel→user ringbuf in batches, calls {@link #policy(QueuedTask)} per
     * task, and calls {@link #notifyComplete(long)}. Override when you need
     * full control (e.g. drain-then-sort-then-dispatch).
     *
     * <p>{@link #notifyComplete(long)} MUST be called at the end of each
     * iteration — the framework's try-with-resources {@link Batch} below
     * makes this impossible to forget.
     */
    protected void schedule() {
        try (Batch batch = dequeueBatch()) {
            while (batch.hasNext()) {
                QueuedTask t = batch.next();   // flyweight; valid until next()
                try {
                    policy(t);
                } catch (Throwable th) {
                    onPolicyException(th);
                }
            }
        }
        // batch.close() calls notifyComplete() with the framework's count of
        // Java-produced-but-not-yet-BPF-drained records (nrScheduled -
        // userDispatches). Override schedule() if you need to report a
        // different value (e.g. policy-internal backlog from drain-then-sort).
    }

    // ─── Hot-path API for subclasses ─────────────────────────────

    /**
     * Open a batch dequeue scope. Iterating drains records from the
     * kernel→user ringbuf into a per-thread pooled {@link QueuedTask}
     * flyweight (zero allocation per task). Closing the batch calls
     * {@link #notifyComplete(long)} with {@code nrScheduled - userDispatches}
     * (records Java produced that BPF hasn't yet drained).
     */
    protected final Batch dequeueBatch();

    /**
     * Pull a single record (rustland-style). Returns the framework's
     * pooled {@link QueuedTask}, or null when the ringbuf is drained.
     * The returned record is invalidated by the next call to dequeueTask().
     * Caller is responsible for calling {@link #notifyComplete(long)} when
     * done draining.
     */
    protected final QueuedTask dequeueTask();

    /**
     * Convenience: dispatch {@code task} with {@code targetCpu = ANY_CPU} and
     * the framework's default slice (no special flags). Routes to
     * {@code SHARED_DSQ}, letting the kernel pick the actual CPU at dispatch
     * time — zero syscall on the Java side, unlike {@link #selectCpu}.
     * Equivalent to filling out a {@link DispatchedTask} with
     * {@code targetCpu = ANY_CPU} and calling {@link #dispatch(DispatchedTask)},
     * but allocation-free and one line at the call site.
     *
     * <p>This is what most per-task policies want. Use the explicit
     * {@link #dispatch(DispatchedTask)} when you need a specific CPU,
     * non-default slice, vtime, or dispatch flags; call {@link #selectCpu}
     * or {@link #pickIdleCpu} first if you want to make the CPU choice
     * yourself rather than deferring to {@code SHARED_DSQ}.
     */
    protected final void dispatch(QueuedTask task);

    /**
     * Submit a dispatch decision. Silently drops on user-ringbuf full
     * (back-pressure); the framework increments {@code cancelledDispatches}
     * so user policies can't lose tasks unnoticed. On drop, the BPF stall
     * fallback will eventually rescue the task via SHARED_DSQ.
     *
     * <p>Use {@link #tryDispatch(DispatchedTask)} if you need the boolean
     * back-pressure signal (e.g. to count failed dispatches in a custom
     * {@link #schedule()} override and pass the count to
     * {@link #notifyComplete(long)}).
     */
    protected final void dispatch(DispatchedTask d);

    /**
     * Submit a dispatch decision and return whether it was accepted.
     * Returns {@code false} on user-ringbuf full (back-pressure); the framework
     * still increments {@code cancelledDispatches} on the false path. The
     * boolean is exposed for policies that need to count their own failed
     * dispatches — most policies should just call {@link #dispatch(DispatchedTask)}.
     */
    protected final boolean tryDispatch(DispatchedTask d);

    /**
     * Run the kernel's default CPU picker for {@code pid} via
     * {@code scx_bpf_select_cpu_dfl}. Returns a CPU id (>=0) when an idle CPU
     * is available, or {@link DispatchedTask#ANY_CPU} ({@code -1}) otherwise —
     * same sentinel as {@link #pickIdleCpu}, so the result can be assigned
     * directly to {@code DispatchedTask.targetCpu}. SMT/NUMA awareness comes
     * from the kernel's built-in idle cpumask construction (which already
     * respects topology); no Java-side flags configure it.
     *
     * <p><b>Cost.</b> Crosses into the kernel via a bpf-syscall round-trip
     * (~1–3 µs depending on host). Use when topology awareness matters —
     * e.g. core/cluster preference, hyperthread avoidance — and the round-trip
     * cost is acceptable. For the hot path, prefer {@link #pickIdleCpu}.
     */
    protected final int selectCpu(int pid, int prevCpu, long flags);

    /**
     * Zero-syscall fallback: read the idle CPU bitmap (mmap'd
     * {@link BPFArena}) and return an idle CPU, or {@link DispatchedTask#ANY_CPU}
     * ({@code -1}) when none are idle. The "no idle CPU" sentinel is
     * deliberately the same value as the "dispatch to SHARED_DSQ" sentinel —
     * a policy can write {@code d.targetCpu = pickIdleCpu();} and route to
     * the shared queue on miss without a conditional.
     *
     * <p><b>Picking strategy.</b> Round-robin via a single {@link java.util.concurrent.atomic.AtomicInteger}
     * cursor on the {@link UserspaceScheduler} instance: each call advances
     * the cursor with {@code getAndIncrement()} and searches the bitmap from
     * {@code cursor % nr_cpu_ids}, wrapping at {@code nr_cpu_ids}. In the
     * common case there is one caller (the run-loop thread) and the atomic
     * is effectively free; concurrent calls just produce slightly worse CPU
     * choices, never wrong ones. Matches the kernel's
     * {@code cpumask_any_distribute()} algorithm (used by
     * {@code bpf_cpumask_any_distribute} and indirectly by
     * {@code scx_bpf_pick_idle_cpu}). Avoids both the cache-warm-CPU-0 bias of
     * "lowest-numbered idle" and the per-call random-bit overhead.
     *
     * <p><b>Cost.</b> A handful of memory loads, no syscall. Coarser than
     * {@link #selectCpu} — does not consult SMT siblings or NUMA. Recommended
     * for the per-task hot path where you'd otherwise be calling
     * {@code selectCpu} per record.
     */
    protected final int pickIdleCpu();

    /**
     * Tell BPF "I'm done dispatching for now; here is the pending count".
     * MUST be called exactly once at the end of every schedule iteration.
     * The default {@link #schedule()} handles this via {@code Batch.close()};
     * manual {@code dequeueTask()} users should prefer {@link #tick()} instead
     * (try-with-resources) so the call is impossible to forget.
     *
     * <p>Mutually exclusive with {@link #tick()} — calling {@code notifyComplete}
     * inside an open {@code Tick} scope double-counts the pending value, since
     * {@code Tick.close()} also fires {@code notifyComplete}. Pick one mechanism
     * per iteration.
     *
     * <p>Writes {@code pending} into the BPF program's {@code nrUserPending}
     * global, which BPF's {@code enqueue()} consults to skip the kernel→user
     * wakeup when Java already has work queued up.
     */
    protected final void notifyComplete(long pending);

    /**
     * Open a try-with-resources tick scope for custom {@link #schedule()}
     * overrides that pull via {@link #dequeueTask()}. Closing the tick fires
     * {@link #notifyComplete(long)} with whatever the user has accumulated
     * via {@link Tick#addPending(long)} — making the call impossible to
     * forget. Use this in place of a manual {@code notifyComplete} call:
     *
     * <pre>{@code
     * @Override
     * protected void schedule() {
     *     try (Tick tick = tick()) {
     *         QueuedTask t;
     *         while ((t = dequeueTask()) != null) {
     *             if (!tryDispatch(decide(t))) tick.addPending(1);
     *         }
     *     }
     * }
     * }</pre>
     */
    protected final Tick tick();

    /**
     * Allocate-and-return snapshot of all 12 counters. Convenient for one-off
     * reads ({@code System.out.println(sched.stats())}); allocates one
     * {@link SchedStatsSnapshot} per call.
     *
     * <p>Hot-path callers (per-tick logging, dashboards) should preallocate a
     * snapshot and use {@link #readStatsInto(SchedStatsSnapshot)} instead to
     * avoid per-read allocation.
     */
    public final SchedStatsSnapshot stats();

    /** Snapshot all 12 counters into a caller-owned record (zero alloc). */
    public final void readStatsInto(SchedStatsSnapshot dest);

    /**
     * Pretty-print this scheduler's current stats as a single line suitable
     * for periodic logging. Mirrors {@code BpfScheduler::print_stats()} in
     * rustland. Equivalent to {@code stats().format()}; allocates one
     * snapshot per call.
     *
     * <p>Hot-path callers should preallocate a snapshot and call
     * {@code snap.format()} after each {@link #readStatsInto(SchedStatsSnapshot)}.
     */
    public final String formatStats();

    /** Print all observability histograms to {@code out}. Layer 1 from §Observability. */
    public final void printHistograms(java.io.PrintStream out);

    /**
     * Hook for policy() exceptions; default rate-limits a warn() to 1/s and
     * increments {@code policyExceptions}. Visible (protected) so custom
     * {@code schedule()} overrides can call it from their own catch blocks to
     * get the counter and rate-limited logging for free.
     */
    protected void onPolicyException(Throwable t) { /* default impl */ }

    // ─── Framework internals (not part of the user API) ──────────
    private void installShutdownHook() {
        // Runtime.addShutdownHook blocks JVM exit until the hook returns, so
        // we can drain the run loop cleanly. No encapsulated-API warnings.
        //
        // Caveat: the hook only signals the loop; the JVM may begin tearing
        // down other shutdown hooks (logging, System.err flush) concurrently.
        // Code that wants a guaranteed final stats print should run it from
        // the main thread *before* returning from main() — try-with-resources
        // around runUntilExit() (as in RustlandFifoSample) does exactly that.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            shutdownRequested.set(true);
        }, "userspace-scheduler-shutdown"));
    }
    private void rescanFrameworkPids()  { /* /proc/self/task/ → prog.frameworkPids */ }

    // ─── AutoCloseable: delegate to prog.close() ──────────────────
    @Override public void close() { prog.close(); }
}

/**
 * Try-with-resources batch dequeue scope. Closing the batch fires
 * {@link UserspaceScheduler#notifyComplete(long)} — the user cannot
 * forget the call that prevents the BPF busy-loop wakeup. Nested
 * class of {@link UserspaceScheduler} so user code reads
 * {@code UserspaceScheduler.Batch}.
 */
public final class Batch implements AutoCloseable {
    public boolean hasNext();
    public QueuedTask next();                // pooled flyweight, invalidated by next()

    /**
     * Number of records drained from the kernel→user ringbuf into this batch.
     * Exact value — the framework increments it once per successful drain
     * callback. Available before, during, and after iteration; useful for
     * subclasses overriding {@link #schedule()} that need to size internal
     * collections (e.g. {@code new ArrayList<>(batch.size())}) before walking
     * the batch with {@code hasNext()} / {@code next()}.
     */
    public int size();

    /**
     * Diagnostic-only: approximate count of records still in the kernel→user
     * ringbuf at the moment {@link #close()} fires. Derived from libbpf's
     * {@code ring_buffer__producer_pos} − {@code consumer_pos} delta divided
     * by {@code sizeof(QueuedTaskCtx)}. Off by ≤1–2 records (producer is the
     * kernel and may advance concurrently).
     *
     * <p><b>Not</b> the value passed to {@link #notifyComplete(long)}. That
     * value is the framework's internal `nrUserPending` counter — the count
     * of tasks Java has produced but not yet seen a corresponding kernel
     * dispatch for — which is what the BPF side needs to suppress its wakeup.
     * This getter exists for logging and back-pressure diagnostics only.
     */
    public long ringbufDepthSnapshot();
    // No forEach() — explicit while(hasNext()) gives users a place to put a
    // per-task try/catch + onPolicyException() call. forEach would either
    // swallow exceptions silently or skip the counter, both surprising.
    @Override public void close();           // notifyComplete(nrScheduled - userDispatches)
}

/**
 * Try-with-resources tick scope for custom {@link UserspaceScheduler#schedule()}
 * overrides that pull tasks via {@link UserspaceScheduler#dequeueTask()}.
 * Closing the tick fires {@link UserspaceScheduler#notifyComplete(long)} with
 * the running {@link #addPending(long)} total — the user cannot forget the
 * call that prevents the BPF busy-loop wakeup. Same role for the manual-pull
 * path that {@link Batch} fills for the per-task-callback path.
 */
public final class Tick implements AutoCloseable {
    /** Add to the pending count reported to BPF on close. Safe to call repeatedly. */
    public void addPending(long delta);

    /** Current accumulated pending count. */
    public long pending();

    @Override public void close();           // calls notifyComplete(pending())
}

/**
 * Construction-time settings. Builder-style so the user can override only the
 * fields they care about; default values come from a no-arg static factory.
 * Made a nested class of {@link UserspaceScheduler} so user code reads
 * {@code UserspaceScheduler.Opts.builder().batchSize(128).numaLocal(true).build()}.
 *
 * <p>The common case is "I want defaults" — written {@code Opts.defaults()},
 * which returns a built {@code Opts} (no trailing {@code .build()}). The
 * customisation case is {@code Opts.builder().field(value).build()}.
 *
 * <p>Why a builder and not mutable public fields like {@link QueuedTask}?
 * {@code Opts} is a one-shot value: built once at scheduler construction, never
 * mutated afterwards. The hot-path records are mutable because they are pooled
 * flyweights refilled on every task; {@code Opts} has no such constraint, and
 * a builder gives the user a self-documenting `.field(value)` call site and
 * prevents accidental mid-flight reconfiguration.
 */
public static final class Opts {
    public final int batchSize;
    public final boolean builtinIdle;
    public final boolean numaLocal;
    public final long defaultSliceNs;
    public final boolean verifyZgcOnStart;
    public final boolean installShutdownHook;
    public final boolean enableLatencyHistograms;
    public final boolean enableJfrEvents;
    public final int histogramPrintIntervalS;
    /**
     * Partial mode: when true, the framework loads the struct_ops with
     * {@code SCX_OPS_SWITCH_PARTIAL} and only tasks explicitly placed in
     * the SCHED_EXT class (via {@code sched_setscheduler} or the
     * {@code chrt} CLI) flow through this scheduler — everything else
     * stays on CFS. Matches rustland's {@code partial} init knob.
     * Default false (whole-system scheduling). Recommended for dev/test
     * so a misbehaving policy can't take down the whole machine.
     */
    public final boolean partialMode;
    /** Size of the BPF UEI exit-info dump buffer (rustland's {@code exit_dump_len}). */
    public final int exitDumpLen;

    private Opts(Builder b) { /* copy from builder */ }

    /** Built {@code Opts} pre-loaded with sensible defaults — the common case. */
    public static Opts defaults() { return new Builder().build(); }

    /** Start a builder pre-loaded with sensible defaults — for customisation. */
    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private int batchSize = 64;
        private boolean builtinIdle = true;       // honour SMT topology
        private boolean numaLocal = false;        // prefer node-local CPUs
        private long defaultSliceNs = 5_000_000L;
        private boolean verifyZgcOnStart = true;  // warn (not fatal) if not ZGC
        private boolean installShutdownHook = true;
        private boolean enableLatencyHistograms = true;
        private boolean enableJfrEvents = true;
        private int histogramPrintIntervalS = 0;  // 0 = never auto-print
        private boolean partialMode = false;
        private int exitDumpLen = 64 * 1024;      // matches rustland's default

        public Builder batchSize(int v)              { this.batchSize = v; return this; }
        public Builder builtinIdle(boolean v)        { this.builtinIdle = v; return this; }
        public Builder numaLocal(boolean v)          { this.numaLocal = v; return this; }
        public Builder defaultSliceNs(long v)        { this.defaultSliceNs = v; return this; }
        public Builder verifyZgcOnStart(boolean v)   { this.verifyZgcOnStart = v; return this; }
        public Builder installShutdownHook(boolean v){ this.installShutdownHook = v; return this; }
        public Builder enableLatencyHistograms(boolean v) { this.enableLatencyHistograms = v; return this; }
        public Builder enableJfrEvents(boolean v)    { this.enableJfrEvents = v; return this; }
        public Builder histogramPrintIntervalS(int v){ this.histogramPrintIntervalS = v; return this; }
        public Builder partialMode(boolean v)        { this.partialMode = v; return this; }
        public Builder exitDumpLen(int v)            { this.exitDumpLen = v; return this; }

        public Opts build() { return new Opts(this); }
    }
}
```

**Struct_ops flags.** The framework unconditionally sets `SCX_OPS_ENQ_LAST | SCX_OPS_ALLOW_QUEUED_WAKEUP` on the struct_ops at attach time, matching rustland. `ALLOW_QUEUED_WAKEUP` enables the "queued wakeup → direct dispatch to idle CPU" kernel fast path that the spec's idle short-circuit in `selectCPU` already relies on; `ENQ_LAST` prevents the kernel from re-enqueuing the last-runnable task back into the same DSQ during preemption (which would otherwise look like a phantom enqueue from Java's perspective). When `Opts.partialMode = true`, `SCX_OPS_SWITCH_PARTIAL` is added; `Opts.exitDumpLen` populates the struct_ops `exit_dump_len` field.

**Data records** (mutable public fields, rustland-style — no builders):

```java
/** kernel→user record. Mirrors scx_rustland_core's QueuedTask. */
public final class QueuedTask {
    public int pid;
    public int prevCpu;        // last CPU it ran on, or -1 (renamed from `cpu`)
    public long nrCpusAllowed;
    public long flags;
    public long startTs;
    public long stopTs;
    public long execRuntime;
    public long weight;        // [1..10000], default 100 — matches rustland
    public long vtime;
    public long enqCnt;

    // The raw 16-byte command name is package-private — callers should use
    // commStr() / commEquals() rather than poking the bytes. Exposed at
    // package level for the framework's marshalling code and zero-alloc
    // unit tests; not part of the user-facing API.
    final byte[] comm = new byte[16];

    /** Trimmed, null-terminated command name as a String. Allocates one String per call. */
    public String commStr() { /* trim null-terminated bytes */ }

    /**
     * Zero-alloc equivalent of {@code commStr().equals(other)} — compares the
     * raw bytes against {@code other} without allocating an intermediate String.
     * Use on the hot path; use {@link #commStr()} when you actually need the
     * String (logging, JFR events).
     */
    public boolean commEquals(String other) { /* byte-wise compare up to NUL */ }

    public QueuedTask() {}

    /**
     * Allocating copy constructor. Use when a policy needs to hold a task
     * reference past the next {@code dequeueTask()} / {@code batch.next()}
     * call (the framework's pooled flyweight is invalidated then). Allocates
     * one {@code QueuedTask} + one {@code byte[16]} per call — fine for
     * drain-then-sort patterns that allocate once per drained record, not
     * suitable for the steady-state hot path.
     */
    public QueuedTask(QueuedTask src) { /* copy all fields, deep-copy comm[] */ }
}

/** user→kernel record. Fill via {@link #fillFrom(QueuedTask)} — never new on the hot path. */
public final class DispatchedTask {
    /** Sentinel value for {@link #targetCpu}: "no specific CPU, use SHARED_DSQ". */
    public static final int ANY_CPU = -1;

    public int pid;
    public int targetCpu;      // ANY_CPU (-1) = SHARED_DSQ
    public long flags;
    public long sliceNs;       // 0 = framework default slice
    public long vtime;         // 0 = monotonic
    public long enqCnt;        // propagated from QueuedTask for correlation

    /** Public no-arg constructor for pool initialisation only. */
    public DispatchedTask() {}

    /**
     * Zero-alloc fill: copies pid/flags/enqCnt from {@code q} into {@code this}
     * and clears the dispatch fields (targetCpu = ANY_CPU, sliceNs = 0,
     * vtime = 0). Returns {@code this} so call sites can chain
     * ({@code scratch.fillFrom(task); scratch.targetCpu = c; dispatch(scratch);}). The intended use
     * is on a long-lived pooled instance — either the framework's
     * {@code pooledDispatched} or the policy's own scratch field.
     */
    public DispatchedTask fillFrom(QueuedTask q) { /* … */ return this; }

    /**
     * Static equivalent for the rare call site that prefers a function-style
     * expression. Delegates to {@code into.fillFrom(q)}. Kept for parity with
     * the rustland reference; new code should prefer the instance form.
     */
    public static DispatchedTask from(QueuedTask q, DispatchedTask into) {
        return into.fillFrom(q);
    }
}
```

**No `policy()` is abstract** — both overrides are optional. Subclassing without overriding either compiles, and you get the default "kernel picks CPU, framework picks slice" behaviour (the same trivial pass-through scx_rlfifo runs out of the box).

The framework cannot enforce JVM tuning. Its class javadoc and the dedicated `docs/userspace-scheduler.md` page document the required flags (see [JVM tuning](#jvm-tuning) below). When `Opts.verifyZgcOnStart=true` (the default) the constructor checks `GarbageCollectorMXBean` names and emits a one-time `Logger.warning(...)` if ZGC is not active — never fatal, never `System.err`, and never repeated. Users who deliberately run a non-ZGC profile can set the flag to `false` to suppress the warning entirely.

### 4. Samples (new, ~280 LOC total)

Three samples ship in v1, each exercising a different slice of the API to prove the framework generalises beyond a single policy shape:

| Sample                | LOC  | Override style        | What it demonstrates                                               |
|-----------------------|------|-----------------------|--------------------------------------------------------------------|
| `RustlandFifoSample`  | ~80  | `policy(QueuedTask)`  | Minimal per-task callback; `pickIdleCpu()` fast path               |
| `WeightedRRSample`    | ~90  | `policy(QueuedTask)`  | `QueuedTask.weight` end-to-end; per-PID counters in a Java map     |
| `LotterySample`       | ~110 | `schedule()`          | Drain-then-sort; ticket-pool RNG; flyweight invalidation handling  |

A drain-then-sort *sketch* for the deadline-ordering pattern follows the three samples — included for the API-coverage argument but not shipped.

#### 4a. `RustlandFifoSample` (~80 LOC)

Path: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandFifoSample.java`

The simplest possible sample. Two top-level types live in one file: the BPF program (`RustlandFifoSample`) and the policy wrapper (`FifoPolicy`, a nested static class) — kept separate at the class level because their lifecycles are independent (the BPF program may outlive a particular policy instance), but co-located in one file so the sample reads as a single ~20-line story:

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "rustland_fifo_java")
@Property(name = "timeout_ms", value = "10000")
public abstract class RustlandFifoSample extends UserspaceSchedulerBase {

    /**
     * Trivial FIFO: dispatch each queued task to an idle CPU via the cheap
     * mmap'd idle-bitmap ({@code pickIdleCpu}), falling back to the shared DSQ.
     * The framework's default {@code policy()} would also work here but uses
     * the syscalling {@code selectCpu} — this override demonstrates how to
     * trade per-task topology awareness for ~1–3 µs saved per record.
     */
    public static final class FifoPolicy extends UserspaceScheduler {
        private final DispatchedTask scratch = new DispatchedTask();

        public FifoPolicy(RustlandFifoSample prog) {
            super(prog);                                    // Opts.defaults()
        }

        @Override
        protected void policy(QueuedTask task) {
            scratch.fillFrom(task);
            scratch.targetCpu = pickIdleCpu();              // -1 ⇒ SHARED_DSQ
            dispatch(scratch);                              // silent drop on full; counted as cancelledDispatches
        }
    }

    public static void main(String[] args) throws Exception {
        try (var prog  = BPFProgram.load(RustlandFifoSample.class);
             var sched = new FifoPolicy(prog)) {
            sched.runUntilExit();
            // sched.stats() allocates one snapshot — fine on the cold exit path.
            // Hot-path users keep a preallocated snapshot + readStatsInto(snap).
            var snap = sched.stats();
            System.out.printf("final: user=%d kernel=%d congestion=%d exc=%d%n",
                snap.userDispatches, snap.kernelDispatches,
                snap.congestionEvents, snap.policyExceptions);
        }
    }
}
```

A user who wants stats output writes a tiny side thread or just polls in their own loop — there's no framework `tick()` hook to learn, no `tickIntervalNs()` override, no inversion of control. `readStatsInto(snap)` is O(1) and they can call it from anywhere.

#### 4b. `WeightedRRSample` (~90 LOC)

Path: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/WeightedRRSample.java`

Proves the `QueuedTask.weight` field flows kernel → BPF → Java intact, and that per-task Java-side state (a plain `HashMap`) survives across calls without leaking on task exit. Scales the dispatched slice proportional to the task's static priority (`nice` value → weight), exactly the data path a real weighted-fair-share scheduler needs.

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "weighted_rr_java")
@Property(name = "timeout_ms", value = "10000")
public abstract class WeightedRRSample extends UserspaceSchedulerBase {

    /** Default weight is 100 (nice 0); range [1..10000]. Slice = base * weight/100. */
    public static final class WeightedRRPolicy extends UserspaceScheduler {
        private static final long BASE_SLICE_NS = 1_000_000L;     // 1 ms at nice 0
        private static final long MAX_SLICE_NS  = 20_000_000L;    // clamp at 20 ms

        /** Total dispatched slice per PID — proves Java-side state stays consistent. */
        private final Map<Integer, Long> servedNs = new HashMap<>();
        private final DispatchedTask scratch = new DispatchedTask();

        public WeightedRRPolicy(WeightedRRSample prog) { super(prog); }

        @Override
        protected void policy(QueuedTask task) {
            long slice = Math.min(MAX_SLICE_NS, BASE_SLICE_NS * task.weight / 100);
            scratch.fillFrom(task);
            scratch.sliceNs  = slice;
            scratch.targetCpu = pickIdleCpu();
            dispatch(scratch);
            servedNs.merge(task.pid, slice, Long::sum);
        }

        /** Called from the shutdown hook — prints the top-10 served PIDs. */
        public void printTopServed(int n) {
            servedNs.entrySet().stream()
                    .sorted(Map.Entry.<Integer, Long>comparingByValue().reversed())
                    .limit(n)
                    .forEach(e -> System.out.printf("  pid=%d  served=%.1f ms%n",
                            e.getKey(), e.getValue() / 1_000_000.0));
        }
    }

    public static void main(String[] args) throws Exception {
        try (var prog  = BPFProgram.load(WeightedRRSample.class);
             var sched = new WeightedRRPolicy(prog)) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> sched.printTopServed(10)));
            sched.runUntilExit();
        }
    }
}
```

The `servedNs` map will grow until process exit — fine for a demo, since hello-ebpf samples are short-lived. A production weighted-RR would prune on `init_task`/`exit_task` callbacks; the spec lists that under §"Implementation order step 5" for the framework hooks.

#### 4c. `LotterySample` (~110 LOC)

Path: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LotterySample.java`

The fun one, and the **first sample that overrides `schedule()` instead of `policy()`**. Implements proper Waldspurger/Weihl-style lottery scheduling: every queued task holds `weight` lottery tickets; on each dispatch, a uniform RNG draws a winner proportional to its share of the total ticket pool. This is the canonical example where the per-task callback path is *insufficient* — the scheduler must see the full batch before it can pick a winner.

It also exercises the most error-prone part of the API (flyweight invalidation across `dequeueTask()` calls — the `QueuedTask` returned by `dequeueTask()` is reused; saving it requires `new QueuedTask(t)`), so it doubles as a worked example of the harder-to-use override.

Compared to the existing BPF-only `LotteryScheduler` (which randomises *slice length* with `bpf_get_prandom_u32`), this one randomises *dispatch order* using `java.util.concurrent.ThreadLocalRandom` — the canonical formulation, and one that's hard to express in BPF because it needs O(n) reservoir-style sampling across the batch.

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "lottery_java")
@Property(name = "timeout_ms", value = "10000")
public abstract class LotterySample extends UserspaceSchedulerBase {

    public static final class LotteryPolicy extends UserspaceScheduler {
        private static final long SLICE_NS = 5_000_000L;       // 5 ms — winners get a real timeslice

        private final ArrayList<QueuedTask> pool = new ArrayList<>(256);
        private final DispatchedTask scratch = new DispatchedTask();

        public LotteryPolicy(LotterySample prog) { super(prog); }

        @Override
        protected void schedule() {
            try (Tick tick = tick()) {
                long totalTickets = 0;
                QueuedTask t;
                while ((t = dequeueTask()) != null) {
                    pool.add(new QueuedTask(t));                // copy — flyweight invalidates on next()
                    totalTickets += t.weight;                   // weight = tickets
                }
                if (pool.isEmpty()) return;

                // Draw winners until the pool drains. Removing winners is O(n);
                // fine for the small batch sizes scx_bpf_dispatch_nr_slots() permits (~32).
                var rng = ThreadLocalRandom.current();
                while (!pool.isEmpty()) {
                    long winningTicket = rng.nextLong(totalTickets);
                    long cumulative = 0;
                    int winnerIdx = -1;
                    for (int i = 0; i < pool.size(); i++) {
                        cumulative += pool.get(i).weight;
                        if (cumulative > winningTicket) { winnerIdx = i; break; }
                    }
                    QueuedTask winner = pool.get(winnerIdx);
                    totalTickets -= winner.weight;
                    scratch.fillFrom(winner);
                    scratch.sliceNs  = SLICE_NS;
                    scratch.targetCpu = pickIdleCpu();
                    if (!tryDispatch(scratch)) tick.addPending(1);    // ringbuf full
                    pool.remove(winnerIdx);                            // swap-remove would be faster but order doesn't matter
                }
            }   // tick.close() fires notifyComplete(pending) — impossible to forget
        }
    }

    public static void main(String[] args) throws Exception {
        try (var prog  = BPFProgram.load(LotterySample.class);
             var sched = new LotteryPolicy(prog)) {
            sched.runUntilExit();
        }
    }
}
```

Why `schedule()` and not `policy()`: a per-task callback can't know `totalTickets` until the whole batch has been seen, so the winner-selection logic genuinely requires the drain-then-sort shape. This is the same reason `scx_rustland`'s deadline-ordered policy needs `schedule()`.

**Drain-then-sort sketch** for the deadline-ordering pattern (provided for API completeness; not a shipped sample — `LotterySample` already covers the `schedule()` override):

```java
class DeadlineOrderedPolicy extends UserspaceScheduler {
    private final TreeSet<QueuedTask> ordered =
            new TreeSet<>(Comparator.comparingLong(t -> t.vtime));
    private final DispatchedTask scratch = new DispatchedTask();

    @Override
    protected void schedule() {              // override the loop, not policy()
        try (Tick tick = tick()) {
            QueuedTask t;
            while ((t = dequeueTask()) != null) {
                ordered.add(new QueuedTask(t));  // copy: pooled flyweight is invalidated on next()
            }
            for (var task : ordered) {
                scratch.fillFrom(task);
                scratch.targetCpu = pickIdleCpu();   // -1 ⇒ SHARED_DSQ
                if (!tryDispatch(scratch)) tick.addPending(1);
            }
            ordered.clear();
        }   // tick.close() fires notifyComplete(pending) — impossible to forget
    }
}
```

This sketch is **not a shipped sample** — `LotterySample` (§4c) already exercises the `schedule()` override path that the deadline pattern would need. The sketch stays in-spec only as the canonical drain-then-sort reference for `scx_rustland`'s deadline ordering; promoting it to a real sample is a followup.

## Data structures

### `QueuedTaskCtx` (kernel→user, BPF wire format)

Matches `scx_rustland_core`'s `queued_task_ctx` exactly. The Java side surfaces these fields via the `QueuedTask` POJO shown in §3.

| Field             | Type    | Notes                                                  |
|-------------------|---------|--------------------------------------------------------|
| `pid`             | int     | task PID                                               |
| `prevCpu`         | int     | CPU it last ran on, or -1 (was `cpu`)                  |
| `nrCpusAllowed`   | long    | cpumask weight                                         |
| `flags`           | long    | sched_ext enqueue flags, passed through                |
| `startTs`         | long    | last cpu-acquire timestamp (boot ns)                   |
| `stopTs`          | long    | last cpu-release timestamp                             |
| `execRuntime`     | long    | cumulative runtime since last sleep                    |
| `weight`          | long    | task static priority weight, [1..10000], default 100   |
| `vtime`           | long    | task's vruntime                                        |
| `enqCnt`          | long    | monotonic counter for this task                        |
| `comm[16]`        | byte[]  | /proc-style command name                               |

### `DispatchedTaskCtx` (user→kernel, BPF wire format)

| Field      | Type | Notes                                                       |
|------------|------|-------------------------------------------------------------|
| `pid`      | int  | task to dispatch                                            |
| `targetCpu`| int  | target CPU id, or `DispatchedTask.ANY_CPU` (-1) for SHARED_DSQ |
| `flags`    | long | dispatch flags (e.g. `SCX_ENQ_PREEMPT`)                     |
| `sliceNs`  | long | time slice; 0 means framework default (5 ms)                |
| `vtime`    | long | vtime to dispatch with; 0 means monotonic                   |
| `enqCnt`   | long | echoed from QueuedTask for correlation                      |

`DispatchedTask.ANY_CPU = -1` (wire-compatible with rustland's `RL_CPU_ANY` sentinel). The BPF-side `dispatchOne` callback tests `d.val().targetCpu < 0` to route to `SHARED_DSQ_ID`; otherwise it dispatches to `SCX_DSQ_LOCAL_ON | targetCpu`. The callback also decrements the per-CPU `dispatchBudget` counter and returns 1 (stop) when the budget is exhausted, so each `dispatch()` call honours `scx_bpf_dispatch_nr_slots()`.

### `SchedStats` (mmap'd from Java)

12 counters. Backed by a `BPFTypedArena<SchedStats>` of 1 page — arenas already encapsulate `BPF_F_MMAPABLE` and expose a `MemorySegment` via `userView()`. BPF increments use `__sync_fetch_and_add` (atomic on 8-byte words). Java reads use `VarHandle.getOpaque()` on `MemorySegment`-derived handles — ordered enough for monotonic counters where staleness of one cycle is acceptable, no fence cost. Not consistent across counters (a snapshot is not an atomic snapshot of all 12) — fine for diagnostics.

Note on the rustland mapping: rustland exposes `nr_failed_dispatches` because its `BpfScheduler::dispatch_task` returns a `bool` from the `scx_bpf_dsq_insert` kfunc. hello-ebpf's binding declares the kfunc `void` (see `Scheduler.java:104`), so there is no call site that can observe a failure — `failedDispatches` would be dead code. The two real failure modes (target CPU offline, task no longer eligible) are already covered by `bouncedDispatches` (slot 7) and `cancelledDispatches` (slot 8).

| #  | Field                    | Description                                       |
|----|--------------------------|---------------------------------------------------|
| 1  | `onlineCpus`             | current online CPU count                          |
| 2  | `runningTasks`           | tasks currently on a CPU                          |
| 3  | `nrQueued`               | cumulative count of `enqueue` events (counter; matches rustland) |
| 4  | `nrScheduled`            | cumulative count of Java→BPF ringbuf submits (incremented Java-side on `dispatch()` accept) |
| 5  | `userDispatches`         | cumulative kernel-side DSQ inserts via the Java-dispatch path (incremented BPF-side in the `bpf_user_ringbuf_drain` callback) — equals `nrScheduled` minus in-flight/dropped records |
| 6  | `kernelDispatches`       | cumulative dispatches via BPF stall-fallback path |
| 7  | `bouncedDispatches`      | task became ineligible (e.g. CPU offline)         |
| 8  | `cancelledDispatches`    | Java reserve→discard, or reserve returned null   |
| 9  | `congestionEvents`       | enqueue saw full ringbuf                          |
| 10 | `frameworkEnqueues`      | tasks routed to FRAMEWORK_DSQ in enqueue          |
| 11 | `policyExceptions`       | exceptions caught in default `schedule()` per-task try block; overriders of `schedule()` must increment manually via `onPolicyException()` |
| 12 | `idleFastPath`           | `selectCPU` short-circuited to LOCAL on idle hint |

**Slot numbering is part of the BPF↔Java ABI.** New counters are *appended only* — never reorder, never insert mid-table, never reuse a retired slot's index. Both sides (`SchedStats` `@Type` schema in Java, `incStat(slot, …)` call sites in BPF) reference these positions by integer, and the `SchedStatsSnapshot` field order is verified against this table at startup.

### `SchedStatsSnapshot` (Java-side mutable record)

A plain Java class with one mutable `long` field per `SchedStats` counter (same 12 names). `readStatsInto(SchedStatsSnapshot dest)` does the `VarHandle.getOpaque()` loads and writes them into the caller-owned `dest`, so subclasses can keep a single instance across ticks and pay zero per-tick allocation. Not a `record` (records are immutable) — a regular class with public mutable fields. The matching field set is verified **once at `UserspaceScheduler` construction time** via reflection against `SchedStats`'s `@Type` schema (not per-snapshot — snapshot construction is on the hot path and must be allocation-only); a mismatch throws a `RuntimeException` at startup before any BPF program is attached.

One derived getter is exposed for the common debugging question "how many records are stuck in the user→kernel ringbuf right now?":

```java
/**
 * Records the framework accepted into the user→kernel ringbuf but the BPF
 * drain callback has not yet consumed. Equals
 * {@code nrScheduled - userDispatches - cancelledDispatches}. This is a
 * point-in-time estimate computed from three independently-loaded counters,
 * so a snapshot taken mid-update can briefly read negative — clamp to zero
 * before displaying. Useful for dashboards; not a source of truth for
 * back-pressure decisions (use {@code tryDispatch}'s return value instead).
 */
public long pendingInRingbuf() {
    return Math.max(0L, nrScheduled - userDispatches - cancelledDispatches);
}

/**
 * Pretty-print this snapshot as a single line suitable for periodic logging.
 * Stable format — covers the seven counters operators watch most:
 * {@code "[stats] user=N kernel=N queued=N sched=N cong=N exc=N idleFast=N"}.
 * Allocation: one {@code String} per call (the formatter builds it from the
 * already-loaded fields — no map reads). Callers who want the full 12-counter
 * dump should iterate the snapshot fields directly.
 */
public String format() { /* … */ }
```

Why the formatter lives here, not on `UserspaceScheduler`: a snapshot is self-describing — every counter the formatter needs is already a field on `this`. Putting `format()` on the snapshot means dashboards that already keep a preallocated snapshot for `readStatsInto` can format from the same object without a second method call into the scheduler, and JFR-style consumers that hold snapshots without holding a `UserspaceScheduler` reference (e.g. log-aggregator threads) can still print. `UserspaceScheduler.formatStats()` remains as the one-line convenience for the rustland `print_stats()` parity case.

### BPF-side stat and bitmap helpers

`incStat(int slot, long delta)` and `decStat(int slot, long delta)` are static helpers in `UserspaceSchedulerBase` (Java-method-bodied, lowered by the compiler plugin), defined roughly as:

```java
private static void incStat(BPFTypedArena<SchedStats> arena, int slot, long delta) {
    int zero = 0;
    Ptr<SchedStats> s = arena.bpf_lookup_elem(Ptr.of(zero));   // index 0 — single-entry arena
    if (s == null) return;
    long offset = SchedStats.offsetOf(slot);                    // generated by plugin from @Type record
    __sync_fetch_and_add(((Ptr<Long>) Ptr.cast(s).add(offset)).val(), delta);
}
```

The call sites in `enqueue`/`dispatch`/`updateIdle` write `incStat(STAT_…, 1)` (without the arena argument) and the plugin rewrites them to thread the `stats` field through. If that lowering is more work than expected, the v1 fallback is to inline the three-line body at each call site — there are ~10 callers, so the duplication is bounded.

`setBit(BPFArena arena, int cpu, boolean idle)` is similarly inlinable:

```java
private static void setBit(BPFArena arena, int cpu, boolean idle) {
    if (cpu >= MAX_CPUS) return;                                // bounded write
    Ptr<Long> word = arena.bpf_arena_word_at(cpu / 64);          // 8-byte word pointer
    long mask = 1L << (cpu & 63);
    if (idle) __sync_fetch_and_or(word, mask);
    else      __sync_fetch_and_and(word, ~mask);
}
```

`BPFArena.bpf_arena_word_at(idx)` returns a `Ptr<Long>` to the *idx*-th 8-byte word of the arena's page-0. If `BPFArena` does not already expose this helper, add it as a `@BuiltinBPFFunction` returning `(unsigned long *)((char *)$this + 8 * $arg1)` — trivial to lower. The arm64 and x86 arena base-pointer translation is already handled by clang's address-space-cast attribute (see [BPFArena javadoc](#)).

### `schedulerTgid` propagation

`schedulerTgid` is a BPF global variable (not a per-CPU map, not a hash map slot) holding the Java scheduler's tgid. Lifecycle:

1. JVM starts; GC and JIT threads already exist as children of the JVM tgid.
2. Java calls `BPFProgram.load(...)`; BPF program is verified but **no programs attached**.
3. The framework writes the current tgid to the BPF program's `schedulerTgid` global via that field's `set(...)` method. This happens inside `UserspaceScheduler` using its private `prog` reference; subclasses do not see or touch this step. Same step also resolves `kswapd` and `khugepaged` PIDs by scanning `/proc/*/comm` once and writes them into the `kswapdPid` / `khugepageDPid` BPF globals so the kthread fast path in `enqueue` can match them. Not finding either (e.g. on a kernel without THP) is fine — the globals stay at 0 and the comparison naturally never matches.
4. Java calls `autoAttachPrograms()` — the `@Tracepoint onFork` goes live with `schedulerTgid` already populated, so the very first fork it sees has a valid parent tgid to compare against.
5. Java calls `attachScheduler()` — the struct_ops scheduler goes live; from now on `enqueue`/`dispatch` callbacks see the populated `frameworkPids` map as soon as step 6 finishes.
6. Java runs the initial `/proc/self/task/` rescan; this catches the GC/JIT threads that existed in step 1 before the tracepoint was attached.
7. From now on: any new fork by the Java process triggers the tracepoint, which sees a matching `parent_tgid` and registers the child.

**Order matters:** the spec deliberately puts the `schedulerTgid` write *before* `autoAttachPrograms()`, and `autoAttachPrograms()` before `attachScheduler()`. Reversing them opens a race window where forks during attach are not registered, since the tracepoint compares against the zero initialiser. Between steps 5 and 6 there is a brief window (a few ms) where struct_ops is live but `frameworkPids` doesn't yet contain the pre-existing GC/JIT threads — they will route through the user ringbuf during that window, which is harmless (the policy will dispatch them like normal tasks; latency hit is bounded by the rescan time).

Field access (`prog.schedulerTgid.set(...)`) works between `load()` and any attach call — same pattern used in `CentralScheduler`, `BoostedScheduler`, `ChaosScheduler`. No fallback path is needed.

The 1-second periodic rescan exists as belt-and-suspenders: if the tracepoint misses anything (race on `frameworkPids` insertion, kernel quirk, or a thread that exits and a new one reuses the TID), the rescan picks it up within ~1 s.

### Idle CPU bitmap

Backed by a 1-page `BPFArena` (4 KiB), holding `(MAX_CPUS + 63) / 64` × 8-byte words at offset 0. Bit *i* in word *i / 64* = 1 iff CPU *i* is currently idle. With `MAX_CPUS = 1024` (current cap) this uses 128 bytes of the page; the remainder is reserved for headroom (online-CPU mask, future fields).

- BPF side: `updateIdle` callback sets/clears a single bit using `__sync_fetch_and_or` / `__sync_fetch_and_and` (atomic, BPF-supported).
- Java side: mmap'd via `BPFArena.userView()` (existing API — `BPFArena` already emits `BPF_F_MMAPABLE` and exposes a `MemorySegment` view via the `BPF_MAP_TYPE_ARENA` `mmap(map_extra, MAP_FIXED)` path). Reads are direct memory loads, no syscall.
- **MAX_CPUS cap.** Hardcoded to 1024. If `scx_bpf_nr_cpu_ids() > MAX_CPUS`, `updateIdle` must skip CPUs ≥ MAX_CPUS (bounded write) and the framework should log a warning at startup. Larger hosts need a recompile bump.
- **No seqlock.** A torn read can at worst report a CPU as idle when it isn't (or vice versa) for one scheduling cycle, causing one suboptimal dispatch decision. The stall fallback and subsequent updates recover within microseconds. Adding seqlock infrastructure (extra header word, write barriers) is not justified for this granularity of staleness.

## Error handling

| Condition                                     | Side    | Action                                                                       |
|-----------------------------------------------|---------|------------------------------------------------------------------------------|
| `kernel→user` ringbuf full in `enqueue`       | BPF     | Increment `congestionEvents`; route task directly to `SHARED_DSQ`.           |
| Drain callback: `bpf_task_from_pid` returns 0 | BPF     | Increment `bouncedDispatches`; drop.                                         |
| Java `policy()` throws                        | Java    | Catch in run loop, log, increment `policyExceptions`, continue with next.    |
| `user→kernel` ringbuf full on Java reserve    | Java    | `dispatch()` silently drops (framework increments `cancelledDispatches`); `tryDispatch()` returns `false` for callers that want the signal. Stall fallback eventually rescues task via `SHARED_DSQ`. |
| Map mmap fails at startup                     | Java    | Fatal — `UserspaceSchedulerStartupException` (see below). We cannot run.     |
| `schedulerTgid` global never set              | both    | Tracepoint becomes a no-op (no match); rescan still works. Log warning when initial rescan finds empty map post-startup. |
| Scheduler-loop thread interrupted via `Thread.interrupt()` (e.g. from `runUntilExit()`'s shutdown hook, or a host harness in tests) | Java    | The run loop polls `Thread.interrupted()` at the top of each iteration and on `InterruptedException` from waits. On detection: stop draining, unload BPF program, close ringbufs. Triggered explicitly by the framework — user code does not need to wire it up. |
| Java run loop wedges (deadlock, infinite GC, blocked syscall) | BPF | **User workloads stay alive throughout the wedge; only `policyExceptions` / log output is lost.** Mechanism: each BPF `enqueue` measures `now - last_kick_ns`; over `STALL_FALLBACK_NS` (default 50 ms) it routes the task to `SHARED_DSQ` directly and increments `kernelDispatches`. The Java run loop itself is dispatched via the dedicated `FRAMEWORK_DSQ` (see §4), so it is never scheduled by itself — it can always make forward progress whenever the kernel gives it a CPU. |

`UserspaceSchedulerStartupException extends RuntimeException` is a dedicated unchecked exception thrown only from the `UserspaceScheduler` constructor path for unrecoverable startup failures (map mmap, ABI mismatch, missing BPF program reference). Users catching it can distinguish "the scheduler never started" from "the scheduler started and later failed", which surface as `BPFError` / `IOException` from the steady-state path. The constructor never throws `RuntimeException` directly — every startup failure has a specific subclass or pre-existing typed exception.

## Testing strategy

Three layers, all run on the thinkstation (per project memory — local mac cannot run BPF tests).

1. **Unit:** `BPFUserRingBufferTest` — reserve/submit/discard cycles, full-buffer behavior, double-submit detection, close cleanup. No BPF program required; calls libbpf via Panama against a standalone-created user-ringbuf map. Lives under `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/map/`.

2. **Compiler-plugin:** `UserRingBufferCompilationTest` in `bpf-compiler-plugin-test/` — verifies a class declaring `BPFUserRingBuffer<X>` field compiles, emits the correct map definition (`__uint(type, BPF_MAP_TYPE_USER_RINGBUF)`), and that `drain()` lowers correctly to `bpf_user_ringbuf_drain`. Pattern matches existing `SharedFromTest`.

3. **Integration:** `RustlandFifoSampleSmokeTest` in `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/`, modelled on `SchedulerSmokeTest`. Uses `SchedulerExtension` (vng harness) to:
   - Load `RustlandFifoSample`
   - Run `stress-ng --cpu 4 --timeout 3s` in the guest
   - Assert: `userDispatches > 0`, `policyExceptions == 0`, no verifier errors, scheduler unloads cleanly
   - Assert: `frameworkPids` map non-empty within 1s of startup

   `WeightedRRSampleSmokeTest` and `LotterySampleSmokeTest` are one-line variants that swap in the sibling class — the assertions are identical (the framework-level contract is what's under test, not the policy). `LotterySampleSmokeTest` additionally asserts `userDispatches > 0` while overriding `schedule()` rather than `policy()`, since the two paths are wired differently inside `runUntilExit()`.

4. **Observability overhead benchmark:** `UserspaceSchedulerObsBenchTest` (JMH-style microbench, not a unit test; runs nightly, not on every PR). Drives 100 k synthetic decisions/s through the run loop with all four observability layers off / Layer-1-only / Layers 1+2 / all on. Asserts:
   - Histograms-off vs. all-on: <5% throughput delta
   - JFR enabled with default threshold: <2% delta
   - Zero allocation in steady state (validated via `JvmHealthSnapshot.allocatedBytes` delta on the loop thread, after warmup, in the all-on configuration)

   Same harness also asserts `ringbufToDispatchNs` p50 < 50 µs and p99 < 500 µs on the thinkstation reference host with a default-tuned JVM — a regression in either is a release blocker.

## JVM tuning

Documented in `UserspaceScheduler`'s class javadoc and `docs/userspace-scheduler.md`. The framework does not enforce these — they are JVM concerns the user must set when launching:

- **`-XX:+UseZGC -XX:+ZGenerational`** — sub-millisecond GC pauses; default for any serious userspace scheduler.
- **`-XX:GuaranteedSafepointInterval=0`** — suppress periodic safepoints that would briefly stall the hot thread.
- **`-Xms == -Xmx`** — fix heap size so no resize events occur.
- **`taskset`/`isolcpus`** — optionally pin the scheduler thread to an isolated CPU; document the pattern.
- **`--enable-native-access=ALL-UNNAMED`** — required for Panama; already standard in hello-ebpf.

The sample's `main()` does *not* re-check ZGC — that is the framework's job via `Opts.verifyZgcOnStart`. The warning fires once at `UserspaceScheduler` construction and is not fatal.

## Zero-alloc hot path

The framework is designed so the steady-state per-task path performs **zero allocations** on the Java side. Patterns the framework embodies (documented in javadoc and the docs page):

- A single pooled `QueuedTask` POJO is reused across `dequeueTask()` / `policy()` calls; each call overwrites its fields in place from the ringbuf's `MemorySegment` via Panama. The user holds the reference for one `policy()` body and never beyond it.
- A single pooled `DispatchedTask` POJO is reused across `dispatch()` calls; `scratch.fillFrom(task)` copies from a `QueuedTask` into a caller-owned record. Users who want their own pool can ignore the framework's pooled instance.
- `dispatch(DispatchedTask)` writes directly into the user ringbuf's `MemorySegment` (reserve → memcpy fields → submit). No intermediate boxing.
- `pickIdleCpu()` and `selectCpu(...)` operate on `MemorySegment` slices and return `int`. No allocation.
- `readStatsInto(SchedStatsSnapshot)` writes into a caller-owned record; no allocation per read.
- `policy()` is called per task; subclasses must keep its body allocation-free (no lambdas with captures, no `new` on hot paths, no autoboxing).
- The framework's default `schedule()` body uses a single pooled `Batch` instance; closing it triggers `notifyComplete(pending)` without allocating an iterator.

The framework cannot statically prove `policy()` is allocation-free. The class javadoc and `docs/userspace-scheduler.md` discuss the rules; users who care about tail latency should validate with `-XX:+PrintCompilation` / JFR allocation profiling.

## JIT and safepoint trade-offs (deferred)

`-XX:GuaranteedSafepointInterval=0` suppresses periodic safepoints, but JIT compilation, deoptimisation, and class-loading still trigger them. A safepoint stalling the scheduler thread for a millisecond will cause stall fallback to fire. This is acknowledged but not solved in v1 — solutions (AOT compilation, JIT pre-warming, dedicated CPU pin, allocation-elision verification) are followup work. See `docs/userspace-scheduler.md` for the full discussion.

## Observability

Operating a userspace scheduler in production requires more than counter totals — you need distributions, because the tail is the story. The 12 counters in `SchedStats` answer "how often?"; the histograms and JFR events below answer "how slow?", "how variable?", and "where did the time go?".

Three measurement layers, each with a kill-switch on the `Opts` builder (already shown in §3 — repeated here for context):

```java
Opts.builder()
    .enableLatencyHistograms(true)    // BPF-side: ~30 ns per record event
    .enableJfrEvents(true)            // Java-side: ~50–200 ns per event, batched
    .histogramPrintIntervalS(0)       // 0 = never auto-print; otherwise periodic
    .build();
```

### Layer 1 — End-to-end task delay (kernel-side, log2 histograms)

Five `BPFHistogram` maps living next to `SchedStats`. Each is the existing `BPFHistogram` (`BPFHashMap<Integer, Long>`, log2-bucketed) — no new map type required. The BPF side records into them with `bpf_ktime_get_ns()` deltas; Java reads via the existing `printLog2Hist(String)` helper.

| Histogram                | Records ns delta between …                                                       | Why it matters                                   |
|--------------------------|----------------------------------------------------------------------------------|--------------------------------------------------|
| `enqueueToRingbufNs`     | task enters `enqueue()` → record submitted to user ringbuf                       | BPF-side fixed cost (reserve + copy + submit)    |
| `ringbufToDispatchNs`    | record submitted by BPF → matching dispatch arrives from Java                    | **end-to-end policy round-trip** (the headline)  |
| `dispatchToRunningNs`    | dispatch arrives from Java → task actually runs on a CPU                         | post-dispatch DSQ wait                           |
| `stallFallbackAgeNs`     | task age at the moment `STALL_FALLBACK_NS` fired and BPF auto-dispatched it      | "how late was Java?" when stall trips            |
| `frameworkDsqWaitNs`     | framework PID enters FRAMEWORK_DSQ → it gets a CPU                               | does the framework starve itself?                |

The `ringbufToDispatchNs` histogram is correlated by `enqCnt`: BPF stamps `lastUserEnqueueTs[enqCnt % N]` when submitting; the user→kernel record echoes `enqCnt`; on receipt BPF computes `now - lastUserEnqueueTs[enqCnt % N]` and records. `N = 4096` (16 KiB per-CPU array); collisions are rare under any realistic load (the array turns over in ~ms) and a collision just produces one bogus sample.

All histograms are zero-overhead when `Opts.enableLatencyHistograms = false` — the BPF helper sites compile to `if (0) record(…);` via a global flag the plugin lowers to a constant. (The plugin already does this for stat-counter sites; same mechanism.)

Java reads them with:

```java
sched.printHistograms(System.err);               // human-readable, periodic
Map<String, long[]> snap = sched.histogramBuckets();  // raw buckets for export
```

### Layer 2 — Per-decision timing (Java-side, JFR)

JFR is the right tool for the in-process side: native, zero allocation per event in steady state, supports `Period`/`Duration`/`Threshold` filtering at the JVM level, and integrates with the recording the user already has (jfr-query, async-profiler, JMC).

Three event types, all `@Category({"hello-ebpf", "scheduler"})`, all annotated `@Threshold("100us")` by default so noise is filtered:

```java
@Name("ebpf.UserspaceSchedulerDecision")
@Label("Scheduler decision")
@Category({"hello-ebpf", "scheduler"})
@Threshold("100us")
public class DecisionEvent extends jdk.jfr.Event {
    @Label("PID")          public int  pid;
    @Label("Target CPU")   public int  targetCpu;     // -1 = ANY
    @Label("Source CPU")   public int  prevCpu;
    @Label("Weight")       public long weight;
    @Label("Batch size")   public int  batchSize;     // tasks in the enclosing batch
    @Label("Policy class") public String policyClass; // e.g. "FifoPolicy"
}

@Name("ebpf.UserspaceSchedulerBatch")
@Label("Scheduler batch")
@Category({"hello-ebpf", "scheduler"})
@Threshold("500us")
public class BatchEvent extends jdk.jfr.Event {
    @Label("Drained tasks")     public int  drained;
    @Label("Dispatched tasks")  public int  dispatched;
    @Label("Cancelled (full)")  public int  cancelled;
    @Label("Policy exceptions") public int  policyExceptions;
    @Label("Pending after")     public long pendingAfter;  // notifyComplete value
}

@Name("ebpf.UserspaceSchedulerLoopIdle")
@Label("Scheduler loop blocked on poll")
@Category({"hello-ebpf", "scheduler"})
@Threshold("10ms")
public class IdleEvent extends jdk.jfr.Event {
    @Label("Poll wait reason") public String reason;  // "no-work" | "rb-empty" | "interrupted"
}
```

`DecisionEvent.commit()` is called inside the per-task try block in default `schedule()`; the framework owns the event object pool to keep allocation at zero. `BatchEvent` brackets each `Batch` scope. `IdleEvent` fires when the loop's `ring_buffer__poll(timeoutMs)` returns 0 — useful for separating "Java is wedged" from "system is idle".

JFR control surface for users — no new framework API needed, just give them recipes in the sample's javadoc:

```bash
# Live recording, 30 s, scheduler events only:
jcmd <pid> JFR.start name=sched settings=profile duration=30s \
    filename=sched.jfr +ebpf.UserspaceSchedulerDecision#enabled=true \
    +ebpf.UserspaceSchedulerBatch#enabled=true

# Disable threshold filter for full distribution:
jcmd <pid> JFR.configure +ebpf.UserspaceSchedulerDecision#threshold=0
```

### Layer 3 — JVM health (GC, safepoints, allocation)

This is the part that catches "the scheduler stutters every 30 seconds and we don't know why". JFR already emits these events; the framework's job is just to make them easy to correlate with Layer 1/2.

The framework's run-loop periodically reads three JFR-derived counters via `ManagementFactory` (no JFR recording required — these are JMX counters that JFR also feeds from) and stamps them into a side struct:

```java
public final class JvmHealthSnapshot {
    public long gcPauseTotalNs;       // sum of all GC pause ns since JVM start
    public long gcPauseCount;
    public long maxGcPauseNs;          // longest single pause since JVM start
    public long safepointTotalNs;      // -XX:+PrintSafepointStatistics equivalent
    public long safepointCount;
    public long allocatedBytes;        // ThreadMXBean.getThreadAllocatedBytes for the loop thread
    public long compilationCount;      // CompilationMXBean — JIT events on the loop thread
    public long ts;                    // System.nanoTime() at snapshot
}
public final void readJvmHealthInto(JvmHealthSnapshot dest);  // O(1), zero alloc
```

Subtract two snapshots taken `Δt` apart to get per-interval rates. The intended use is "every 5 s, snapshot + subtract + log + warn on regression":

```java
var prev = new JvmHealthSnapshot();
var cur  = new JvmHealthSnapshot();
sched.readJvmHealthInto(prev);
while (!sched.exited()) {
    Thread.sleep(5_000);
    sched.readJvmHealthInto(cur);
    long gcMs = (cur.gcPauseTotalNs - prev.gcPauseTotalNs) / 1_000_000;
    if (gcMs > 50) System.err.println("[health] gc=" + gcMs + "ms in last 5s");
    var swap = prev; prev = cur; cur = swap;
}
```

`maxGcPauseNs` is the headline number — if it exceeds `STALL_FALLBACK_NS / 2` (25 ms with the default) you are one bad pause away from a stall-fallback storm.

### Layer 4 — One-line health dashboard

A `formatHealth(SchedStatsSnapshot, JvmHealthSnapshot, HistogramSnapshot)` static method emits a single dashboard line per tick. Stable format, comparable to `formatStats`:

```
[health] qps=12340 disp/s=12339 stall/s=0  rt p50=47us p99=380us p99.9=2.1ms  jvm gc=3ms safepoint=0.8ms alloc=12KB/s
```

Where:
- `qps`, `disp/s`, `stall/s` are per-second deltas of `nrQueued`, `userDispatches`, `kernelDispatches`.
- `rt` percentiles come from `ringbufToDispatchNs` (Layer 1).
- `gc`, `safepoint`, `alloc` come from `JvmHealthSnapshot` (Layer 3).

Operators get the "is it healthy?" question answered in one line.

### Overhead budget

| Layer        | Per-task cost           | Steady-state allocation | Verified by                                  |
|--------------|-------------------------|--------------------------|----------------------------------------------|
| Layer 1 (BPF histos) | ~30 ns × 3 sites | none                     | microbenchmark: with/without flag, 1 M decisions |
| Layer 2 (JFR)        | ~50–200 ns w/ threshold filter; 0 when disabled | event-object pool, reused | JFR's own benchmark suite + JMH harness     |
| Layer 3 (JVM health) | 0 per task (read on-demand) | 0 (snapshot is mutable) | structural — no per-task work             |
| Layer 4 (dashboard)  | 1 string format per tick | 1 String per tick       | tick is O(seconds), allocation is acceptable |

Total target: **<5% overhead vs. observability-off** at 100 k decisions/s. Captured as a CI benchmark in the test plan.

## Validated against rustland consumers

Surveyed 14 third-party `scx_rustland_core` consumers found via GitHub code
search (2026-06), beyond the 2 in-tree references — covering production
research, theses, fuzzers, DSL engines, and joke schedulers:

- **In-tree references** — `scx_rlfifo` (per-task callback), `scx_rustland`
  (drain-then-sort, deadline-ordered).
- **Production / research** — `arighi/scx_rust_scheduler` (rlfifo reference by
  an scx maintainer), `nkaretnikov/concurrency-fuzz-scheduler-rs` (concurrency
  fuzzer using `nr_queued_mut()` as a drain hint), `amiremohamadi/schedra`
  (DSL-driven, exercises the full rustland-equivalent stats surface and *every* QueuedTask field
  the spec exposes), `sergiopani/tfg_scheduler` (thesis project: FIFO,
  deadline, "green" power-aware, AI-priority variants — uses `BinaryHeap` for
  drain-then-sort, exercises `ANY_CPU`).
- **Joke / personality schedulers** — `scx_horoscope`, `scx_graha` (astrology),
  `scx_truther` (zodiac aphorisms). All use only the per-task callback path.
- **Embedded forks (excluded)** — `TheUnknownThing/COSMOS` forks
  `scx_rustland_core` and adds custom topology; `TELOS-syslab/Aeolia` and
  `YaQia/sched_tags_schedulers` embed full scx trees but their novelty is in
  unrelated schedulers; `hodgesds/scx-midi` is a stock fork. None constitute
  a clean third-party use of the public API.

### Coverage verdict

**Every API surface and field used by any real third-party scheduler is in
this spec.** Specifically validated:

- All seven core `BpfScheduler` methods (`init`, `dequeue_task`, `select_cpu`,
  `dispatch_task`, `notify_complete`, `exited`, `shutdown_and_report`).
- Nine of the ten rustland `nr_*_mut` stats getters (slots 1–9 of our 12;
  the rustland-specific `nr_failed_dispatches` is dropped because hello-ebpf's
  `scx_bpf_dsq_insert` binding is void — see §`SchedStats`. The three Java-side
  additions are `frameworkEnqueues`, `policyExceptions`, `idleFastPath`) —
  exercised in full by `schedra`, `arighi`, `sergiopani`.
- All QueuedTask fields the spec exposes (`pid`, `prevCpu`, `nrCpusAllowed`,
  `flags`, `startTs`, `stopTs`, `execRuntime`, `weight`, `vtime`, `comm`).
- All DispatchedTask fields and the `DispatchedTask.ANY_CPU = -1` sentinel
  (`sergiopani/tfg_scheduler` uses the sentinel explicitly).
- Both override styles: per-task callback (horoscope, graha, fuzz —
  exercised in v1 by `RustlandFifoSample` and `WeightedRRSample`) and
  drain-then-sort (sergiopani deadline, arighi — exercised in v1 by
  `LotterySample`).

### Follow-up additions (not blocking v1)

- **`QueuedTask.nvcsw` and `QueuedTask.slice`** — present in upstream
  `queued_task_ctx` wire format; used by `arighi/scx_rust_scheduler`. Spec
  should list them as "upstream fields not surfaced to Java in v1" so adding
  them later is additive (no schema break). Documented below.
- **`QueuedTask.uid`** — only `scx_graha` uses it (per-user joke scheduler).
  Defer indefinitely.
- **`RustLandBuilder`** — alternate construction surface used by
  `PawelKnapp/scx-throughput`. Spec's `new UserspaceScheduler(prog, opts)`
  covers the same ground; document the mapping in javadoc when porting.
- **`bpf.print_stats()`** — convenience pretty-printer used by all 4
  sergiopani variants. Implemented in v1 as `SchedStatsSnapshot.format()`
  alongside `readStatsInto`, with `UserspaceScheduler.formatStats()` as a
  zero-arg convenience that wraps `stats().format()`; same one-liner
  ergonomics as rustland.
- **`scx_utils::Topology`** — only `COSMOS` uses it (and `COSMOS` forks
  rustland_core anyway). Already covered by the explicit "topology is out
  of scope" non-goal.
- **Direct sched_ext kfunc calls** — *not used by any pure third-party
  rustland consumer*. The decision to wall this off behind the framework
  is validated.

**Upstream wire-format fields not in v1's Java view** (additive followups,
list here so the BPF↔Java struct doesn't drift): `nvcsw` (voluntary context
switches), `slice` (remaining time slice), `uid`. Adding any of these later
extends `queued_task_ctx` and `QueuedTask` without breaking the existing
field set.

## Out of scope (deferred)

- CPU topology / sibling map
- cgroup-aware decisions
- Promoting the deadline-ordering sketch (§4 trailing) to a shipped sample — followup PR; `LotterySample` already exercises the same `schedule()` override path
- Latency-benchmark harness (round-trip histogram) — followup PR
- GraalVM native-image build
- `@SharedFrom` interaction (out of basic-version scope; should drop in cleanly later)

## Implementation order (suggested)

**Step 0 — Pre-implementation gate (blockers).** None of the work below can begin until the three plan-time blockers are resolved. Each one ends with a concrete acceptance test; the implementation plan must pass all three before progressing to step 1. The blockers are scoped tightly (combined budget ~150 LOC plugin work + ~40 LOC infra) and the design choices below are pre-committed so no further design discussion is needed at plan-write time.

- **0a. `BPFRingBuffer.consumeRaw(SegmentCallback)` (segment-based dequeue).** Decided: option (b) from the risks section. Add a new `consumeRaw` method to `BPFRingBuffer` that wraps `ring_buffer__consume` and invokes a `SegmentCallback` with an unmaterialised `MemorySegment` per record (no per-record deserialisation to `E`). Signature: `int consumeRaw(SegmentCallback cb, Object ctx)` where `SegmentCallback` is `@FunctionalInterface int apply(MemorySegment record, long size, Object ctx)`; returns the number of records consumed. Existing `consume()` / `poll()` keep their current semantics. *Acceptance:* unit test reads N records out of a populated ringbuf via `consumeRaw`, asserts each callback sees the right byte range with zero `E`-shaped allocations (verified with the `allocatedBytes` JFR counter on the consume thread).
- **0b. User-ringbuf compiler-plugin emission (specialised sibling file).** Decided: copy the existing `BPFRingBuffer` emission file in `bpf-compiler-plugin` and specialise it for `BPF_MAP_TYPE_USER_RINGBUF` rather than generalising the existing path. Reasoning: cleaner code-review diff, no back-compat risk to the existing `BPFRingBuffer` emission, and the two emission paths can diverge later (e.g. different map flags, different `max_entries` semantics) without back-fitting a discriminator. *Acceptance:* `UserRingBufferCompilationTest` in `bpf-compiler-plugin-test/` compiles a class declaring a `BPFUserRingBuffer<X>` field and asserts the emitted C output contains `__uint(type, BPF_MAP_TYPE_USER_RINGBUF)` and the correct `max_entries` line, with no regression against `BPFRingBufferCompilationTest`.
- **0c. Typed `BPFUserRingbufCallback<E>` lowering.** Decided: ship the typed callback in v1. The plugin lowers a Java callback of the shape `int (E record, Ctx ctx)` into a C thunk that reads `sizeof(E)` bytes from the kernel-provided `bpf_dynptr*` into a stack-allocated `E` (via `bpf_dynptr_read`) and then invokes the user callback. The lowering reuses the same `bpf_dynptr_read` machinery the spec's `dispatchOne` callback uses, so 0c and the framework's drain callback share infrastructure. *Acceptance:* a `BPFUserRingbufCallbackCompilationTest` that compiles a minimal BPF program declaring a `BPFUserRingbufCallback<SomeType>`, runs it against a populated user ringbuf, and asserts the callback fires `N` times with the right field values for each record. If lowering proves intractable inside the LOC budget (~80 LOC), the documented fallback in the risks section (untyped `(MemorySegment, ctx)` callback + framework-side `VarHandle` reads) is the v1 escape hatch — but only after the typed approach is shown infeasible in step 0c, not as a default.

**Plan-time deliverable for step 0:** a single short report (one page) confirming each of the three acceptance criteria passes, and recording any signature drift discovered against §"Infrastructure assumptions" in the risks section. Steps 1–8 below assume step 0 is green.

1. `BPFUserRingBuffer<E>` Java wrapper + `MapTypeId` entry + compiler-plugin map-type wiring (depends on 0b)
2. `BPFUserRingBufferTest` (unit; depends on 0a for the segment-based read path)
3. `UserRingBufferCompilationTest` (plugin)
4. `UserspaceSchedulerBase` (BPF side) — struct_ops, kthread fast path, task_storage + enqCnt cancellation, running/stopping/runnable lifecycle ops, heartbeat `bpf_timer`, fork tracepoint sub-program
5. `UserspaceScheduler` (Java side) — run loop (uses 0a + 0c), `/proc/self/task/` rescan, kswapd/khugepaged PID lookup, struct_ops flag wiring (`ENQ_LAST | ALLOW_QUEUED_WAKEUP`, optional `SWITCH_PARTIAL`), shutdown-hook wiring, stats and histogram helpers
6. Samples: `RustlandFifoSample` + `Opts.verifyZgcOnStart` warning, then `WeightedRRSample`, then `LotterySample` (which validates the `schedule()` override path)
7. `RustlandFifoSampleSmokeTest` (plus a one-line smoke variant per sibling sample)
8. `docs/userspace-scheduler.md` + javadoc passes

## Risks

Each risk is tagged **[blocker]** (a v1 release cannot ship until resolved), **[probable]** (likely to need work but well-scoped — discoverable in a named implementation step), or **[polish]** (known minor wart, accept-and-document). Tags are calibrated against the suggested implementation order; "discovered in step N" means N is the earliest step that will exercise the relevant code path.

### Compiler-plugin / Java↔BPF lowering

- **[blocker — decided, gated on step 0a] Segment-based dequeue.** Current `BPFRingBuffer` exposes only callback-driven `consume()` / `poll(timeoutMs)` (`BPFRingBuffer.java:233,282`); both deserialise to `E` per record. *Decision (committed):* add `consumeRaw(SegmentCallback)` — option (b) from the original risk write-up — with the unmaterialised-segment shape described in §"Implementation order, Step 0a". *Fallback (documented, only if 0a fails acceptance):* one `E` allocation per batch slot; still better than per-task, but flagged as a known v1 deviation from §"Zero-alloc hot path".
- **[blocker — decided, gated on step 0b] User ringbuf compiler-plugin emission.** *Decision (committed):* specialised sibling emission file alongside `BPFRingBuffer`'s, scoped to `BPF_MAP_TYPE_USER_RINGBUF`. Reasoning under §"Implementation order, Step 0b". Budget ~50 LOC plugin work plus an integration test (`UserRingBufferCompilationTest`). *Fallback:* generalise the existing path with a map-type discriminator — only if the sibling-file approach turns up an unforeseen plugin-internal coupling.
- **[blocker — decided, gated on step 0c] `BPFUserRingbufCallback<E>` lowering.** The kernel callback signature is `(struct bpf_dynptr *dynptr, void *ctx)`. *Decision (committed):* ship the typed callback in v1 — plugin lowers `int (E, Ctx)` into a C thunk that calls `bpf_dynptr_read` into a stack-allocated `E`. Reuses the dynptr-read machinery the framework's own `dispatchOne` drain callback needs, so 0c is a prerequisite for 5 rather than an independent risk. Budget ~80 LOC plugin work. *Fallback (documented, only if 0c fails acceptance):* untyped `(MemorySegment, ctx)` callback + framework-side `VarHandle` reads — slightly more verbose call site, identical performance, promotes to typed in v1.1.
- **[probable] BPF callback `this` access.** BPF callbacks lower to free functions; they do not close over `this`. The drain callback `dispatchOne` reads only program globals (`STAT_*` constants, `incStat` helper) and map fields, both of which are reachable from any BPF function in the same program without `this`. *Mitigation:* verify in step 4 that the plugin lowers `incStat(STAT_X, 1)` correctly inside a static callback context; if not, pass the relevant map field explicitly through the drain `ctx` argument (one-line wiring change at the call site, no plugin work).
- **[polish] Method reference vs inline lambda.** The spec uses an inline lambda `d -> dispatchOne(d)` rather than `this::dispatchOne`, since the compiler plugin's `$lambdaM:code` template was originally written for inline lambdas. *Mitigation:* 5-line probe in step 1; if method references compile cleanly, switch to the more idiomatic form. If they don't, accept the inline lambda — semantically identical.

### Kernel-side API surface

- **[probable] `BPFTaskStorage<T>` wrapper.** The spec assumes a `BPFTaskStorage<T>` map type (BPF `BPF_MAP_TYPE_TASK_STORAGE`) exists with `bpf_get(task)` / `bpf_get_or_create(task)` methods. hello-ebpf may not have this map type yet. *Mitigation:* if absent, step 4 adds it (~80 LOC: `MapTypeId` entry, plugin map-type emission, Java wrapper). Pattern is well-established (mirror `BPFHashMap`); upstream kernel support is from 5.11 so no kernel-side risk. Required for the `enqCnt` cancellation path and the lifecycle-op timestamps — no v1 fallback if this can't be added.
- **[probable] `bpf_timer` kfunc plumbing.** The heartbeat needs `bpf_timer_init` / `bpf_timer_set_callback` / `bpf_timer_start`. *Mitigation:* if hello-ebpf doesn't have `@BuiltinBPFFunction` wrappers, step 4 adds them (~30 LOC, three single-line declarations). Standard upstream kfuncs since 5.15, so kernel side is stable. Fallback if the wrapper proves awkward: replace the 1 Hz heartbeat with a userspace-driven `bpf_send_signal`-like kick from the Java run loop's own 1 Hz tick — slightly more cross-boundary chatter but zero plugin work.
- **[probable] `init_task` / `running` / `stopping` / `runnable` op signatures.** Verify the `Scheduler` interface (or `SchedulerBase`) exposes these as overridable ops. *Mitigation:* if only `init`, `selectCPU`, `enqueue`, `dispatch`, `updateIdle`, `enable`, `exited` are wired in `Scheduler.java`, step 4 extends the interface and the struct_ops emission in the compiler plugin. Signatures (`scx_init_task_args*` for `init_task`, plain `task_struct*` for the others) are stable; plumbing not design. Fallback: of the four, only `running` and `stopping` are strictly required (for the per-task exec-runtime accounting); `init_task` is replaceable by lazy `bpf_get_or_create` in `enqueue`, `runnable` is a no-op in v1. So the minimum bar is just two ops if plugin work is contended.
- **[probable] `BPFRingBuffer.submitNoWakeup`.** The wake-suppression optimisation in `enqueue` calls a hypothetical `submitNoWakeup(evt)` that forwards `BPF_RB_NO_WAKEUP` to `bpf_ringbuf_submit`. *Mitigation:* if `BPFRingBuffer` only exposes `submit()`, add the flag-bearing variant in step 1 (~5 LOC). Worst-case fallback for v1: drop the optimisation entirely, every enqueue wakes Java — measurable but not fatal (rustland gets ~10% throughput from the same trick; v1 still ships a working scheduler, just with one extra syscall per enqueue under heavy load).
- **[probable] Tracepoint + struct_ops co-residence.** `TracepointAnnotationTest` proves a `@Tracepoint` compiles alongside other BPF programs; `LockHolderBoostScheduler` proves multiple program types co-exist when split across classes. Untested: a tracepoint and a struct_ops in *the same* `@BPF` class. *Mitigation:* if the plugin rejects this combination, split into a sibling class `UserspaceSchedulerUprobes` (mirroring the `LockHolderBoost{Scheduler,Uprobes}` split) and share `frameworkPids` via `@SharedFrom`. The §"Out of scope" disclaimer about `@SharedFrom` applies to user-facing API; the framework using it internally is fine. Cost: one extra Java class and one extra `BPFProgram.load` call.
- **[polish] Tracepoint argument names.** `parent_tgid`, `child_pid` come from the kernel's `sched_process_fork` event format and must match what hello-ebpf's `TraceDefinitions` exposes. On some kernels the field is `parent_pid` (which is the tgid in tracepoint context anyway). *Mitigation:* verify in step 4 against `cat /sys/kernel/debug/tracing/events/sched/sched_process_fork/format` on the thinkstation; if names differ, rename the parameter in the tracepoint Java method to match — the field order/type is ABI-stable, only the name varies.
- **[polish] `frameworkPids.bpf_get(pid) != null`.** Verify the BPF-side null comparison on hash-map lookup compiles correctly. Pattern is used elsewhere in hello-ebpf (e.g. per-task storage). *Mitigation:* verify in step 4 with a 3-line probe; if rejected, the equivalent pattern `frameworkPids.bpf_get(pid) != 0L` (compare the pointer cast to long) is universally supported.

### Infrastructure assumptions (reused hello-ebpf code)

- **[probable] Reused infrastructure assumptions.** The spec assumes `BPFArena.userView()`, `BPFTypedArena<T>` (with 1-page `maxEntries` semantics), `SchedulerBase.init()`, and the `Scheduler` BPF helpers all exist and behave as described. *Mitigation:* the Step 0 deliverable already requires a signature-drift report (see §"Implementation order, Step 0"), so this is folded into the same pre-implementation gate. In particular confirm whether `BPFTypedArena<T>` initialises offset 0 to a valid `T` zero value automatically or whether the BPF program must do a one-time init. If a signature has drifted from the spec, fix locally in step 4 and update the spec — the assumptions are at field/method granularity, never load-bearing on a wider abstraction.
- **[probable] `QueuedTask` / `DispatchedTask` field marshalling.** The framework copies between the ringbuf `MemorySegment` and pooled POJOs on every task. Layout must match `queued_task_ctx` / `dispatched_task_ctx` C structs bit-for-bit (padding, alignment, endianness). *Mitigation:* generate the `VarHandle` table (one per field) from the `@Type` schema — same pattern hello-ebpf uses elsewhere; the schema is the single source of truth. Add a golden-bytes unit test that writes a known POJO through the marshalling, reads it back through a separate libbpf path, and asserts byte-for-byte equality (~20 LOC, catches misalignment at the cheapest possible point in the build).

### Runtime / JVM behaviour

- **[probable] JIT warmup vs `STALL_FALLBACK_NS`.** The first N dispatches through the Java run loop will be 10–100× slower than steady state until C2 tier-compiles `policy()` / `schedule()`. On a cold start with a real workload, the 50 ms `STALL_FALLBACK_NS` watchdog could trigger transient fallback dispatches even on a healthy scheduler. *Mitigation:* the constructor runs a 200-iteration warmup loop driving synthetic `QueuedTask` records through `policy()` / `schedule()` *before* attaching struct_ops (~30 LOC). Additionally, `Opts.warmupIterations` lets users tune for `-XX:TieredCompilation` profiles or pre-AOT loaders; default 200 hits C2 reliably with stock ZGC on the thinkstation.
- **[probable] ZGC concurrent pause vs `STALL_FALLBACK_NS`.** A ZGC concurrent root-scan or relocation pause >50 ms is rare on a healthy heap but can happen under memory pressure or with aggressive `-XX:ZUncommitDelay`. *Mitigation:* (1) the stall fallback itself is the recovery — the kernel's default DSQ runs until Java catches up, so the worst observable effect is a `congestionEvents` spike, not a hang; (2) surface the spike in the §Observability dashboard so operators see it; (3) document recommended JVM flags in §"JVM tuning" — disable `-XX:ZUncommit` for low-latency profiles, set `-XX:ZCollectionInterval=N` to a small value to keep heap pressure predictable; (4) the JFR-based JVM health snapshot already tracks `gcPauseNs` so a regression is attributable.
- **[probable] Run-loop starvation before `frameworkPids` propagates.** The Java run loop is itself a task scheduled by the very scheduler it implements. The kthread fast path plus `frameworkPids` insertion in `init()` together ensure the loop bypasses Java enqueue — but if the BPF program loads before `frameworkPids` is populated with the run-loop tgid, the first ~milliseconds can deadlock. *Mitigation:* populate `frameworkPids` *before* `attachScheduler()` returns (already specified in §`schedulerTgid` propagation); attach the struct_ops only after the map write returns; smoke test asserts `frameworkPids` non-empty within 1s of startup. Hard backstop: the same 50 ms stall fallback handles a worst-case race, so even if the map write is delayed the kernel keeps making forward progress.
- **[polish] PID reuse for `kswapdPid`/`khugepageDPid`.** The framework looks up `kswapd` / `khugepaged` once at startup. If kswapd is killed and restarted (rare; possible during memory hot-add), the recorded PID becomes stale and the kthread fast path misses it — kswapd then routes through Java. *Mitigation:* extend the 1 Hz `frameworkPids` rescan to also re-scan `/proc/*/comm` for these two names (~10 LOC, one extra `readdir` per second). Defer to v1.1 unless smoke test catches it; the kthread fast path is an optimisation, not a correctness requirement — Java handles kswapd correctly via the normal enqueue path, just with more latency than ideal.

### Kernel / operational requirements

- **[blocker] Kernel ≥ 6.17.** Project floor (already documented for `BPFArena`). The combination of struct_ops + arena + `bpf_timer` + user ringbuf works on older kernels piecewise, but the verifier-budget headroom and the `BPF_F_MMAPABLE` arena behaviour the spec relies on assume 6.17+. *Mitigation:* on `BPFProgram.load()` failure, the constructor catches the libbpf error and re-throws `UserspaceSchedulerStartupException` with the running `uname -r`, the required floor, and a one-line pointer to the kernel-upgrade docs — rather than letting libbpf's terse `BPF_PROG_LOAD: invalid argument` bubble up. Add a startup feature probe that checks for `BPF_MAP_TYPE_USER_RINGBUF` support specifically (cheap: `bpf(BPF_PROG_LOAD, …)` with a 1-instruction stub) so the error fires before the heavy load path.
- **[blocker] `CAP_BPF` + `CAP_SYS_ADMIN`.** Required for struct_ops attach (sched_ext is privileged by design). *Mitigation:* document in the README and constructor javadoc; on `EPERM` from `attachScheduler()`, throw `UserspaceSchedulerStartupException` listing the specific capabilities (`CAP_BPF`, `CAP_SYS_ADMIN`, `CAP_PERFMON`) and the typical `sudo` invocation, not the generic `permission denied`. The constructor pre-checks the effective capability set via `/proc/self/status` and warns early if either capability is missing, so the error surfaces *before* the BPF object is loaded.
- **[probable] `RLIMIT_MEMLOCK` for the ringbufs.** Two 4 MiB ringbufs plus ~8 KiB of arenas need ~8 MiB of locked memory. Most modern distros set `RLIMIT_MEMLOCK=infinity` for root, but the framework should not depend on this. *Mitigation:* call `setrlimit(RLIMIT_MEMLOCK, INFINITY)` at startup before any map creation; if `setrlimit` itself fails (capability missing), fall through to map creation and let the explicit `ENOMEM` error path surface a clear message. hello-ebpf's `BPFProgram.load` may already do this — verify in step 1 and skip the framework-level call if so.
- **[polish] `MAX_CPUS = 1024` cap.** On hosts with more online CPUs than this, `updateIdle` must early-return (the `cpu >= MAX_CPUS` guard in `setBit`). *Mitigation:* document the limit in §"Idle CPU bitmap"; add a startup warning when `scx_bpf_nr_cpu_ids() > MAX_CPUS` so the user knows the idle fast path will be disabled (not silently broken). Doubling the cap is a 1-line change but rebuilds the arena layout — defer until a real >1024-CPU host shows up.
- **[polish] CPU-offline race.** `bpf_cpumask_test_cpu` validates affinity at dispatch time, but a CPU can go offline between the test and the kernel actually inserting into `SCX_DSQ_LOCAL_ON | targetCpu`. *Mitigation:* accepted as-is — the kernel handles this by bouncing the task to the runnable set, observable as a `bouncedDispatches` increment. Self-healing, rare in practice, and already counted in the stats surface; no code needed beyond the existing `bouncedDispatches` slot.
- **[polish] Verifier insn-count budget.** scx programs are large; kthread fast path + lifecycle ops + heartbeat + fork tracepoint together approach the 1M-insn verifier limit on older kernels. *Mitigation:* the 6.17 floor leaves comfortable headroom (limit raised to 4M in 6.6). Add a CI check that captures the verifier's reported insn count on every smoke-test run (a one-line awk over `BPF_VERIFIER_LOG_LEVEL=1` output) and asserts it stays under 800k as an early-warning. If a future map/feature addition busts the budget, split into sub-programs (each scheduler callback is independently verified); the spec's program structure already lends itself to this split.

### Documented user-facing contracts (not framework risks, but easy to get wrong)

- **`dequeueTask()` flyweight invalidation.** The pooled `QueuedTask` is invalidated on the next `dequeueTask()` / `Batch.next()` call. `LotterySample` demonstrates the `new QueuedTask(task)` copy pattern; the contract is loud in javadoc. Listed here only so reviewers know the design choice was deliberate.
- **Drain budget enforcement.** `dispatchOne` stops after `scx_bpf_dispatch_nr_slots()` records per call; this is a *correctness requirement*, not a knob users see. Implementation tracks a per-CPU counter, resets on each `dispatch()` entry, returns 1 from the callback when the budget is hit. Stragglers stay in the ringbuf and drain on the next call. Listed here so reviewers can flag any future code that calls `bpf_user_ringbuf_drain` directly.
