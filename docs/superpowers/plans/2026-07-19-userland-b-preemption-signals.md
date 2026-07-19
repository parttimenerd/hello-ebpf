# Sub-project B — Preemption, cross-task signals, multithreaded dispatch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three capabilities to `UserspaceScheduler`: (1) a preemption/control ring so Java can `preempt(pid)`/`kick(cpu, flags)` with sub-batch latency; (2) a BPF→Java signals ring with an `onSignal(Signal)` callback and a BPF `emitSignal(kind, pid, payload)` helper; (3) opt-in `workerThreads(n)` multithreaded dispatch with per-pid affinity.

**Architecture:** Two new ring buffers mirror the existing `dispatched` (user→kernel) and `queued` (kernel→user) rings. The `control` ring carries `ControlCtx { kind, pid, cpu, flags }` drained by BPF in `dispatch()` → `scx_bpf_kick_cpu`. The `signals` ring carries `SignalCtx { kind, pid, payload, ts }` drained by the Java run loop each iteration → `onSignal`. Multithreading shards drained tasks by `hash(pid) % n` to N worker threads, each owning its own dispatch-ring producer. All three default off/absent: a scheduler overriding nothing behaves exactly as today.

**Tech Stack:** Java 25 (Panama FFI, `java.util.concurrent` for workers), hello-ebpf BPF (`BPFRingBuffer`/`BPFUserRingBuffer`, `scx_bpf_kick_cpu`, `bpf_task_from_pid`/`bpf_task_release`, existing `KickFlags`), JUnit 5. Builds/tests on thinkstation only.

**Build/test workflow (CRITICAL):** All builds/tests run on thinkstation, never the mac.
- Sync: `./scripts/sync.sh`
- Command on thinkstation: `./scripts/ts.sh <cmd>`
- Kernel-attach tests (root): `./scripts/ts.sh ./scripts/run-tests-vng.sh <TestClass>`
- After any `bpf-processor` change, reinstall `bpf-processor` THEN `bpf` (jar bundles the plugin — repo memory `bpf_jar_shadows_compiler_plugin`).

**Depends on:** Sub-project A is landed (light dependency — B doesn't touch the extension tail but shares `UserspaceSchedulerBase`; rebase on A first).

---

## Key facts locked from the codebase (do not re-derive)

- `dispatched` (user→kernel) declared at `UserspaceSchedulerBase.java:254-256`: `@BPFMapDefinition(maxEntries = 4 * 1024 * 1024) public BPFUserRingBuffer<DispatchedTaskCtx> dispatched;`
- `queued` (kernel→user) at `:250-252`: `@BPFMapDefinition(maxEntries = 4 * 1024 * 1024) public BPFRingBuffer<QueuedTaskCtx> queued;`
- BPF drains user→kernel with `dispatched.drain((Ptr<T> d, Ptr<Integer> ctx) -> ..., null)` in `dispatch()` at `:658-659`.
- Java reserves/submits into user→kernel: `MemorySegment slot = dispatched.reserve(); slot.set(...); dispatched.submit(slot);` (`submitDispatchDecision`, `:992-1003`).
- Java drains kernel→user with `bpfHandle.queued.consumeRaw(callback, ctx)` (`drainRaw`, `UserspaceScheduler.java:520-531`); callback signature `(seg, size, ctx) -> int` (`:91-97`).
- Run loop `runLoop()` at `UserspaceScheduler.java:419-437`; insert `drainSignalsOnce()` right after `drainBatchOnce();` (line 425).
- `scx_bpf_kick_cpu(int cpu, @Unsigned long flags)` — `ScxDefinitions.java:1414`. `KickFlags` exists (`sched/KickFlags.java`): `none()/idle()/preempt()/waitForKick()`, `carrier` values `0`/`SCX_KICK_IDLE`/`SCX_KICK_PREEMPT`/`SCX_KICK_WAIT`, `or(...)`.
- `bpf_task_from_pid(int)` / `bpf_task_release(Ptr<task_struct>)` — `BpfDefinitions.java:15967` / `:16002`. Acquire→use→release every path (see `dispatchOne` `:683-707`; repo memory on reference leaks).
- Stats slots: last is `HEARTBEAT_KICKS = 13` (`UserspaceSchedulerBase.java:94-123`). Next free = **14**. `incStat(int slot, long delta)` at `:878-886`.
- `Opts` (`userspace/Opts.java`): plain public-field class; add `workerThreads` and `signalPollBudget` here.
- `submitDispatchDecision(targetCpu, pid, enqCnt, sliceNs, vtime)` is the existing Java→BPF seam; `submitControl` will mirror it.

---

## File Structure

- **New** `bpf/.../userspace/Signal.java` — Java signal record + `SignalKind` reserved constants. ~50 lines.
- **New** `bpf/.../userspace/ControlKind.java` — `PREEMPT`/`KICK` int constants (kept tiny; matches `ControlCtx.kind`). ~20 lines.
- **Modify** `bpf/.../UserspaceSchedulerBase.java` — `@Type ControlCtx`, `@Type SignalCtx`, `control` + `signals` ring maps, `emitSignal(...)` BPF helper, drain `control` in `dispatch()`, resolve pid→cpu + `scx_bpf_kick_cpu`, new stats slots, `submitControl(...)` Java writer.
- **Modify** `bpf/.../userspace/UserspaceScheduler.java` — `preempt(int)`, `kick(int, KickFlags)`, `onSignal(Signal)` no-op default, `drainSignalsOnce()` in run loop, worker-thread sharding in `drainBatchOnce`, `protected submitControl(...)` seam.
- **Modify** `bpf/.../userspace/Opts.java` — `workerThreads`, `signalPollBudget`.
- **New** `bpf/.../userspace/ControlDispatchedMarshallingTest.java` — pin `ControlCtx`/`SignalCtx` wire layout.
- **New** `bpf/.../userspace/SignalDeliveryTest.java` — offline drain→`onSignal`, order, overflow drop counting.
- **New** `bpf/.../userspace/WorkerShardingTest.java` — per-pid affinity + total dispatch count == single-threaded.
- **New** `bpf-samples/.../sched/LatencyCriticalSample.java` — `preempt()` demo (~70).
- **New** `bpf-samples/.../sched/LockBoostSignalSample.java` — `emitSignal` demo replacing shared-map hack (~90).

---

## Task 1: `ControlKind` + `Signal`/`SignalKind` Java types

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/ControlKind.java`
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Signal.java`

- [ ] **Step 1: Write `ControlKind`**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/ControlKind.java`:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/** Discriminator for a control-ring record. Matches ControlCtx.kind on the BPF side. */
public final class ControlKind {
    private ControlKind() {}
    /** Preempt whatever runs on the target's CPU so {@code pid} can run ASAP. */
    public static final int PREEMPT = 1;
    /** Kick a specific CPU with {@code flags} (SCX_KICK_*). */
    public static final int KICK    = 2;
}
```

- [ ] **Step 2: Write `Signal` + `SignalKind`**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Signal.java`:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/**
 * A typed event pushed from BPF to the Java scheduler over the signals ring.
 * Delivered to {@link UserspaceScheduler#onSignal(Signal)} in arrival order.
 *
 * @param kind    author-defined int; framework-reserved values in {@link SignalKind}
 * @param pid     subject task pid (or -1 if not task-scoped)
 * @param payload author-defined 64-bit payload
 * @param tsNs    BPF-side timestamp (bpf_ktime_get_ns) at emit time
 */
public record Signal(int kind, int pid, long payload, long tsNs) {

    /** Framework-reserved signal kinds. Author kinds should start well above these. */
    public static final class SignalKind {
        private SignalKind() {}
        public static final int CPU_RELEASED = 1;
        public static final int CPU_IDLE     = 2;
        public static final int TASK_EXIT    = 3;
        /** Authors define domain kinds at or above this value. */
        public static final int FIRST_USER_KIND = 1000;
    }
}
```

- [ ] **Step 3: Compile**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am compile -q`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/ControlKind.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Signal.java
git commit -m "feat(userspace): add ControlKind + Signal/SignalKind types for B channels"
```

---

## Task 2: Control-ring wire contract — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/ControlDispatchedMarshallingTest.java`

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/ControlDispatchedMarshallingTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Pins the ControlCtx and SignalCtx wire layouts bit-for-bit. */
class ControlDispatchedMarshallingTest {

    @Test
    void controlCtxLayout() {
        // ControlCtx { int kind; int cpu; int pid; int _pad; long flags; } — 24 bytes.
        assertEquals(0,  UserspaceSchedulerBase.CTL_KIND);
        assertEquals(4,  UserspaceSchedulerBase.CTL_CPU);
        assertEquals(8,  UserspaceSchedulerBase.CTL_PID);
        assertEquals(16, UserspaceSchedulerBase.CTL_FLAGS);
        assertEquals(24, UserspaceSchedulerBase.CTL_SIZEOF);
    }

    @Test
    void controlCtxRoundTrip() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = arena.allocate(UserspaceSchedulerBase.CTL_SIZEOF);
            seg.set(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_KIND,  ControlKind.PREEMPT);
            seg.set(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_CPU,   3);
            seg.set(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_PID,   4242);
            seg.set(ValueLayout.JAVA_LONG, UserspaceSchedulerBase.CTL_FLAGS, 0L);

            assertEquals(ControlKind.PREEMPT, seg.get(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_KIND));
            assertEquals(3,    seg.get(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_CPU));
            assertEquals(4242, seg.get(ValueLayout.JAVA_INT,  UserspaceSchedulerBase.CTL_PID));
            assertEquals(0L,   seg.get(ValueLayout.JAVA_LONG, UserspaceSchedulerBase.CTL_FLAGS));
        }
    }

    @Test
    void signalCtxLayout() {
        // SignalCtx { int kind; int pid; long payload; long ts; } — 24 bytes.
        assertEquals(0,  UserspaceSchedulerBase.SIG_KIND);
        assertEquals(4,  UserspaceSchedulerBase.SIG_PID);
        assertEquals(8,  UserspaceSchedulerBase.SIG_PAYLOAD);
        assertEquals(16, UserspaceSchedulerBase.SIG_TS);
        assertEquals(24, UserspaceSchedulerBase.SIG_SIZEOF);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=ControlDispatchedMarshallingTest -q`
Expected: COMPILE FAILURE — `CTL_*`/`SIG_*` constants and `CTL_SIZEOF`/`SIG_SIZEOF` don't exist yet.

---

## Task 3: BPF-side `ControlCtx`/`SignalCtx` types + wire constants + rings

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java`

- [ ] **Step 1: Declare the two `@Type` structs**

Near the existing `@Type ... QueuedTaskCtx` / `DispatchedTaskCtx` declarations in `UserspaceSchedulerBase.java`, add:

```java
    /** User→kernel control record: Java submits preempt/kick; BPF drains and acts. */
    @Type
    static class ControlCtx {
        int kind;                 // ControlKind.PREEMPT | ControlKind.KICK
        int cpu;                  // target cpu for KICK; ignored for PREEMPT (resolved from pid)
        int pid;                  // subject task for PREEMPT; ignored for KICK
        int _pad;                 // explicit pad so flags is 8-byte aligned at offset 16
        @Unsigned long flags;     // SCX_KICK_* for KICK; 0 for PREEMPT
    }

    /** Kernel→user signal record: BPF emits typed events; Java drains in the run loop. */
    @Type
    static class SignalCtx {
        int kind;                 // SignalKind.* or an author kind
        int pid;                  // subject pid or -1
        @Unsigned long payload;   // author-defined
        @Unsigned long ts;        // bpf_ktime_get_ns at emit
    }
```

- [ ] **Step 2: Add wire-offset constants (public, for the test + Java writers)**

Add near the existing `DTC_*` constant block (`:941-946`):

```java
    // ControlCtx wire offsets — pinned by ControlDispatchedMarshallingTest.
    public static final long CTL_KIND   = 0;
    public static final long CTL_CPU    = 4;
    public static final long CTL_PID    = 8;
    public static final long CTL_FLAGS  = 16;
    public static final long CTL_SIZEOF = 24;

    // SignalCtx wire offsets — pinned by ControlDispatchedMarshallingTest.
    public static final long SIG_KIND    = 0;
    public static final long SIG_PID     = 4;
    public static final long SIG_PAYLOAD = 8;
    public static final long SIG_TS      = 16;
    public static final long SIG_SIZEOF  = 24;
```

- [ ] **Step 3: Declare the two new ring maps**

Below the existing `queued` and `dispatched` map declarations (`:250-256`), add:

```java
    /** User→kernel control ring: preempt/kick decisions. Separate from dispatch to keep it latency-isolated. */
    @BPFMapDefinition(maxEntries = 1024 * 1024)
    public BPFUserRingBuffer<ControlCtx> control;

    /** Kernel→user signals ring: typed BPF-emitted events for onSignal(). */
    @BPFMapDefinition(maxEntries = 1024 * 1024)
    public BPFRingBuffer<SignalCtx> signals;
```

- [ ] **Step 4: Add new stats slots (append-only, next free = 14)**

In the `Stats` class (`:94-123`), after `HEARTBEAT_KICKS = 13;` add:

```java
        public static final int SIGNALS_DROPPED   = 14;
        public static final int SIGNALS_DELIVERED  = 15;
        public static final int PREEMPTS_ISSUED    = 16;
        public static final int KICKS_ISSUED       = 17;
        public static final int PREEMPT_UNRESOLVED = 18;  // pid→task lookup failed
```

- [ ] **Step 5: Build the bpf module (compile only, checks @Type codegen)**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf-processor -am install -q -DskipTests && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=ControlDispatchedMarshallingTest -q`
Expected: PASS — the marshalling test now compiles and both layout/round-trip assertions are green.

- [ ] **Step 6: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/ControlDispatchedMarshallingTest.java
git commit -m "feat(userspace): add ControlCtx/SignalCtx types, control+signals rings, stats slots"
```

---

## Task 4: BPF-side control drain + `emitSignal` helper

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java`

- [ ] **Step 1: Add a control-drain callback that acts on each record**

Add a `@BPFFunction int drainControlOne(Ptr<ControlCtx> c)` near `dispatchOne` (`:683-707`). It resolves preempt targets via `bpf_task_from_pid`/`bpf_task_release` (acquire→use→release on EVERY path — repo memory on reference leaks):

```java
    @BPFFunction
    int drainControlOne(Ptr<ControlCtx> c) {
        int kind = c.val().kind;
        if (kind == 2 /* ControlKind.KICK */) {
            scx_bpf_kick_cpu(c.val().cpu, c.val().flags);
            incStat(17 /* KICKS_ISSUED */, 1);
            return 0;
        }
        // PREEMPT: resolve pid → its current cpu, then kick that cpu with SCX_KICK_PREEMPT.
        Ptr<task_struct> p = bpf_task_from_pid(c.val().pid);
        if (p == null) {
            incStat(18 /* PREEMPT_UNRESOLVED */, 1);
            return 0;
        }
        int cpu = scx_bpf_task_cpu(p);
        bpf_task_release(p);
        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
        incStat(16 /* PREEMPTS_ISSUED */, 1);
        return 0;
    }
```

Confirm `SCX_KICK_PREEMPT` is importable in this file; if not, use the `KickFlags.preempt().carrier` value or the raw `ScxDefinitions` constant. Check with:

Run: `./scripts/ts.sh --no-tty 'grep -rn "SCX_KICK_PREEMPT\|scx_bpf_task_cpu" bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/ScxDefinitions.java | head'`

- [ ] **Step 2: Drain the control ring inside `dispatch()`**

In the BPF `dispatch()` method, right before or after the existing `dispatched.drain(...)` call (`:658-659`), add a control drain:

```java
        control.drain((Ptr<ControlCtx> c, Ptr<Integer> ctx) -> drainControlOne(c), null);
```

Place the control drain FIRST (preemption is latency-critical) so kicks are issued before ordinary dispatches are processed.

- [ ] **Step 2b: Add the `emitSignal` BPF helper**

Add a `@BPFFunction` usable from any scheduler BPF callback:

```java
    /**
     * Emit a typed signal to the Java scheduler. Best-effort: drops under ring overflow
     * are counted in SIGNALS_DROPPED. Callable from any BPF callback (enqueue, cpuRelease,
     * a companion kprobe, …).
     */
    @BPFFunction
    public void emitSignal(int kind, int pid, long payload) {
        Ptr<SignalCtx> s = signals.reserve();
        if (s == null) { incStat(14 /* SIGNALS_DROPPED */, 1); return; }
        s.val().kind    = kind;
        s.val().pid     = pid;
        s.val().payload = payload;
        s.val().ts      = bpf_ktime_get_ns();
        signals.submit(s);
    }
```

Confirm `bpf_ktime_get_ns` is already imported in this file (it is used elsewhere in the scheduler); if not, grep and add the import used by existing timestamp reads.

- [ ] **Step 3: Rebuild bpf-processor + bpf, run marshalling test again for regression**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf-processor -am install -q -DskipTests && ./scripts/ts.sh ./mvnw -pl bpf -am install -q -DskipTests && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=ControlDispatchedMarshallingTest -q`
Expected: BUILD SUCCESS + marshalling test PASS (BPF C compiles with the new drain + helper; verifier is only exercised at attach time — covered by kernel smoke tests in Tasks 8/9).

- [ ] **Step 4: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java
git commit -m "feat(userspace): drain control ring in dispatch(), add emitSignal BPF helper"
```

---

## Task 5: Java `submitControl` writer + `preempt`/`kick` API

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java` (Java-side `submitControl`)
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java` (`preempt`/`kick` + seam)

- [ ] **Step 1: Add the Java-side `submitControl` writer (mirrors `submitDispatchDecision`)**

In `UserspaceSchedulerBase.java`, next to `submitDispatchDecision` (`:992-1003`), add:

```java
    /** Write one control record into the control ring. Returns 0 on success, -1 on full ring. */
    public int submitControl(int kind, int pid, int cpu, long flags) {
        MemorySegment slot = control.reserve();
        if (slot == null) return -1;
        slot.set(ValueLayout.JAVA_INT,  CTL_KIND,  kind);
        slot.set(ValueLayout.JAVA_INT,  CTL_CPU,   cpu);
        slot.set(ValueLayout.JAVA_INT,  CTL_PID,   pid);
        slot.set(ValueLayout.JAVA_INT,  CTL_KIND + 12, 0); // _pad
        slot.set(ValueLayout.JAVA_LONG, CTL_FLAGS, flags);
        control.submit(slot);
        return 0;
    }
```

(The `_pad` write uses `CTL_KIND + 12` = offset 12; it's harmless to zero it explicitly.)

- [ ] **Step 2: Add `preempt`/`kick` + a protected seam on `UserspaceScheduler`**

In `UserspaceScheduler.java`, add the public API plus a `protected submitControl` seam the offline harness (Sub-project C) can override:

```java
    /** Preempt whatever is running so {@code pid} can run ASAP. Best-effort. */
    public final void preempt(int pid) {
        submitControl(me.bechberger.ebpf.bpf.userspace.ControlKind.PREEMPT, pid, -1, 0L);
    }

    /** Kick a CPU (wake it / force reschedule). flags come from {@link KickFlags}. */
    public final void kick(int cpu, me.bechberger.ebpf.bpf.sched.KickFlags flags) {
        submitControl(me.bechberger.ebpf.bpf.userspace.ControlKind.KICK, -1, cpu, kickFlagsToLong(flags));
    }

    /** Test seam: default routes to the BPF control ring. The harness overrides to capture. */
    protected int submitControl(int kind, int pid, int cpu, long flags) {
        if (bpfHandle == null) return -1;
        return bpfHandle.submitControl(kind, pid, cpu, flags);
    }
```

For `kickFlagsToLong`: `KickFlags` is a `@BPFAbstraction` carrier type, so its numeric value isn't directly readable in plain Java. Add a tiny mapping that mirrors the four constants:

Run: `./scripts/ts.sh --no-tty 'sed -n "1,90p" bpf/src/main/java/me/bechberger/ebpf/bpf/sched/KickFlags.java'`
Then implement `kickFlagsToLong` by matching the flag identity (e.g. an `enum`-like `switch` or by adding a `long value()` accessor to `KickFlags` that returns `0`/`SCX_KICK_IDLE`/`SCX_KICK_PREEMPT`/`SCX_KICK_WAIT` numeric equivalents). Prefer adding a plain-Java `public long toLong()` to `KickFlags` that returns the numeric bitmask (SCX_KICK_IDLE=1, SCX_KICK_PREEMPT=2, SCX_KICK_WAIT=4 — confirm these against the kernel header via the grep in Task 4 Step 1). Use whichever the file structure supports; document the chosen numeric constants inline.

- [ ] **Step 3: Compile**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am compile -q`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/sched/KickFlags.java
git commit -m "feat(userspace): add preempt()/kick() API + submitControl seam"
```

---

## Task 6: `onSignal` delivery + signal drain — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SignalDeliveryTest.java`

- [ ] **Step 1: Write the failing offline test**

The signal drain must be testable without a kernel. The run loop drains `signals` via a `consumeRaw`-style path; the offline seam is `drainSignalsRaw()` (analogous to `drainRaw`). Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SignalDeliveryTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SignalDeliveryTest {

    /** A test scheduler that feeds synthetic SignalCtx segments and records onSignal calls. */
    static class TestSched extends UserspaceScheduler {
        final List<Signal> seen = new ArrayList<>();
        final List<MemorySegment> pending = new ArrayList<>();
        int overflowDrops = 0;

        @Override protected int policy(QueuedTaskShim t) { return -1; } // unused here

        @Override protected void onSignal(Signal s) { seen.add(s); }

        // Offline seam: hand each queued segment to the framework's per-record decoder.
        @Override protected int drainSignalsRaw(java.util.function.Consumer<MemorySegment> sink) {
            int n = 0;
            for (MemorySegment seg : pending) { sink.accept(seg); n++; }
            pending.clear();
            return n;
        }
    }

    private MemorySegment sig(Arena a, int kind, int pid, long payload, long ts) {
        MemorySegment s = a.allocate(24);
        s.set(ValueLayout.JAVA_INT,  0,  kind);
        s.set(ValueLayout.JAVA_INT,  4,  pid);
        s.set(ValueLayout.JAVA_LONG, 8,  payload);
        s.set(ValueLayout.JAVA_LONG, 16, ts);
        return s;
    }

    @Test
    void signalsDeliveredInOrder() {
        try (Arena a = Arena.ofConfined()) {
            TestSched sched = new TestSched();
            sched.pending.add(sig(a, Signal.SignalKind.CPU_IDLE, 10, 0, 100));
            sched.pending.add(sig(a, 1000, 20, 42, 200));

            sched.drainSignalsOnce();

            assertEquals(2, sched.seen.size());
            assertEquals(Signal.SignalKind.CPU_IDLE, sched.seen.get(0).kind());
            assertEquals(10, sched.seen.get(0).pid());
            assertEquals(1000, sched.seen.get(1).kind());
            assertEquals(42, sched.seen.get(1).payload());
        }
    }
}
```

**Note:** `QueuedTaskShim` above stands in for whatever the existing minimal-override policy signature is — check `UserspaceScheduler`'s abstract `policy(...)` signature and match it exactly (it takes a `QueuedTask`). Replace `QueuedTaskShim` with the real `QueuedTask` type and import it. Confirm:

Run: `./scripts/ts.sh --no-tty 'grep -n "protected.*int policy\|abstract.*policy" bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java'`

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=SignalDeliveryTest -q`
Expected: COMPILE FAILURE — `onSignal`, `drainSignalsRaw`, `drainSignalsOnce` don't exist.

---

## Task 7: `onSignal` + signal drain — implement

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java`
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Opts.java`

- [ ] **Step 1: Add `signalPollBudget` to `Opts`**

In `Opts.java`, after `ringPollBudget`:

```java
    /** Max signals drained per run-loop iteration. 0 disables signal draining entirely. */
    public int signalPollBudget = 256;
```

- [ ] **Step 2: Add `onSignal`, `drainSignalsRaw`, `drainSignalsOnce`**

In `UserspaceScheduler.java`, add the callback (default no-op), the raw seam (default consumes the real ring), and the decode-and-dispatch driver:

```java
    /** Override to react to BPF-emitted signals. Default: no-op. */
    protected void onSignal(Signal s) { }

    /**
     * Raw signal drain seam. Default consumes the real signals ring, handing each record
     * segment to {@code sink}. The offline harness overrides this to feed synthetic records.
     * Returns the number of records handed to the sink.
     */
    protected int drainSignalsRaw(java.util.function.Consumer<MemorySegment> sink) {
        if (bpfHandle == null) return 0;
        int[] budget = { opts == null ? 256 : opts.signalPollBudget };
        return bpfHandle.signals.consumeRaw((seg, size, ctx) -> {
            if (budget[0]-- <= 0) return 1;
            sink.accept(seg);
            return 0;
        }, null);
    }

    /** Drain the signals ring once, decoding each record and calling {@link #onSignal}. */
    protected final void drainSignalsOnce() {
        drainSignalsRaw(seg -> {
            Signal s = new Signal(
                seg.get(java.lang.foreign.ValueLayout.JAVA_INT,  0),
                seg.get(java.lang.foreign.ValueLayout.JAVA_INT,  4),
                seg.get(java.lang.foreign.ValueLayout.JAVA_LONG, 8),
                seg.get(java.lang.foreign.ValueLayout.JAVA_LONG, 16));
            try {
                onSignal(s);
            } catch (Throwable t) {
                System.err.println("[sched] onSignal() threw: " + t);
            }
        });
    }
```

- [ ] **Step 3: Call `drainSignalsOnce()` in the run loop**

In `runLoop()` (`:419-437`), after `drainBatchOnce();` (line 425), add:

```java
        drainBatchOnce();
        if (opts.signalPollBudget > 0) drainSignalsOnce();
```

- [ ] **Step 4: Run the signal delivery test**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=SignalDeliveryTest -q`
Expected: PASS — signals delivered in order to `onSignal`.

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Opts.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SignalDeliveryTest.java
git commit -m "feat(userspace): deliver BPF signals to onSignal() via run-loop drain"
```

---

## Task 8: Multithreaded dispatch (opt-in) — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/WorkerShardingTest.java`

- [ ] **Step 1: Write the failing test**

The invariant to test offline: with `workerThreads(n)`, a given pid is always routed to `hash(pid) % n`, and total dispatched count equals the single-threaded count for the same input. Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/WorkerShardingTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WorkerShardingTest {

    @Test
    void samePidAlwaysSameWorker() {
        int n = 4;
        Map<Integer, Integer> pidToWorker = new HashMap<>();
        for (int rep = 0; rep < 3; rep++) {
            for (int pid = 1; pid <= 1000; pid++) {
                int w = UserspaceScheduler.workerForPid(pid, n);
                assertTrue(w >= 0 && w < n, "worker in range");
                Integer prev = pidToWorker.putIfAbsent(pid, w);
                if (prev != null) assertEquals(prev.intValue(), w, "pid " + pid + " stable across reps");
            }
        }
    }

    @Test
    void workerForPidIsUniformEnough() {
        int n = 4;
        int[] counts = new int[n];
        for (int pid = 1; pid <= 4000; pid++) counts[UserspaceScheduler.workerForPid(pid, n)]++;
        for (int c : counts) assertTrue(c > 500, "each worker gets a fair share, got " + c);
    }

    @Test
    void singleWorkerIsIdentity() {
        for (int pid = 0; pid < 100; pid++) assertEquals(0, UserspaceScheduler.workerForPid(pid, 1));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=WorkerShardingTest -q`
Expected: COMPILE FAILURE — `UserspaceScheduler.workerForPid` doesn't exist.

---

## Task 9: Multithreaded dispatch — implement sharding fn + worker plumbing

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Opts.java`
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java`

- [ ] **Step 1: Add `workerThreads` to `Opts`**

```java
    /** Number of policy worker threads. 1 (default) = today's single-threaded loop, byte-identical. */
    public int workerThreads = 1;
```

- [ ] **Step 2: Add the pure sharding function (unit-testable, static)**

In `UserspaceScheduler.java`:

```java
    /** Route a pid to a worker index. Static + pure so the sharding invariant is unit-testable. */
    public static int workerForPid(int pid, int workerThreads) {
        if (workerThreads <= 1) return 0;
        int h = pid * 0x9E3779B1;          // Fibonacci hashing; avoids clustering on sequential pids
        return Math.floorMod(h, workerThreads);
    }
```

- [ ] **Step 3: Run the sharding test (passes with just the static fn)**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=WorkerShardingTest -q`
Expected: PASS — affinity + uniformity + n=1 identity all green. (The worker-thread wiring below is exercised by the kernel smoke test; the correctness-critical invariant is the pure function above.)

- [ ] **Step 4: Wire N workers in `drainBatchOnce` (n>1 only)**

In `drainBatchOnce` / the schedule path, gate on `opts.workerThreads`. For n==1 the path MUST remain byte-identical to today (no queue hop). For n>1: after `drainRaw()` fills `taskPool`, partition tasks by `workerForPid(pid, n)` into per-worker sub-batches, hand each sub-batch to that worker's `schedule(...)`, and have each worker submit through its OWN dispatch producer OR a per-ring lock. Implement the simplest correct version first: **a single dispatch ring guarded by a per-submit lock**, measured; leave a `// TODO(perf): evaluate N dispatch rings` note. Add this near the existing schedule invocation, guarded:

```java
        if (opts.workerThreads <= 1) {
            // unchanged single-threaded path
            schedule(taskPool, drained);
        } else {
            dispatchSharded(taskPool, drained, opts.workerThreads);
        }
```

Implement `dispatchSharded` with a fixed `ExecutorService` of `n` threads created once in `runUntilExit` (store as a field, shut down in the exit path). Each worker owns a reusable `QueuedTask[]` sub-batch buffer (pooled, no per-task alloc); the framework copies flyweights into the worker's buffer via `QueuedTask` reuse (worker i only ever sees pids where `workerForPid == i`, so per-pid state is lock-free). Serialize `submitDispatchDecision` behind a `synchronized` block or a `ReentrantLock` field for v1.

- [ ] **Step 5: Compile + re-run all three B unit tests for regression**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=WorkerShardingTest,SignalDeliveryTest,ControlDispatchedMarshallingTest -q`
Expected: BUILD SUCCESS + all PASS.

- [ ] **Step 6: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Opts.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/WorkerShardingTest.java
git commit -m "feat(userspace): opt-in workerThreads(n) with per-pid affinity sharding"
```

---

## Task 10: `LatencyCriticalSample` — preempt() kernel demo

**Files:**
- Create: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LatencyCriticalSample.java`

- [ ] **Step 1: Mirror an existing sample skeleton**

Run: `./scripts/ts.sh --no-tty 'sed -n "1,80p" bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java'`
Expected: prints the sample structure (package, `@BPF`, `main`, `policy`).

- [ ] **Step 2: Write the sample**

Create `LatencyCriticalSample.java` mirroring `MinimalScheduler`, with a policy that marks tasks whose `comm` matches a `--critical <name>` CLI arg as latency-critical and calls `preempt(pid)` for them the moment they enqueue:

```java
    @Override
    protected int policy(QueuedTask t) {
        if (t.commEquals(criticalComm)) {
            preempt(t.pid);   // demo: force the critical task to run ASAP
        }
        return -1; // ANY_CPU
    }
```

Fill in `main` + a `criticalComm` field parsed from args, mirroring the sample CLI idiom.

- [ ] **Step 3: Kernel smoke test on thinkstation**

Run: `./scripts/ts.sh ./scripts/run-tests-vng.sh LatencyCriticalSample 2>&1 | tail -40`
(Or a manual attach: a low-priority CPU hog + a latency-critical task; assert the critical task's wake-to-run latency drops with `preempt` enabled vs. disabled. If main-only, run the main under vng as root.)
Expected: attaches, no verifier rejection, no reference leak; critical task observably preempts in.

- [ ] **Step 4: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LatencyCriticalSample.java
git commit -m "feat(samples): LatencyCriticalSample demonstrates preempt()"
```

---

## Task 11: `LockBoostSignalSample` — emitSignal demo (replaces shared-map hack)

**Files:**
- Create: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LockBoostSignalSample.java`

- [ ] **Step 1: Locate the existing LockHolderBoost scheduler to port its assertion**

Run: `./scripts/ts.sh --no-tty 'find bpf-samples -iname "*LockHolder*" -o -iname "*LockBoost*"; grep -rln "LockHolderBoost\|LOCK_ACQUIRED\|uprobe" bpf-samples/src 2>/dev/null | head'`
Expected: finds the existing `LockHolderBoostScheduler` (shared-map + uprobe producer) to base the port on.

- [ ] **Step 2: Write the signal-based version**

Create `LockBoostSignalSample.java`. A companion `@Kprobe`/`@Fentry` (or the existing uprobe) calls `emitSignal(LOCK_ACQUIRED, pid, ...)`; the scheduler's `onSignal` reacts by calling `preempt(pid)` or bumping a boost table:

```java
    private static final int LOCK_ACQUIRED = Signal.SignalKind.FIRST_USER_KIND;

    @Override
    protected void onSignal(Signal s) {
        if (s.kind() == LOCK_ACQUIRED) {
            preempt(s.pid());   // boost the lock holder in
        }
    }
```

Keep the companion BPF program a SEPARATE object communicating only via the signals ring (not shared kfuncs) — the verifier rejects mixed uprobe + struct_ops kfunc sharing (repo memory / design risk note).

- [ ] **Step 3: Kernel smoke test**

Run: `./scripts/ts.sh ./scripts/run-tests-vng.sh LockBoostSignalSample 2>&1 | tail -40`
Expected: boosted lock holders get preempted-in; the assertion ported from `LockHolderBoostScheduler` passes. No verifier rejection.

- [ ] **Step 4: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LockBoostSignalSample.java
git commit -m "feat(samples): LockBoostSignalSample replaces shared-map hack with emitSignal"
```

---

## Task 12: Full regression

**Files:** (none — verification)

- [ ] **Step 1: Run the full bpf module test suite**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -q`
Expected: BUILD SUCCESS — new B tests plus all existing marshalling/round-trip tests green; n=1 path unchanged.

- [ ] **Step 2: Run kernel-attach smoke tests for both samples via vng**

Run: `./scripts/ts.sh ./scripts/run-tests-vng.sh LatencyCriticalSample LockBoostSignalSample 2>&1 | tail -60`
Expected: both attach and pass their assertions on thinkstation.

---

## Self-review notes

- **Spec coverage:** preempt/kick API (Task 5) + control ring (Tasks 3/4) + separate-ring latency isolation (Task 3 Step 3 comment); onSignal + emitSignal + signals ring + overflow drop counting (Tasks 3/4/6/7, `SIGNALS_DROPPED` slot 14); workerThreads with per-pid affinity + n=1 identity (Tasks 8/9); all three default off (Opts defaults: `workerThreads=1`, `signalPollBudget>0` but drain is no-op without emits, no override = no preempt/onSignal). Marshalling contract pinned (Task 2). LockHolderBoost subsumed (Task 11).
- **Type consistency:** `ControlKind.PREEMPT=1`/`KICK=2` used identically in `drainControlOne` (as literals `1`/`2` on the BPF side where the enum import may not be visible — commented) and `preempt`/`kick` (via the constants). `CTL_*`/`SIG_*` offsets identical in the `@Type` structs, the marshalling test, and `submitControl`/`drainSignalsOnce`. Stats slots 14-18 appended after 13, no reuse. `workerForPid(pid, n)` signature identical in test and impl.
- **Reference-leak discipline:** `drainControlOne` releases the task on both the null and success paths (Task 4 Step 1) — the one place `bpf_task_from_pid` is used in this sub-project.
- **Open decision resolved in-plan:** multi-producer rings → v1 uses a single dispatch ring guarded by a lock (Task 9 Step 4), with an explicit perf TODO, per the design's "measure the lock-guarded path first."
- **Unverified assumptions flagged with grep checks:** `SCX_KICK_PREEMPT` importability (Task 4 Step 1), `KickFlags` numeric mapping (Task 5 Step 2), abstract `policy` signature for the test shim (Task 6 Step 1). Each is a build-check decision point, not a silent assumption.
