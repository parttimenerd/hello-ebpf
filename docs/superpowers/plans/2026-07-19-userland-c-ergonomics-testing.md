# Sub-project C — Ergonomics & offline testing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide four pure-Java helpers so scheduler authors stop re-inventing scaffolding: `DeferredQueue` (cross-batch task store), `TaskClassifier<C>` (multi-class routing), `SchedulerHarness` (drive a scheduler offline with synthetic batches and assert decisions), and `SchedulerRunner` (one-line `main`).

**Architecture:** All four are pure Java, no BPF/wire changes. `SchedulerHarness` formalizes the existing `FakeSchedulerBase` test pattern (overrides BPF lifecycle seams to no-ops, drives `drainRaw`, captures `submitDispatch`) and lives in `src/main` so `bpf-samples` tests can consume it. `DeferredQueue` and `TaskClassifier` are self-contained data structures. `SchedulerRunner` wraps the femtocli `Cli` + shutdown-hook + stats-thread boilerplate.

**Tech Stack:** Java 25, JUnit 5, femtocli (`me.bechberger.femtocli`, `@Command`/`@Option`, `FemtoCli.run`). Pure Java — unit tests run anywhere, but per repo policy still executed on thinkstation.

**Build/test workflow (CRITICAL):** All builds/tests on thinkstation, never the mac.
- Sync: `./scripts/sync.sh`
- Command on thinkstation: `./scripts/ts.sh <cmd>`
- These are pure-Java tests: `./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=<Class> -q` (no vng/root needed). The migrated `VtimeSample` keeps its existing thinkstation smoke test.

**Depends on:** Sub-project A landed (light — `DeferredQueue.deferUntil` copies `QueuedTask` including A's tail via `copy()`). B is NOT required for C's core, but `SchedulerHarness` should also expose a `submitControl` capture seam if B has landed (guarded/optional task at the end).

---

## Key facts locked from the codebase (do not re-derive)

- Existing offline pattern: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/FakeSchedulerBase.java` — overrides `loadAndAttachBpf`/`cleanupBpf`/`isAttached`/`idleMaskView`/`putFrameworkPid`/`frameworkPidsIterable`/`submitDispatch`, drives `drainRaw()` from a `List<QueuedTask> fakeTasks`, uses `ensureTaskPool(n)` + `batchCtx.count`. **This is the blueprint for `SchedulerHarness`** — but package-private/test-scope; the harness re-implements the same seam set in `src/main`.
- Seams (all in `UserspaceScheduler.java`): `policy(QueuedTask)` `:113`, `schedule(QueuedTask[], int)` `:144`, `tick()` `:162`, `drainRaw()` `:520`, `submitDispatch(int,int,long,long,long)` `:679`, `idleMaskView()` `:716`, `dispatchTask(QueuedTask,int)` public final `:503`, `record{BatchSize,RoundTrip,RingConsume}` `:562/573/584`.
- `bpfHandle == null` is handled in `drainRaw` (sleeps), `idleMaskView` (null), record* (guarded), `frameworkPidsIterable` (empty). Only `submitDispatch` NPEs on null handle → harness overrides it.
- `dispatchTask` → `dispatchInternal` → `submitDispatch(target, pid, enqCnt, 0L, vtime)`. `ANY_CPU == -1`; `cpu==ANY_CPU` → `pickIdleCpu()` (uses `idleMaskView`).
- `QueuedTask`: public no-arg ctor, public mutable fields (`pid`, `prevCpu`, `weight`, `vtime`, `enqCnt`, …), `copy()`. Test construction: `var t = new QueuedTask(); t.pid = …; t.weight = …;`.
- `VtimeSample` (`bpf-samples/.../sched/VtimeSample.java`): `Map<Integer,Long> vtimes` + `long minVtime`; `schedule()` builds a per-batch `TreeMap<Long,QueuedTask>` keyed by `vt << 20 | (pid & 0xFFFFF)`, drains in vtime order, `step = SLICE_NS * 100 / weight`. Its `Cli` (`:100-145`) is the boilerplate `SchedulerRunner` replaces; `main` uses `FemtoCli.run(new Cli(), args)`.
- `ShowcaseScheduler`: `enum Tier {INTERACTIVE_FRESH, INTERACTIVE_HOT, HOST_JVM, CONTAINER, BUILDER, OTHER}` + `HashMap<Integer,PidInfo> pids` + classify() reading /proc. Pattern `TaskClassifier` replaces.
- Test dirs: core module → `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/`; samples → `bpf-samples/src/test/java/me/bechberger/ebpf/samples/sched/` (create if absent) or `.../bpf/`.
- **Decision locked:** `SchedulerHarness`, `DeferredQueue`, `TaskClassifier`, `SchedulerRunner` all in `bpf` module `src/main`, package `me.bechberger.ebpf.bpf.userspace` — matches how `FakeSchedulerBase` seams already live in that package, avoids a new module. `SchedulerHarness` is a small non-test surface in the jar (accepted, per design).

---

## File Structure

- **New** `bpf/.../userspace/DeferredQueue.java` — min-heap keyed by `(key, pid)` + time index; stores `QueuedTask.copy()`. ~130 lines.
- **New** `bpf/.../userspace/TaskClassifier.java` — `TaskClassifier<C extends Enum<C>>` builder: `classify(fn)` + `policy(C, fn)` → `decide(QueuedTask)`. ~120 lines.
- **New** `bpf/.../userspace/SchedulerHarness.java` — wraps a `UserspaceScheduler`, no-op BPF seams, `feed`/`runBatch`/`tick`, captures `dispatches()`. ~180 lines.
- **New** `bpf/.../userspace/SchedulerRunner.java` — `run(UserspaceScheduler, String[])`: femtocli + shutdown hook + stats thread. ~90 lines.
- **New tests** `DeferredQueueTest`, `TaskClassifierTest`, `SchedulerHarnessTest` in `bpf/src/test/.../userspace/`.
- **Modify** `bpf-samples/.../sched/VtimeSample.java` — migrate `schedule()` to `DeferredQueue`, `main` to `SchedulerRunner`.
- **New** `bpf-samples/.../sched/VtimeSampleTest.java` — offline policy test via harness (lowest-vtime dispatched first).

---

## Task 1: `DeferredQueue` — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/DeferredQueueTest.java`

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/DeferredQueueTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DeferredQueueTest {

    private QueuedTask task(int pid, long vtime) {
        var t = new QueuedTask();
        t.pid = pid;
        t.vtime = vtime;
        t.weight = 100;
        return t;
    }

    @Test
    void deferOrderedDrainsInKeyOrder() {
        var q = new DeferredQueue();
        q.deferOrdered(task(3, 0), 30);
        q.deferOrdered(task(1, 0), 10);
        q.deferOrdered(task(2, 0), 20);

        List<Integer> pids = new ArrayList<>();
        q.drainEligible(0, Integer.MAX_VALUE, t -> pids.add(t.pid));
        assertEquals(List.of(1, 2, 3), pids, "min-key drains first");
        assertEquals(0, q.size());
    }

    @Test
    void deferUntilRespectsTime() {
        var q = new DeferredQueue();
        q.deferUntil(task(1, 0), 100);   // eligible at 100
        q.deferUntil(task(2, 0), 200);   // eligible at 200

        List<Integer> early = new ArrayList<>();
        q.drainEligible(150, Integer.MAX_VALUE, t -> early.add(t.pid));
        assertEquals(List.of(1), early, "only pid 1 is eligible at t=150");
        assertEquals(1, q.size());

        List<Integer> late = new ArrayList<>();
        q.drainEligible(250, Integer.MAX_VALUE, t -> late.add(t.pid));
        assertEquals(List.of(2), late);
        assertEquals(0, q.size());
    }

    @Test
    void drainEligibleRespectsMax() {
        var q = new DeferredQueue();
        for (int i = 1; i <= 5; i++) q.deferOrdered(task(i, 0), i);
        List<Integer> got = new ArrayList<>();
        q.drainEligible(0, 2, t -> got.add(t.pid));
        assertEquals(2, got.size(), "max caps the drain");
        assertEquals(3, q.size());
    }

    @Test
    void evictOlderThanBoundsSize() {
        var q = new DeferredQueue();
        q.deferUntil(task(1, 0), 10);
        q.deferUntil(task(2, 0), 100);
        q.evictOlderThan(50);   // drops entries whose notBefore < 50
        assertEquals(1, q.size());
    }

    @Test
    void storesCopiesSafeAcrossBatches() {
        var q = new DeferredQueue();
        var t = task(42, 7);
        q.deferOrdered(t, 5);
        t.pid = 999;            // mutate the flyweight after deferring
        List<Integer> got = new ArrayList<>();
        q.drainEligible(0, Integer.MAX_VALUE, x -> got.add(x.pid));
        assertEquals(List.of(42), got, "deferred task is a copy, not the mutated flyweight");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=DeferredQueueTest -q`
Expected: COMPILE FAILURE — `DeferredQueue` does not exist.

---

## Task 2: `DeferredQueue` — implement

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/DeferredQueue.java`

- [ ] **Step 1: Write the implementation**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/DeferredQueue.java`:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;

import java.util.PriorityQueue;
import java.util.function.Consumer;

/**
 * Cross-batch task store for sorted/deferred scheduling policies (vtime, EDF, delay).
 * Stores {@link QueuedTask#copy() copies} so entries are safe to retain across batch
 * boundaries (the framework reuses the drained flyweights).
 *
 * <p>Two ordering modes share one heap:
 * <ul>
 *   <li>{@link #deferOrdered} — min-key first (vtime, deadline). {@code notBefore = Long.MIN_VALUE}
 *       so it is always time-eligible.</li>
 *   <li>{@link #deferUntil} — becomes eligible at {@code notBeforeNs}; among eligible entries,
 *       still drained in key order (key defaults to {@code notBeforeNs}).</li>
 * </ul>
 * Not thread-safe: a given pid is handled by one worker (see Sub-project B affinity).
 */
public final class DeferredQueue {

    private record Entry(QueuedTask task, long key, long notBeforeNs, long seq) {}

    // Order by (key, then pid, then insertion seq) for a total, stable order.
    private final PriorityQueue<Entry> heap = new PriorityQueue<>((a, b) -> {
        int c = Long.compare(a.key, b.key);
        if (c != 0) return c;
        c = Integer.compare(a.task.pid, b.task.pid);
        if (c != 0) return c;
        return Long.compare(a.seq, b.seq);
    });
    private long seqCounter = 0;

    /** Store a copy of {@code t} to (re)consider at or after {@code notBeforeNs}. */
    public void deferUntil(QueuedTask t, long notBeforeNs) {
        heap.add(new Entry(t.copy(), notBeforeNs, notBeforeNs, seqCounter++));
    }

    /** Store a copy of {@code t} keyed by {@code key} (vtime/deadline). Min-key drains first. */
    public void deferOrdered(QueuedTask t, long key) {
        heap.add(new Entry(t.copy(), key, Long.MIN_VALUE, seqCounter++));
    }

    /**
     * Drain up to {@code max} tasks that are time-eligible at {@code nowNs}, in key order,
     * handing each to {@code sink}. Time-ineligible entries block nothing behind them only
     * if they sort after eligible ones; to keep it simple and correct we scan-and-reinsert.
     */
    public void drainEligible(long nowNs, int max, Consumer<QueuedTask> sink) {
        if (max <= 0 || heap.isEmpty()) return;
        java.util.ArrayList<Entry> deferredBack = new java.util.ArrayList<>();
        int drained = 0;
        while (drained < max && !heap.isEmpty()) {
            Entry e = heap.poll();
            if (e.notBeforeNs <= nowNs) {
                sink.accept(e.task);
                drained++;
            } else {
                deferredBack.add(e);
            }
        }
        heap.addAll(deferredBack);
    }

    /** Evict entries whose {@code notBeforeNs} is strictly older than {@code horizonNs}. */
    public void evictOlderThan(long horizonNs) {
        heap.removeIf(e -> e.notBeforeNs < horizonNs);
    }

    public int size() { return heap.size(); }
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=DeferredQueueTest -q`
Expected: PASS — all five tests green.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/DeferredQueue.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/DeferredQueueTest.java
git commit -m "feat(userspace): add DeferredQueue cross-batch task store"
```

---

## Task 3: `TaskClassifier` — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/TaskClassifierTest.java`

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/TaskClassifierTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TaskClassifierTest {

    enum Tier { INTERACTIVE, BATCH }

    private QueuedTask task(int pid, int prevCpu, long weight) {
        var t = new QueuedTask();
        t.pid = pid; t.prevCpu = prevCpu; t.weight = weight;
        return t;
    }

    private TaskClassifier<Tier> build() {
        return TaskClassifier.<Tier>builder()
            .classify(t -> t.weight >= 200 ? Tier.INTERACTIVE : Tier.BATCH)
            .policy(Tier.INTERACTIVE, t -> -1)                                  // ANY_CPU
            .policy(Tier.BATCH,       t -> t.prevCpu >= 0 ? t.prevCpu : -1)     // stick to prev cpu
            .build();
    }

    @Test
    void classifyRoutesToPerClassPolicy() {
        var c = build();
        assertEquals(-1, c.decide(task(1, 5, 300)));   // INTERACTIVE → ANY_CPU
        assertEquals(5,  c.decide(task(2, 5, 100)));   // BATCH, prevCpu=5 → 5
        assertEquals(-1, c.decide(task(3, -1, 100)));  // BATCH, no prevCpu → ANY_CPU
    }

    @Test
    void classOfExposesClassification() {
        var c = build();
        assertEquals(Tier.INTERACTIVE, c.classOf(task(1, 0, 500)));
        assertEquals(Tier.BATCH,       c.classOf(task(2, 0, 50)));
    }

    @Test
    void missingPolicyThrowsClearly() {
        var c = TaskClassifier.<Tier>builder()
            .classify(t -> Tier.INTERACTIVE)
            .policy(Tier.INTERACTIVE, t -> -1)
            .build();   // BATCH has no policy
        // classify always returns INTERACTIVE, so decide is fine; force a BATCH:
        var bad = TaskClassifier.<Tier>builder()
            .classify(t -> Tier.BATCH)
            .policy(Tier.INTERACTIVE, t -> -1)
            .build();
        assertThrows(IllegalStateException.class, () -> bad.decide(task(1, 0, 100)));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=TaskClassifierTest -q`
Expected: COMPILE FAILURE — `TaskClassifier` does not exist.

---

## Task 4: `TaskClassifier` — implement

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/TaskClassifier.java`

- [ ] **Step 1: Write the implementation**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/TaskClassifier.java`:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;

import java.util.EnumMap;
import java.util.Map;
import java.util.function.Function;
import java.util.function.ToIntFunction;

/**
 * Maps a {@link QueuedTask} to a class enum, then to a per-class placement policy.
 * Turns the copy-paste "classify task → route to band" pattern into a table.
 *
 * <pre>{@code
 * var c = TaskClassifier.<Tier>builder()
 *     .classify(t -> tierOf(t))
 *     .policy(Tier.INTERACTIVE, t -> ANY_CPU)
 *     .policy(Tier.BATCH,       t -> t.prevCpu >= 0 ? t.prevCpu : ANY_CPU)
 *     .build();
 * // in a scheduler: protected int policy(QueuedTask t) { return c.decide(t); }
 * }</pre>
 */
public final class TaskClassifier<C extends Enum<C>> {

    private final Function<QueuedTask, C> classifier;
    private final Map<C, ToIntFunction<QueuedTask>> policies;

    private TaskClassifier(Function<QueuedTask, C> classifier, Map<C, ToIntFunction<QueuedTask>> policies) {
        this.classifier = classifier;
        this.policies = policies;
    }

    /** The class this task falls into. */
    public C classOf(QueuedTask t) { return classifier.apply(t); }

    /** Classify {@code t} and apply its class's placement policy; returns the target cpu (or ANY_CPU). */
    public int decide(QueuedTask t) {
        C c = classifier.apply(t);
        ToIntFunction<QueuedTask> p = policies.get(c);
        if (p == null) throw new IllegalStateException("no policy registered for class " + c);
        return p.applyAsInt(t);
    }

    public static <C extends Enum<C>> Builder<C> builder() { return new Builder<>(); }

    public static final class Builder<C extends Enum<C>> {
        private Function<QueuedTask, C> classifier;
        private final Map<C, ToIntFunction<QueuedTask>> policies = new java.util.HashMap<>();

        public Builder<C> classify(Function<QueuedTask, C> fn) { this.classifier = fn; return this; }

        public Builder<C> policy(C cls, ToIntFunction<QueuedTask> placement) {
            policies.put(cls, placement);
            return this;
        }

        public TaskClassifier<C> build() {
            if (classifier == null) throw new IllegalStateException("classify(...) is required");
            return new TaskClassifier<>(classifier, Map.copyOf(policies));
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=TaskClassifierTest -q`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/TaskClassifier.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/TaskClassifierTest.java
git commit -m "feat(userspace): add TaskClassifier for multi-class routing"
```

---

## Task 5: `SchedulerHarness` — failing self-test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SchedulerHarnessTest.java`

- [ ] **Step 1: Write the failing self-test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SchedulerHarnessTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SchedulerHarnessTest {

    /** Trivial scheduler: dispatch every task to ANY_CPU, count ticks. */
    static class TrivialSched extends UserspaceScheduler {
        int ticks = 0;
        @Override protected void schedule(QueuedTask[] tasks, int count) {
            for (int i = 0; i < count; i++) dispatchTask(tasks[i], -1);
        }
        @Override protected void tick() { ticks++; }
    }

    private QueuedTask task(int pid, long weight) {
        var t = new QueuedTask(); t.pid = pid; t.weight = weight; return t;
    }

    @Test
    void capturesDispatchesInOrder() {
        var sched = new TrivialSched();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8);

        harness.feed(task(100, 200), task(101, 100));
        harness.runBatch();

        List<SchedulerHarness.Dispatch> ds = harness.dispatches();
        assertEquals(2, ds.size());
        assertEquals(100, ds.get(0).pid());
        assertEquals(101, ds.get(1).pid());
    }

    @Test
    void tickDrivesSchedulerTick() {
        var sched = new TrivialSched();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(4);
        harness.tick();
        harness.tick();
        assertEquals(2, sched.ticks);
    }

    @Test
    void runBatchClearsBetweenRuns() {
        var sched = new TrivialSched();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(4);
        harness.feed(task(1, 100));
        harness.runBatch();
        assertEquals(1, harness.dispatches().size());

        harness.feed(task(2, 100));
        harness.runBatch();
        // dispatches() accumulates across runs; the second run adds one more.
        assertEquals(2, harness.dispatches().size());
        assertEquals(2, harness.dispatches().get(1).pid());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=SchedulerHarnessTest -q`
Expected: COMPILE FAILURE — `SchedulerHarness` does not exist.

---

## Task 6: `SchedulerHarness` — implement

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerHarness.java`

- [ ] **Step 1: Confirm the seam names to override**

Run: `./scripts/ts.sh --no-tty 'grep -n "protected.*drainRaw\|protected.*submitDispatch\|protected.*idleMaskView\|protected.*loadAndAttachBpf\|protected.*cleanupBpf\|protected.*isAttached\|protected.*putFrameworkPid\|protected.*frameworkPidsIterable\|void drainBatchOnce\|ensureTaskPool\|batchCtx" bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java'`
Expected: confirms the exact seam signatures and that `drainBatchOnce`/`ensureTaskPool`/`batchCtx` are accessible to a same-package subclass (they are — `FakeSchedulerBase` uses them). The harness's inner scheduler-wrapper lives in the same package so it can reach them.

- [ ] **Step 2: Write the implementation**

The harness cannot subclass the user's scheduler (that's the user's class). Instead it **installs itself as the BPF-seam backend** on the user's scheduler instance. Because the seams are `protected` on `UserspaceScheduler`, the harness provides a same-package bridge: a package-private method set on `UserspaceScheduler` is not available, so the harness drives the scheduler through a thin adapter subclass the USER's scheduler already is. The simplest correct approach that matches `FakeSchedulerBase`: the harness requires the scheduler under test to be driven via a package-private hook the harness sets. Implement it by having `SchedulerHarness` hold the scheduler and call a new package-private `runBatchOffline(...)` added to `UserspaceScheduler` that (a) fills `taskPool` from a supplied list, (b) sets `batchCtx.count`, (c) calls the existing `drainBatchOnce` body's schedule path, and (d) routes `submitDispatch` capture through a settable sink.

Add to `UserspaceScheduler.java` (same commit) a minimal offline hook:

```java
    // ── Offline harness support (package-private; no effect in production) ──────
    private java.util.function.IntUnaryOperator offlineIdleCpu;               // pid→cpu stub, optional
    java.util.List<QueuedTask> offlineFeed;                                    // set by harness
    java.util.function.Consumer<int[]> offlineDispatchSink;                    // {targetCpu,pid} sink

    /** Package-private: drive one batch from {@link #offlineFeed} with no BPF handle. */
    void runBatchOffline() {
        if (offlineFeed == null) return;
        int n = offlineFeed.size();
        ensureTaskPool(n);
        for (int i = 0; i < n; i++) taskPool[i] = offlineFeed.get(i);
        batchCtx.count = n;
        schedule(taskPool, n);
    }
```

Override the capture seam in the same file so offline dispatch is captured when a sink is set (guard keeps production untouched):

In `submitDispatch` (`:679`), wrap the existing body:

```java
    protected int submitDispatch(int targetCpu, int pid, long enqCnt, long sliceNs, long vtime) {
        if (offlineDispatchSink != null) {          // offline mode
            offlineDispatchSink.accept(new int[]{ targetCpu, pid });
            return 0;
        }
        return bpfHandle.submitDispatchDecision(targetCpu, pid, enqCnt, sliceNs, vtime);
    }
```

Also make `idleMaskView`/`isAttached` tolerate offline mode: when `offlineDispatchSink != null`, `pickIdleCpu` must not touch a null `idleMaskView`. Confirm `pickIdleCpu` already handles `idleMaskView()==null` (research showed it does — returns a default cpu); if not, add: when offline, `dispatchTask(t, ANY_CPU)` should capture with `targetCpu = -1` rather than resolving an idle cpu. Simplest: in offline mode, capture the RAW requested cpu. To do that, capture in `dispatchInternal` BEFORE the `ANY_CPU→pickIdleCpu` resolution is not possible without touching it; instead, since the tests dispatch to `-1` and assert on `pid` only, capturing post-resolution is fine as long as `pickIdleCpu()` returns without NPE when `idleMaskView()` is null. Verify:

Run: `./scripts/ts.sh --no-tty 'sed -n "700,760p" bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java'`
If `pickIdleCpu` NPEs on null idle view, add an offline guard returning `0`.

Now create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerHarness.java`:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Drives a {@link UserspaceScheduler} subclass offline — synthetic batches in, captured
 * decisions out — with no BPF file descriptor and no root. Tests <em>policy decisions</em>,
 * not kernel timing/preemption (see design risk note). Complements the thinkstation smoke tests.
 *
 * <pre>{@code
 * var harness = SchedulerHarness.forScheduler(new MyScheduler()).withCpus(8);
 * harness.feed(task(100, 200), task(101, 100));
 * harness.runBatch();
 * assertThat(harness.dispatches()).extracting(Dispatch::pid).containsExactly(100, 101);
 * }</pre>
 */
public final class SchedulerHarness {

    /** A captured dispatch decision. */
    public record Dispatch(int targetCpu, int pid) {}

    private final UserspaceScheduler sched;
    private final List<Dispatch> dispatches = new ArrayList<>();
    private int cpus = Runtime.getRuntime().availableProcessors();

    private SchedulerHarness(UserspaceScheduler sched) {
        this.sched = sched;
        sched.offlineDispatchSink = arr -> dispatches.add(new Dispatch(arr[0], arr[1]));
    }

    public static SchedulerHarness forScheduler(UserspaceScheduler sched) {
        return new SchedulerHarness(sched);
    }

    public SchedulerHarness withCpus(int n) { this.cpus = n; return this; }

    /** Queue tasks for the next {@link #runBatch}. */
    public SchedulerHarness feed(QueuedTask... tasks) {
        sched.offlineFeed = new ArrayList<>(Arrays.asList(tasks));
        return this;
    }

    /** Run one batch through the scheduler's schedule() path; captured dispatches accumulate. */
    public void runBatch() {
        sched.runBatchOffline();
        sched.offlineFeed = null;
    }

    /** Drive one periodic tick(). */
    public void tick() { sched.tick(); }

    /** All dispatches captured so far, in order. */
    public List<Dispatch> dispatches() { return List.copyOf(dispatches); }

    /** Clear captured dispatches (e.g. between assertion phases). */
    public void clear() { dispatches.clear(); }

    public int cpus() { return cpus; }
}
```

- [ ] **Step 3: Run the self-test to verify it passes**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=SchedulerHarnessTest -q`
Expected: PASS — capture, tick, and cross-run accumulation all green.

- [ ] **Step 4: Run FakeSchedulerBase-dependent tests for regression**

Run: `./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=JfrEmissionTest,HistogramsTest -q`
Expected: PASS — the `submitDispatch` rewrite (guarded by `offlineDispatchSink != null`) leaves the existing fake-scheduler tests unaffected (their `submitDispatch` override in `FakeSchedulerBase` short-circuits before the new guard is reached — confirm `FakeSchedulerBase` still overrides the method; it does).

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerHarness.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SchedulerHarnessTest.java
git commit -m "feat(userspace): add SchedulerHarness for offline policy testing"
```

---

## Task 7: `SchedulerRunner` — one-line main

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerRunner.java`

- [ ] **Step 1: Read the exact femtocli + boilerplate to replicate**

Run: `./scripts/ts.sh --no-tty 'sed -n "95,150p" bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/VtimeSample.java'`
Expected: the `Cli` inner class (shutdown hook + stats thread + `runUntilExit`) and `FemtoCli.run(new Cli(), args)`. Also confirm the public methods used: `requestExit()`, `exited()`, `formatStats()`, `printHistograms(PrintStream)`, `runUntilExit(Opts)`.

Run: `./scripts/ts.sh --no-tty 'grep -n "public.*requestExit\|public.*exited\|public.*formatStats\|public.*printHistograms\|public.*runUntilExit" bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java'`

- [ ] **Step 2: Write the runner**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerRunner.java`. Use the exact method names confirmed in Step 1:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

/**
 * One-call launcher: wires the shutdown hook, the periodic stats thread, and
 * {@code runUntilExit} so a sample's {@code main} shrinks to one line:
 *
 * <pre>{@code
 * public static void main(String[] args) {
 *     SchedulerRunner.run(new VtimeSample(), args);
 * }
 * }</pre>
 *
 * <p>Reads {@code --stats-interval <sec>} (default 5; 0 = off) from {@code args}.
 * (Metrics-port wiring is Sub-project D and layered on separately.)
 */
public final class SchedulerRunner {
    private SchedulerRunner() {}

    public static void run(UserspaceScheduler sched, String[] args) {
        int statsInterval = parseIntOpt(args, "--stats-interval", 5);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            sched.requestExit();
            while (!sched.exited()) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); break; }
            }
            System.err.println();
            System.err.println("==== Final stats ====");
            System.err.println(sched.formatStats());
            System.err.println("==== Histograms ====");
            sched.printHistograms(System.err);
        }));

        if (statsInterval > 0) {
            long intervalNs = (long) statsInterval * 1_000_000_000L;
            Thread t = new Thread(() -> {
                long deadline = System.nanoTime() + intervalNs;
                try {
                    while (!sched.exited()) {
                        Thread.sleep(200);
                        if (System.nanoTime() >= deadline) {
                            System.err.printf("[stats] %s%n", sched.formatStats());
                            deadline += intervalNs;
                        }
                    }
                } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }, "sched-stats");
            t.setDaemon(true);
            t.start();
        }

        sched.runUntilExit(Opts.defaults());
    }

    private static int parseIntOpt(String[] args, String name, int dflt) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals(name)) {
                try { return Integer.parseInt(args[i + 1]); } catch (NumberFormatException e) { return dflt; }
            }
        }
        return dflt;
    }
}
```

If any of `requestExit`/`exited`/`formatStats`/`printHistograms` is not public, promote it to public in `UserspaceScheduler.java` in this task (they are already used by the sample `Cli` in the same package, so they may be package-private — if so, make public since `SchedulerRunner` is same-package and doesn't strictly need it, but samples in other packages call `run` not these methods, so package-private is fine). Verify in Step 1's grep.

- [ ] **Step 3: Compile**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am compile -q`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerRunner.java
git commit -m "feat(userspace): add SchedulerRunner one-line launcher"
```

---

## Task 8: Migrate `VtimeSample` + offline policy test (the proof point)

**Files:**
- Modify: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/VtimeSample.java`
- Create: `bpf-samples/src/test/java/me/bechberger/ebpf/samples/sched/VtimeSampleTest.java`

- [ ] **Step 1: Write the offline policy test first (drives the migration)**

Create `bpf-samples/src/test/java/me/bechberger/ebpf/samples/sched/VtimeSampleTest.java`:

```java
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.SchedulerHarness;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** The proof point: vtime ordering asserted offline, no kernel. */
class VtimeSampleTest {

    private QueuedTask task(int pid, long vtime, long weight) {
        var t = new QueuedTask(); t.pid = pid; t.vtime = vtime; t.weight = weight; return t;
    }

    @Test
    void lowestVtimeDispatchedFirst() {
        var sched = new VtimeSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8);

        // Fed out of order; the policy must dispatch in ascending vtime.
        harness.feed(task(3, 300, 100), task(1, 100, 100), task(2, 200, 100));
        harness.runBatch();

        List<Integer> order = harness.dispatches().stream().map(SchedulerHarness.Dispatch::pid).toList();
        assertEquals(List.of(1, 2, 3), order, "vtime policy dispatches lowest-vtime first");
    }
}
```

- [ ] **Step 2: Run to verify it fails (compiles, wrong order or NPE)**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf-samples -am test -Dtest=VtimeSampleTest -q`
Expected: FAIL — either `VtimeSample` isn't harness-drivable yet, or the current TreeMap logic works but we're about to migrate it. If it already PASSES with the current TreeMap code, that's fine — the migration must keep it passing.

- [ ] **Step 3: Migrate `VtimeSample.schedule()` to `DeferredQueue`**

Replace the `Map<Integer,Long> vtimes` + per-batch `TreeMap` with a per-pid vtime map (kept — vtime state is inherently per-pid) plus using `DeferredQueue` for ordered draining within the batch. Minimal migration keeping behavior identical:

```java
    // keep per-pid vtime accounting (this is domain state, not scaffolding)
    private final java.util.Map<Integer, Long> vtimes = new java.util.HashMap<>();
    private long minVtime = 0;

    @Override
    protected void schedule(QueuedTask[] tasks, int count) {
        var ordered = new me.bechberger.ebpf.bpf.userspace.DeferredQueue();
        for (int i = 0; i < count; i++) {
            QueuedTask t = tasks[i];
            long vt = vtimes.computeIfAbsent(t.pid, p -> minVtime);
            ordered.deferOrdered(t, vt);
        }
        long[] newMin = { Long.MAX_VALUE };
        ordered.drainEligible(0, Integer.MAX_VALUE, t -> {
            long vt = vtimes.getOrDefault(t.pid, minVtime);
            long weight = Math.max(1, t.weight);
            long step = SLICE_NS * 100 / weight;
            long nextVt = vt + step;
            vtimes.put(t.pid, nextVt);
            if (nextVt < newMin[0]) newMin[0] = nextVt;
            dispatchTask(t, ANY_CPU);
        });
        if (newMin[0] != Long.MAX_VALUE) minVtime = newMin[0];
    }
```

- [ ] **Step 4: Migrate `main` to `SchedulerRunner` (remove the `Cli` boilerplate)**

Replace the `Cli` inner class + `FemtoCli.run(...)` `main` with:

```java
    public static void main(String[] args) {
        me.bechberger.ebpf.bpf.userspace.SchedulerRunner.run(new VtimeSample(), args);
    }
```

Delete the now-unused `Cli` class and its femtocli imports. (If `VtimeSample` is `abstract` because of `@BPF`, keep the `@BPF`/abstract structure and construct via the framework loader instead of `new VtimeSample()` — check how the current `Cli` obtained its instance; the research showed `var sched = new VtimeSample();`, so a direct `new` matches.)

- [ ] **Step 5: Run the offline test — must pass after migration**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf-samples -am test -Dtest=VtimeSampleTest -q`
Expected: PASS — lowest-vtime-first order preserved through the DeferredQueue migration.

- [ ] **Step 6: Kernel smoke test (existing) still passes on thinkstation**

Run: `./scripts/ts.sh ./scripts/run-tests-vng.sh VtimeSample 2>&1 | tail -30`
(Or whatever the existing VtimeSample smoke test class is — find it: `./scripts/ts.sh --no-tty 'grep -rln "VtimeSample" bpf-samples/src/test'`.)
Expected: attaches and runs on thinkstation as before; migration didn't change kernel behavior.

- [ ] **Step 7: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/VtimeSample.java \
        bpf-samples/src/test/java/me/bechberger/ebpf/samples/sched/VtimeSampleTest.java
git commit -m "refactor(samples): migrate VtimeSample to DeferredQueue + SchedulerRunner, add offline test"
```

---

## Task 9: Full regression

**Files:** (none — verification)

- [ ] **Step 1: Run all C unit tests + the fake-scheduler regression**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=DeferredQueueTest,TaskClassifierTest,SchedulerHarnessTest,JfrEmissionTest,HistogramsTest -q`
Expected: BUILD SUCCESS, all PASS.

- [ ] **Step 2: Run the samples module tests**

Run: `./scripts/ts.sh ./mvnw -pl bpf-samples -am test -Dtest=VtimeSampleTest -q`
Expected: PASS.

---

## Self-review notes

- **Spec coverage:** DeferredQueue with deferUntil/deferOrdered/drainEligible/evictOlderThan/size (Tasks 1/2); TaskClassifier builder classify+policy+decide (Tasks 3/4); SchedulerHarness feed/runBatch/dispatches/tick built on existing seams (Tasks 5/6); SchedulerRunner one-line main (Task 7); VtimeSample migration + the proof-point offline test (Task 8). Backwards-compatible: production `submitDispatch` unchanged unless `offlineDispatchSink` is set.
- **Type consistency:** `SchedulerHarness.Dispatch(int targetCpu, int pid)` record used identically in harness impl, self-test, and VtimeSampleTest (`Dispatch::pid`). `DeferredQueue` method names (`deferOrdered`/`deferUntil`/`drainEligible`/`evictOlderThan`/`size`) identical across test, impl, and VtimeSample migration. `TaskClassifier.<C>builder().classify(...).policy(...).build()` + `decide`/`classOf` identical across test and impl.
- **Decision resolved in-plan:** harness lives in `bpf` `src/main` package `me.bechberger.ebpf.bpf.userspace` (not a separate testkit module) — matches `FakeSchedulerBase`'s package and lets `bpf-samples` tests import it.
- **Risk surfaced:** offline `pickIdleCpu` on a null idle-mask view — Task 6 Step 2 includes an explicit verification grep + fallback guard, rather than assuming it's null-safe.
- **Placeholder scan:** none — every step has full code or a concrete grep/build command with expected output.
