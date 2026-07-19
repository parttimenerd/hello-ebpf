# Sub-project C — Ergonomics & offline testing

**Status:** Draft
**Date:** 2026-07-19
**Author:** brainstormed with Johannes Bechberger
**Part of:** [userland scheduler improvements](2026-07-19-userland-scheduler-improvements-overview.md)

## Summary

Remove the repetitive scaffolding every non-trivial Java scheduler re-invents,
and make policy logic unit-testable without root or a live kernel. Four pieces,
all **pure Java** (no BPF/wire changes):

1. **`DeferredQueue`** — a cross-batch task store: delay-until-time, sorted-by-key
   heap, auto-eviction. Replaces the hand-rolled `TreeMap`/`ArrayDeque` in
   `VtimeSample`/`ShowcaseScheduler`.
2. **`TaskClassifier<C>`** — map a `QueuedTask` → class enum → per-class policy,
   the multi-class routing pattern as a first-class helper.
3. **`SchedulerHarness`** — drive a `UserspaceScheduler` subclass with synthetic
   batches, capture dispatch/control decisions, assert. No BPF fd, no root.
4. **`SchedulerRunner`** — one call wires the CLI, periodic stats thread, and
   shutdown hook. Samples shrink to policy + a one-line `main`.

## Problem

- **Cross-batch state is hand-rolled.** `VtimeSample` builds a `TreeMap` keyed by
  a bit-packed `vtime<<20|pid` every batch; `ShowcaseScheduler` maintains its own
  per-pid `PidInfo` map with manual aging. Every sorted/deferred policy
  re-implements the same eviction and ordering logic.
- **Multi-class routing is copy-paste.** `PriorityScheduler` (BPF-side) and
  `ShowcaseScheduler` (Java-side) both hand-roll "classify task → route to
  band". No shared abstraction.
- **No offline tests.** Policy correctness can only be checked by attaching on
  thinkstation as root. A researcher iterating on an algorithm can't TDD it. The
  code *already* has the seams (`drainRaw`, `submitDispatch`, `idleMaskView`,
  `recordRoundTrip` are all `protected` and overridable) — they just aren't
  packaged into a harness.
- **~40 lines of boilerplate per sample.** Every `Cli` inner class repeats the
  shutdown hook + stats-interval thread + `runUntilExit`.

## Goals

1. A vtime/EDF/deferred policy expresses its cross-batch state in a few lines via
   `DeferredQueue`, with correct eviction handled for it.
2. A multi-class policy declares `class-of(task)` + `policy-per-class` and the
   framework routes.
3. A policy is unit-testable: feed batches, assert decisions, in plain JUnit,
   running on the mac.
4. A new sample's `main` is one line; no repeated shutdown/stats plumbing.
5. **Backwards compatible:** existing samples keep working unchanged; the helpers
   are additive.

## Design

### 1. `DeferredQueue`

```java
public final class DeferredQueue {
    /** Store a task to (re)consider at or after {@code notBeforeNs}. Copies the flyweight. */
    public void deferUntil(QueuedTask t, long notBeforeNs);
    /** Store keyed by an ordering value (vtime, deadline). Min-key drains first. */
    public void deferOrdered(QueuedTask t, long key);
    /** Drain all tasks now eligible (time reached) in key order, up to {@code max}. */
    public void drainEligible(long nowNs, int max, Consumer<QueuedTask> sink);
    /** Evict entries older than {@code horizonNs} to stay bounded. */
    public void evictOlderThan(long horizonNs);
    public int size();
}
```

Internally a min-heap keyed by `(key, pid)` plus a time index; stores
`QueuedTask.copy()` so it is safe across batches (and carries the Sub-project A
extension tail). This is exactly what `VtimeSample` and `DeadlineScheduler` need.

### 2. `TaskClassifier<C extends Enum<C>>`

```java
var classifier = TaskClassifier.<Tier>builder()
    .classify(t -> tierOf(t))                 // QueuedTask → Tier
    .policy(Tier.INTERACTIVE, t -> ANY_CPU)   // per-class placement
    .policy(Tier.BATCH,       t -> t.prevCpu >= 0 ? t.prevCpu : ANY_CPU)
    .build();

@Override protected int policy(QueuedTask t) { return classifier.decide(t); }
```

Optional per-class `DeferredQueue` so bands can be drained in priority order in
`schedule()`. This turns `ShowcaseScheduler`'s six-tier hand-roll into a table.

### 3. `SchedulerHarness`

```java
var sched = new MyScheduler();
var harness = SchedulerHarness.forScheduler(sched)
    .withCpus(8)
    .withIdleCpus(2, 3);                       // seed the idle bitmap view

harness.feed(task(pid=100, weight=200, prevCpu=1),
             task(pid=101, weight=100, prevCpu=-1));
harness.runBatch();

assertThat(harness.dispatches())              // captured (pid, cpu, slice, vtime)
    .extracting(d -> d.pid).containsExactly(100, 101);
assertThat(harness.preempts()).isEmpty();      // Sub-project B integration
harness.tick();                                // drive the periodic tick()
```

Built on the **existing** test seams: the harness supplies a `UserspaceScheduler`
subclass wiring that overrides `drainRaw` (feeds synthetic tasks), `submitDispatch`
(captures), `submitControl` (captures preempt/kick from B), and `idleMaskView`
(heap segment). No new production code beyond exposing what's already `protected`.
This is the single highest-leverage piece for researchers.

### 4. `SchedulerRunner`

```java
public static void main(String[] args) {
    SchedulerRunner.run(new VtimeSample(), args);   // one line
}
```

`run` handles: `--stats-interval`, `--metrics-port` (Sub-project D), the stats
thread, the shutdown hook that prints final stats + histograms, and
`runUntilExit`. Femtocli-based, matching the existing sample `Cli` pattern.
Existing samples can migrate incrementally; not forced.

### Files touched

```
bpf/.../userspace/DeferredQueue        (new, ~120)
bpf/.../userspace/TaskClassifier       (new, ~120)
bpf/.../userspace/SchedulerHarness     (new, ~180) — test-support, main scope so
                                        samples' tests can use it too
bpf/.../userspace/SchedulerRunner      (new, ~90)
bpf/.../userspace/UserspaceScheduler   expose submitControl seam if not already (edit)
bpf/.../userspace/DeferredQueueTest    (new)
bpf/.../userspace/TaskClassifierTest   (new)
bpf/.../userspace/SchedulerHarnessTest (new) — self-test of the harness
bpf-samples/.../sched/VtimeSample      migrate to DeferredQueue + Runner (edit, shrinks)
bpf-samples/.../sched/VtimeSampleTest  offline policy test via harness    (new)
```

## Testing

- `DeferredQueueTest`, `TaskClassifierTest`: pure-Java unit tests of ordering,
  eviction, classification. Run on the mac.
- `SchedulerHarnessTest`: self-test — a trivial scheduler produces predictable
  dispatches; assert capture works, tick fires, preempt capture works.
- `VtimeSampleTest`: **the proof point** — the vtime policy's ordering is asserted
  offline (lowest-vtime dispatched first) with zero kernel involvement. This is
  the pattern researchers copy.
- No kernel tests needed for this sub-project; it is pure Java. (The migrated
  `VtimeSample` still gets its existing thinkstation smoke test.)

## Risks

- **Harness fidelity:** the offline harness models the drain/dispatch seams but
  not real kernel timing/preemption. Document clearly that it tests *policy
  decisions*, not kernel behaviour — it complements, not replaces, the
  thinkstation smoke tests.
- **`SchedulerHarness` in main scope:** placing test-support in `src/main` (so
  downstream users' tests can use it) is intentional but adds a small
  non-test surface to the published jar. Alternative: a dedicated
  `scheduler-testkit` module. Decide in the plan; leaning main-scope for
  simplicity, matching how `TestUtil` is handled today.
