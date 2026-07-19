# Sub-project A — Extensible per-task metadata

**Status:** Draft
**Date:** 2026-07-19
**Author:** brainstormed with Johannes Bechberger
**Part of:** [userland scheduler improvements](2026-07-19-userland-scheduler-improvements-overview.md)

## Summary

Let a Java scheduler author attach **custom per-task fields** to the BPF→Java
message without editing framework internals. A scheduler declares a
`@TaskExtension` record (e.g. `record MyExt(long cgroupId, long ioBytes) {}`)
and a small BPF fill hook; the framework carries those fields in a fixed-size
tail appended to the wire record and surfaces them via a typed
`QueuedTask.ext()` accessor. The existing 88-byte prefix stays byte-for-byte
rustland-wire-compatible.

## Problem

`QueuedTaskCtx` (BPF, `UserspaceSchedulerBase`) and `QueuedTask` (Java) are a
fixed 88-byte struct. Adding one field means editing, in lockstep:

1. `QueuedTaskCtx` `@Type` fields (BPF side)
2. `QueuedTask` public fields
3. `QueuedTask` wire offset constants
4. `QueuedTask.fillFromSegment`
5. `QueuedTask` copy constructor
6. `QueuedTaskDispatchedTaskMarshallingTest`

Operators who want to route by cgroup, and researchers who want a BPF-computed
score (e.g. cache-miss rate from a PMU, futex-wait count), cannot express it
without forking the framework. `ShowcaseScheduler` works around this by reading
`/proc/<pid>/{cgroup,cmdline,io}` from Java — correct but slow and racy, and
impossible for values that only exist in kernel context.

## Goals

1. A scheduler declares extra per-task fields in **one place** (a record) plus a
   **one-method** BPF fill hook, and reads them type-safely in `policy`/`schedule`.
2. The stable prefix stays wire-compatible; `QueuedTaskDispatchedTaskMarshallingTest`
   still guards it unchanged.
3. Zero per-task allocation on the drain path — the extension is filled into the
   pooled flyweight, not a fresh object.
4. Schedulers that need no extension pay nothing (no larger record, no fill call).

## Non-goals

- Dynamic/reflective key-value bags (too slow, no type safety).
- Extending the *dispatch* (Java→BPF) record — that is Sub-project B's control
  channel. This sub-project is kernel→user only.
- Per-task fields that require sleepable BPF context (fill hook runs in
  `enqueue`, which is not sleepable).

## Design

### Wire layout

```
QueuedTaskCtx (BPF)                         QueuedTask (Java)
┌───────────────────────────┐  0
│ stable 88-byte prefix      │               fixed fields (pid, prevCpu, …)
│ (pid…comm) — UNCHANGED     │
├───────────────────────────┤  88
│ extension block            │               ext()  → typed record view
│ EXT_CAP bytes (e.g. 64)    │
└───────────────────────────┘  88 + EXT_CAP
```

`EXT_CAP` is a compile-time constant (proposed **64 bytes** = eight `long`s, or
one `long` + a `@Size(56)` byte scratch). It is fixed so the ring-buffer record
size is static and the marshalling test can assert the total. Schedulers that
declare no extension get `EXT_CAP = 0` (record stays exactly 88 bytes — full
back-compat).

### Author-facing API

```java
// 1. Declare the extension fields (Java record, mirrors a BPF @Type)
@TaskExtension
public record CgroupExt(long cgroupId, long ppid) {}

// 2. BPF fill hook — override in the scheduler's UserspaceSchedulerBase subclass.
//    Runs in enqueue() context on the BPF side; must be non-sleepable, bounded.
@Override
@BPFFunction
public void fillExtension(Ptr<task_struct> p, Ptr<CgroupExtCtx> e) {
    e.val().cgroupId = BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id);
    e.val().ppid     = p.val().real_parent.val().tgid;
}

// 3. Read it in policy — type-safe, zero-copy view over the flyweight tail
@Override
protected int policy(QueuedTask t) {
    CgroupExt ext = t.ext(CgroupExt.class);
    return isContainer(ext.cgroupId()) ? UPPER_PARTITION_CPU : ANY_CPU;
}
```

### How the pieces connect

- **`@TaskExtension`** (new annotation, `SOURCE` retention) marks the record.
  The compiler plugin generates a matching BPF `@Type` (`CgroupExtCtx`) with the
  same field layout, and the offset table for the Java view.
- **Framework wiring:** `UserspaceSchedulerBase` gains an overridable
  `fillExtension(Ptr<task_struct>, Ptr<ExtCtx>)` no-op default. When a subclass
  overrides it, the generated `enqueue` path calls it against the reserved tail
  region of the `QueuedTaskCtx` slot *before* ringbuf submit.
- **Java view:** `QueuedTask` gains `MemorySegment extSegment` (a slice of the
  drained record, no copy) and `<E> E ext(Class<E> type)` which lazily builds a
  cached record instance from the tail using generated offsets. On the hot path
  authors can instead use generated primitive accessors (`t.extLong(0)`) to
  avoid even the record allocation; the record form is the ergonomic default.
- **`QueuedTask.copy()`** copies the `EXT_CAP` tail bytes too, so deferred tasks
  (Sub-project C) keep their metadata.

### Files touched

```
annotations/               @TaskExtension                              (new, ~30)
bpf-processor/             generate ExtCtx @Type + offset table        (edit)
                           from @TaskExtension record
bpf/.../UserspaceSchedulerBase  fillExtension() hook, enlarge slot,    (edit)
                                call hook in enqueue path
bpf/.../QueuedTask         extSegment slice, ext(Class), extLong/ext…  (edit)
bpf/.../userspace/Opts     (no change)
bpf/.../QueuedTaskDispatchedTaskMarshallingTest  assert prefix stable, (edit)
                                                 assert EXT_CAP total
bpf/.../userspace/TaskExtensionTest              round-trip a record   (new)
bpf-samples/.../sched/CgroupAwareSample          demo                  (new, ~60)
```

## Testing

- **Marshalling:** extend `QueuedTaskDispatchedTaskMarshallingTest` to assert the
  88-byte prefix is unchanged and the total is `88 + EXT_CAP`. This is the
  wire-format contract guard.
- **Round-trip:** new `TaskExtensionTest` fills a tail segment with known bytes,
  reads back via `ext(CgroupExt.class)` and the primitive accessors, asserts
  equality. Pure Java — runs without a kernel.
- **Kernel end-to-end:** `CgroupAwareSample` smoke test on thinkstation —
  attach, run a cgroup-confined workload, assert the scheduler observed a
  non-zero `cgroupId` for it.
- **Back-compat:** an existing sample with no extension still produces an
  88-byte record (assert record size == 88).

## Open questions / decisions to lock in the plan

- **`EXT_CAP` size:** 64 bytes proposed. Larger = more headroom, bigger ring
  footprint. Decide in the plan; make it a single named constant either way.
- **CO-RE for the fill hook:** cgroup/task_struct reads should use
  `BPF_CORE_READ` (see repo memory on `preserve_access_index`). The generated
  fill-hook scaffolding should not force CO-RE; the author writes the reads.
- **Multiple extensions:** v1 supports **one** `@TaskExtension` per scheduler
  (simplest). If authors need composition later, the record can nest.

## Risks

- Enlarging `QueuedTaskCtx` changes the ring-buffer record size → must re-verify
  the 4 MiB ring still absorbs fork-storms (it does: 152 B/record × 27k still
  fits). Note in the plan.
- The fill hook runs in `enqueue` (non-sleepable, hot). A heavy hook regresses
  enqueue latency — document the constraint and keep the demo hook to a few
  field reads.
