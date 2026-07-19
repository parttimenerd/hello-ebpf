# Making userland scheduler development easy — overview

**Status:** Draft
**Date:** 2026-07-19
**Author:** brainstormed with Johannes Bechberger

## Summary

The `UserspaceScheduler` framework (see
[2026-06-29-userspace-scheduler-design.md](2026-06-29-userspace-scheduler-design.md))
proved that a `sched_ext` scheduler can run its policy in Java userspace. This
follow-up makes that framework *easy to build complex, production-grade
schedulers on* — for two audiences:

- **Researchers / students** prototyping novel algorithms (EDF, lottery,
  ML-driven, cache-aware) who want to write Java, not BPF C.
- **Production operators** tuning scheduling for a specific workload (JVM
  services, containers, databases) without learning the BPF verifier.

The work is decomposed into **four independent sub-projects**, each with its own
design doc, implementation plan, and ship cycle. They are ordered by dependency:
A is foundational, B is the biggest capability lever, C and D layer ergonomics
and observability on top.

| # | Sub-project | Spec | Risk | Depends on |
|---|-------------|------|------|-----------|
| A | Extensible per-task metadata | [design](2026-07-19-userland-a-task-metadata-design.md) | Medium (wire protocol) | — |
| B | Preemption, signals, multithreading | [design](2026-07-19-userland-b-preemption-signals-design.md) | High (new channels + threading) | A (light) |
| C | Ergonomics & offline testing | [design](2026-07-19-userland-c-ergonomics-testing-design.md) | Low (pure Java) | A (light) |
| D | Observability | [design](2026-07-19-userland-d-observability-design.md) | Low–Medium | A, C |

## The through-line

Today, a non-trivial Java scheduler author hits four walls in sequence:

1. **The wire message is fixed.** They can't route by cgroup or a BPF-computed
   score without patching five files in lockstep. → **Sub-project A**.
2. **They can only place a task at enqueue.** No "run pid X now", no reacting to
   a BPF-observed event (lock acquisition, RT preemption), and one drain thread
   caps throughput. → **Sub-project B**.
3. **They re-implement the same scaffolding** (cross-batch queues, multi-class
   routing, CLI, stats thread) and can't unit-test policy without root.
   → **Sub-project C**.
4. **They can't see what the scheduler decided** beyond counters and a stderr
   histogram dump. → **Sub-project D**.

Each sub-project removes one wall. Together they turn "write a scheduler" from a
multi-file BPF-and-Java exercise into "subclass `UserspaceScheduler`, override
one or two methods, run".

## Cross-cutting constraints

- **Wire compatibility:** the existing 88-byte `QueuedTaskCtx` prefix stays
  rustland-wire-compatible and byte-for-byte stable. All additions are appended
  or carried on new channels. `QueuedTaskDispatchedTaskMarshallingTest` remains
  the contract guard.
- **Zero-alloc hot path:** the drain/dispatch loop must not allocate per task.
  New features use pooled flyweights and pre-allocated segments, matching the
  existing `taskPool` / `drainCallback` pattern.
- **Opt-in complexity:** defaults stay simple. Multithreading, signals, the
  metrics endpoint, and decision tracing are all off unless the author asks.
- **Test seams:** every new hot-path method gets a `protected` seam (like the
  existing `drainRaw`/`submitDispatch`/`recordRoundTrip`) so it runs in the
  offline harness without a BPF fd.
- **Builds/tests run on thinkstation only** — see repo memory. Kernel-bound
  behaviour is verified there; pure-Java pieces (Sub-project C's harness) run
  anywhere.

## Non-goals (all sub-projects)

- Performance parity with `scx_rustland` (Rust). Java has higher tail latency;
  we accept it and measure it (Sub-project D).
- GraalVM native-image build.
- Replacing the BPF-only `SchedulerBase` tier — that remains for authors who
  want full in-kernel policy.
