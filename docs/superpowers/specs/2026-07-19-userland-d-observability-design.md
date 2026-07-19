# Sub-project D — Observability

**Status:** Draft
**Date:** 2026-07-19
**Author:** brainstormed with Johannes Bechberger
**Part of:** [userland scheduler improvements](2026-07-19-userland-scheduler-improvements-overview.md)

## Summary

Make a running scheduler observable without a JFR reader. Three pieces:

1. **Per-class metrics** — latency / wait-time / slice histograms keyed by task
   class (builds on Sub-project A's metadata and C's `TaskClassifier`).
2. **Decision trace** — an opt-in ring of the last N dispatch/preempt decisions
   with `(pid, cpu, reason)`, queryable live; cheap and off the JFR path.
3. **JFR-free consumption** — `stats().toJson()` / `toPrometheus()` snapshot
   strings plus an optional tiny embedded HTTP endpoint (`--metrics-port`)
   serving text/JSON. Reuses the existing `femtojson` dependency; no new heavy
   deps.

## Problem

Today observability is:

- 13 scalar counters in the mmap'd `SchedStats` arena.
- Five fixed histograms (batchSize, roundTrip, dispatchLat, queueDepth,
  ringConsume), printed to a `PrintStream` via `printHistograms`.
- JFR events (`BatchEvent`, `DispatchEvent`, `TickEvent`) — rich, but require a
  JFR recording + a reader to consume, and can't answer "why did pid X get
  CPU 3 just now?"

That is enough to know the scheduler is alive, not enough to *tune* it. An
operator wants "p99 wait time for the interactive class" and a dashboard feed; a
researcher wants "show me the last 100 decisions" while debugging a policy.

## Goals

1. Latency/wait/slice histograms **per task class**, not just global.
2. A live, bounded decision trace answering "what did the scheduler just do and
   why", without enabling JFR.
3. A single call yielding a JSON or Prometheus-text snapshot of all
   counters/histograms.
4. An optional HTTP endpoint an operator points a scraper/dashboard at.
5. All of it **opt-in and cheap** — zero cost when unused, bounded cost when on.

## Non-goals

- Replacing JFR — JFR stays for deep, sampled, low-overhead recording. This adds
  a *pull*/live path alongside it.
- A full metrics library (Micrometer etc.) — `femtojson` + a `HttpServer` from
  the JDK is the whole footprint.
- Distributed/remote aggregation.

## Design

### 1. Per-class metrics

- With Sub-project C's `TaskClassifier`, each dispatched task carries a class
  label. The framework records `roundTrip`/`dispatchLat`/`slice` into a histogram
  **array indexed by class ordinal** in addition to the global histogram.
- Exposed as `stats().perClass(C)` → a small record of `(count, p50, p99, …)`
  derived from the class's histogram buckets.
- If no classifier is set, only the global histograms exist (today's behaviour) —
  zero cost.

### 2. Decision trace

```java
Opts.decisionTrace(1024);   // ring capacity; 0 (default) = disabled

// framework records on every dispatchTask / preempt / kick:
//   TraceEntry { tsNs, pid, cpu, kind: DISPATCH|PREEMPT|KICK|DROP, reason }

scheduler.recentDecisions();     // returns a snapshot List<TraceEntry>
```

- Backed by a pre-allocated ring of flyweight `TraceEntry` structs — no per-decision
  allocation, matching the hot-path discipline.
- **`reason`** is a small enum/int the policy can stamp via an overload
  (`dispatchTask(t, cpu, reason)`); defaults to `UNSPECIFIED`. This is what makes
  the trace explain *why*.
- Wraps around at capacity; `recentDecisions()` copies out under a short lock (or
  a seqlock-style read) so it never blocks the run loop meaningfully.

### 3. JFR-free consumption

```java
String json = sched.stats().toJson();          // femtojson
String prom = sched.stats().toPrometheus();     // text exposition format
```

`SchedStatsSnapshot` (already exists) gains `toJson()`/`toPrometheus()` covering
counters + histogram buckets + per-class summaries.

Optional endpoint (via `SchedulerRunner` `--metrics-port N`, or
`Opts.metricsPort`):

```
GET /metrics        → Prometheus text
GET /stats.json     → JSON snapshot
GET /decisions.json → recent decision trace (if enabled)
```

Served by `com.sun.net.httpserver.HttpServer` (JDK built-in) on a daemon thread.
Bound to `127.0.0.1` by default (operator opt-in to widen). No auth in v1 —
document the localhost default and the risk of widening.

### Files touched

```
bpf/.../userspace/SchedStatsSnapshot   toJson()/toPrometheus(), per-class summary (edit)
bpf/.../userspace/DecisionTrace        ring of TraceEntry, recentDecisions()      (new, ~130)
bpf/.../userspace/UserspaceScheduler   record trace on dispatch/preempt/kick,     (edit)
                                       per-class histogram recording, reason overload
bpf/.../userspace/Opts                 decisionTrace(n), metricsPort              (edit)
bpf/.../userspace/MetricsServer        HttpServer wiring, 3 endpoints             (new, ~110)
bpf/.../userspace/SchedulerRunner      --metrics-port flag (from C)               (edit)
bpf/.../userspace/SchedStatsSnapshotTest   json/prom format assertions            (new)
bpf/.../userspace/DecisionTraceTest        ring wrap, snapshot, reason capture    (new)
bpf/.../userspace/MetricsServerTest        HTTP GET returns valid json/prom       (new)
bpf-samples/.../sched/ShowcaseScheduler    add per-class metrics + --metrics-port (edit)
```

## Testing

- `SchedStatsSnapshotTest`: assert `toJson()` parses and contains expected keys;
  `toPrometheus()` matches the exposition format (metric name, `# TYPE`, value).
  Pure Java.
- `DecisionTraceTest`: fill past capacity, assert wrap-around keeps the most
  recent N, assert `reason` round-trips, assert `recentDecisions()` is a
  consistent snapshot. Pure Java.
- `MetricsServerTest`: start the server on an ephemeral port, `GET /metrics` and
  `/stats.json`, assert 200 + valid body, assert bound to localhost. Pure Java.
- Per-class metrics: harness (Sub-project C) test feeding classified tasks,
  assert `perClass(Tier.INTERACTIVE).count` increments correctly.
- No kernel-specific tests; all consumption paths are Java-side over the mmap'd
  stats + in-heap trace.

## Risks

- **HTTP endpoint scope creep / security:** localhost-only default and no auth in
  v1 must be documented; widening the bind address is the operator's explicit
  choice. Keep the server tiny and optional.
- **Decision-trace overhead:** even flyweight recording costs a little per
  dispatch. It is opt-in (capacity 0 = off) and bounded; measure the on-cost in
  the plan and note it.
- **Per-class histogram memory:** one histogram set per class × per metric. With
  a handful of classes this is negligible; document the ceiling
  (classes × metrics × BUCKET_COUNT longs).
