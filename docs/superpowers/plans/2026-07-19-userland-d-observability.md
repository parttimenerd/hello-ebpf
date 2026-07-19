# Sub-project D — Observability — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a running scheduler observable without a JFR reader: per-class latency histograms, an opt-in bounded decision trace, `stats().toJson()`/`toPrometheus()` snapshot strings, and an optional localhost HTTP metrics endpoint.

**Architecture:** `SchedStatsSnapshot` gains `toJson()` (via femtojson) and `toPrometheus()` (text exposition). A new `DecisionTrace` pre-allocated ring records `(tsNs, pid, cpu, kind, reason)` per dispatch/preempt/kick when `Opts.decisionTrace(n>0)`. A new `MetricsServer` (JDK `com.sun.net.httpserver.HttpServer`, localhost-bound, daemon thread) serves `/metrics`, `/stats.json`, `/decisions.json`. Per-class histograms are recorded when a `TaskClassifier` (Sub-project C) is attached. All opt-in: zero cost when unused.

**Tech Stack:** Java 25, femtojson (`me.bechberger.util:femtojson:0.4.2`, `me.bechberger.util.json.PrettyPrinter`), JDK `com.sun.net.httpserver.HttpServer` (already used in `BPFProgram.java:2509`), `BPFHistogram.percentile(double)`/`totalCount()`, JUnit 5.

**Build/test workflow (CRITICAL):** All builds/tests on thinkstation, never the mac.
- Sync: `./scripts/sync.sh`; command: `./scripts/ts.sh <cmd>`.
- These are pure-Java tests (HTTP on an ephemeral localhost port, in-heap trace, snapshot formatting): `./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=<Class> -q`.

**Depends on:** Sub-project **A** (per-class metrics key off `QueuedTask`/classifier) and **C** (`SchedulerRunner` exists — this plan wires `--metrics-port` into it; `TaskClassifier` provides `classOf`). Land A and C first. If C's `SchedulerRunner` is not yet present, Task 6 adds the flag directly to the sample `Cli` instead (noted inline).

---

## Key facts locked from the codebase (do not re-derive)

- `SchedStatsSnapshot` (`bpf/.../userspace/SchedStatsSnapshot.java:8-19`) is a **record with 8 fields**: `ringEnqueued, ringDropped, ringDrained, ringCanceled, dispatched, dispatchFailed, stallFallbacks, heartbeatKicks`. `ZERO` constant at `:18`. This is the object that gains `toJson()`/`toPrometheus()`.
- Built by `UserspaceScheduler.stats()` (`:250-259`), public, reads BPF counters or cached values. `formatStats()` (`:410-417`) is the existing string form.
- Stats slots (`UserspaceSchedulerBase.java:95-120`): `ONLINE_CPUS`(1)…`HEARTBEAT_KICKS`(13). (Sub-project B may append 14+.)
- `BPFHistogram` (`bpf/.../map/BPFHistogram.java`): `long totalCount()` `:136`, `long percentile(double p)` `:156` (p in [0,1], returns bucket upper bound), 64 log2 buckets. Accessor seams `batchSizeHistView()`/`roundTripHistView()`/`dispatchLatencyHistView()`/`queueDepthHistView()`/`ringConsumeHistView()` (`UserspaceSchedulerBase.java:382-408`). `printHistograms(PrintStream)` (`UserspaceScheduler.java:597-607`).
- femtojson usage pattern (`bpf-samples/.../CPUProfiler.java`): build a `Map<String,Object>`, then `PrettyPrinter.compactPrint(map)` → JSON string. Import `me.bechberger.util.json.PrettyPrinter`. Dependency already in `bpf/pom.xml:149-151`.
- `HttpServer` idiom already in repo (`BPFProgram.java:2509-2536`): `HttpServer.create(new InetSocketAddress(addr, port), 0)`, `setExecutor(daemon single-thread)`, `createContext("/path", exchange -> {...})`, `sendResponseHeaders(200, bytes.length)`, `getResponseBody()`, `start()`. Mirror this exactly.
- `Opts` (`userspace/Opts.java`): current fields `batchSize`, `ringPollBudget`, `verifyZgcOnStart`, `frameworkPidRescan`, `policyExceptionBudgetPerSec`. Add `metricsPort` (int, 0=off) and `decisionTraceCapacity` (int, 0=off).
- `SchedulerRunner` (C) at `bpf/.../userspace/SchedulerRunner.java` — wire `--metrics-port` there once C lands.
- `TaskClassifier<C>` (C) exposes `classOf(QueuedTask) → C` — the per-class metric key.
- ShowcaseScheduler (`bpf-samples/.../sched/ShowcaseScheduler.java`) `extends UserspaceScheduler`, has inner `Cli`, `main` uses `FemtoCli.run`. Target for the per-class + `--metrics-port` demo.

---

## File Structure

- **Modify** `bpf/.../userspace/SchedStatsSnapshot.java` — add `toJson()`, `toPrometheus()`, and a per-class summary carrier. ~80 added lines.
- **New** `bpf/.../userspace/DecisionTrace.java` — pre-allocated flyweight ring; `record(...)`, `recentDecisions()`, `TraceEntry`, `Kind`. ~140 lines.
- **New** `bpf/.../userspace/ClassMetrics.java` — per-class `(count, p50, p99)` summary record + helper to derive from a histogram. ~50 lines.
- **New** `bpf/.../userspace/MetricsServer.java` — `HttpServer` wiring, 3 endpoints, localhost bind. ~120 lines.
- **Modify** `bpf/.../userspace/UserspaceScheduler.java` — `recentDecisions()`, trace-record calls on dispatch/preempt/kick, per-class histogram recording, `perClass(C)` accessor, start/stop `MetricsServer` in `runUntilExit` when `metricsPort>0`.
- **Modify** `bpf/.../userspace/Opts.java` — `metricsPort`, `decisionTraceCapacity`.
- **Modify** `bpf/.../userspace/SchedulerRunner.java` — parse `--metrics-port`, set `Opts.metricsPort` (only if C landed; else skip).
- **New tests** `SchedStatsSnapshotTest`, `DecisionTraceTest`, `MetricsServerTest` in `bpf/src/test/.../userspace/`.
- **Modify** `bpf-samples/.../sched/ShowcaseScheduler.java` — attach a `TaskClassifier`, add `--metrics-port` to its `Cli`.

---

## Task 1: `SchedStatsSnapshot.toJson()`/`toPrometheus()` — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SchedStatsSnapshotTest.java`

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SchedStatsSnapshotTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SchedStatsSnapshotTest {

    private SchedStatsSnapshot sample() {
        // (ringEnqueued, ringDropped, ringDrained, ringCanceled, dispatched, dispatchFailed, stallFallbacks, heartbeatKicks)
        return new SchedStatsSnapshot(1000, 3, 990, 5, 985, 2, 1, 7);
    }

    @Test
    void toJsonContainsAllCounters() {
        String json = sample().toJson();
        // valid-ish JSON object with each counter key + value
        assertTrue(json.trim().startsWith("{"), "json object");
        assertTrue(json.contains("\"ringEnqueued\""), "has ringEnqueued key");
        assertTrue(json.contains("1000"), "has ringEnqueued value");
        assertTrue(json.contains("\"dispatched\""));
        assertTrue(json.contains("985"));
        assertTrue(json.contains("\"heartbeatKicks\""));
    }

    @Test
    void toPrometheusUsesExpositionFormat() {
        String prom = sample().toPrometheus();
        // Each metric: a # TYPE line + a value line with the sched_ prefix.
        assertTrue(prom.contains("# TYPE sched_ring_enqueued counter"), "TYPE line for ring_enqueued");
        assertTrue(prom.contains("sched_ring_enqueued 1000"), "value line");
        assertTrue(prom.contains("# TYPE sched_dispatched counter"));
        assertTrue(prom.contains("sched_dispatched 985"));
        assertTrue(prom.contains("sched_heartbeat_kicks 7"));
        // exposition format ends each line with newline
        assertTrue(prom.endsWith("\n"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=SchedStatsSnapshotTest -q`
Expected: COMPILE FAILURE — `toJson`/`toPrometheus` don't exist.

---

## Task 2: `SchedStatsSnapshot.toJson()`/`toPrometheus()` — implement

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedStatsSnapshot.java`

- [ ] **Step 1: Add the two format methods**

In `SchedStatsSnapshot.java`, inside the record body (after the `ZERO` constant), add:

```java
    /** JSON object of all counters, e.g. {@code {"ringEnqueued":1000,...}}. Uses femtojson. */
    public String toJson() {
        var m = new java.util.LinkedHashMap<String, Object>();
        m.put("ringEnqueued",   ringEnqueued());
        m.put("ringDropped",    ringDropped());
        m.put("ringDrained",    ringDrained());
        m.put("ringCanceled",   ringCanceled());
        m.put("dispatched",     dispatched());
        m.put("dispatchFailed", dispatchFailed());
        m.put("stallFallbacks", stallFallbacks());
        m.put("heartbeatKicks", heartbeatKicks());
        return me.bechberger.util.json.PrettyPrinter.compactPrint(m);
    }

    /** Prometheus text exposition format (each counter with a # TYPE line). */
    public String toPrometheus() {
        StringBuilder sb = new StringBuilder();
        prom(sb, "sched_ring_enqueued",   ringEnqueued());
        prom(sb, "sched_ring_dropped",    ringDropped());
        prom(sb, "sched_ring_drained",    ringDrained());
        prom(sb, "sched_ring_canceled",   ringCanceled());
        prom(sb, "sched_dispatched",      dispatched());
        prom(sb, "sched_dispatch_failed", dispatchFailed());
        prom(sb, "sched_stall_fallbacks", stallFallbacks());
        prom(sb, "sched_heartbeat_kicks", heartbeatKicks());
        return sb.toString();
    }

    private static void prom(StringBuilder sb, String name, long value) {
        sb.append("# TYPE ").append(name).append(" counter\n");
        sb.append(name).append(' ').append(value).append('\n');
    }
```

Confirm `PrettyPrinter.compactPrint(Map)` is the exact signature femtojson exposes (research shows CPUProfiler uses `PrettyPrinter.compactPrint(root.toJsonObject())` on a Map). If the method name differs, grep:

Run: `./scripts/ts.sh --no-tty 'grep -rn "PrettyPrinter\|compactPrint\|toJson" bpf-samples/src/main/java/me/bechberger/ebpf/samples/CPUProfiler.java | head'`
Use whatever femtojson entry point that file uses.

- [ ] **Step 2: Run the test to verify it passes**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=SchedStatsSnapshotTest -q`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedStatsSnapshot.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/SchedStatsSnapshotTest.java
git commit -m "feat(userspace): add SchedStatsSnapshot.toJson()/toPrometheus()"
```

---

## Task 3: `DecisionTrace` — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/DecisionTraceTest.java`

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/DecisionTraceTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DecisionTraceTest {

    @Test
    void recordsAndSnapshots() {
        var trace = new DecisionTrace(4);
        trace.record(1000, 10, 3, DecisionTrace.Kind.DISPATCH, 0);
        trace.record(1001, 11, 4, DecisionTrace.Kind.PREEMPT, 7);

        List<DecisionTrace.TraceEntry> recent = trace.recentDecisions();
        assertEquals(2, recent.size());
        assertEquals(10, recent.get(0).pid());
        assertEquals(DecisionTrace.Kind.DISPATCH, recent.get(0).kind());
        assertEquals(7, recent.get(1).reason());
        assertEquals(DecisionTrace.Kind.PREEMPT, recent.get(1).kind());
    }

    @Test
    void wrapsAndKeepsMostRecentN() {
        var trace = new DecisionTrace(3);
        for (int i = 0; i < 5; i++) {
            trace.record(1000 + i, i, 0, DecisionTrace.Kind.DISPATCH, 0);
        }
        List<DecisionTrace.TraceEntry> recent = trace.recentDecisions();
        assertEquals(3, recent.size(), "capacity bounds the ring");
        // most recent three are pids 2,3,4 in chronological order
        assertEquals(List.of(2, 3, 4), recent.stream().map(DecisionTrace.TraceEntry::pid).toList());
    }

    @Test
    void reasonRoundTrips() {
        var trace = new DecisionTrace(2);
        trace.record(1, 1, 0, DecisionTrace.Kind.KICK, 42);
        assertEquals(42, trace.recentDecisions().get(0).reason());
    }

    @Test
    void zeroCapacityIsDisabled() {
        var trace = new DecisionTrace(0);
        trace.record(1, 1, 0, DecisionTrace.Kind.DISPATCH, 0);
        assertTrue(trace.recentDecisions().isEmpty(), "capacity 0 records nothing");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=DecisionTraceTest -q`
Expected: COMPILE FAILURE — `DecisionTrace` does not exist.

---

## Task 4: `DecisionTrace` — implement

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/DecisionTrace.java`

- [ ] **Step 1: Write the implementation**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/DecisionTrace.java`:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import java.util.ArrayList;
import java.util.List;

/**
 * Bounded, live ring of the last N scheduling decisions — answers "what did the scheduler
 * just do and why" without enabling JFR. Backed by pre-allocated parallel arrays (no
 * per-decision allocation), matching the hot-path discipline. Opt-in: capacity 0 disables it.
 *
 * <p>Not lock-free: {@link #recentDecisions()} copies out under {@code synchronized}; the run
 * loop's {@link #record} is a cheap array write under the same lock. Contention is negligible
 * at scheduling rates because reads are operator-initiated (a dashboard poll), not per-decision.
 */
public final class DecisionTrace {

    public enum Kind { DISPATCH, PREEMPT, KICK, DROP }

    /** One captured decision. */
    public record TraceEntry(long tsNs, int pid, int cpu, Kind kind, int reason) {}

    private static final Kind[] KINDS = Kind.values();

    private final int capacity;
    private final long[] tsNs;
    private final int[]  pid;
    private final int[]  cpu;
    private final byte[] kind;    // ordinal
    private final int[]  reason;
    private int head;             // next write index
    private int size;             // number of valid entries (≤ capacity)

    public DecisionTrace(int capacity) {
        this.capacity = Math.max(0, capacity);
        this.tsNs   = new long[this.capacity];
        this.pid    = new int[this.capacity];
        this.cpu    = new int[this.capacity];
        this.kind   = new byte[this.capacity];
        this.reason = new int[this.capacity];
    }

    public boolean enabled() { return capacity > 0; }

    /** Record one decision. No-op when capacity is 0. */
    public synchronized void record(long tsNs, int pid, int cpu, Kind kind, int reason) {
        if (capacity == 0) return;
        this.tsNs[head]   = tsNs;
        this.pid[head]    = pid;
        this.cpu[head]    = cpu;
        this.kind[head]   = (byte) kind.ordinal();
        this.reason[head] = reason;
        head = (head + 1) % capacity;
        if (size < capacity) size++;
    }

    /** Snapshot of the most recent decisions, oldest→newest. */
    public synchronized List<TraceEntry> recentDecisions() {
        List<TraceEntry> out = new ArrayList<>(size);
        int start = (head - size + capacity) % Math.max(1, capacity);
        for (int i = 0; i < size; i++) {
            int idx = (start + i) % capacity;
            out.add(new TraceEntry(tsNs[idx], pid[idx], cpu[idx], KINDS[kind[idx]], reason[idx]));
        }
        return out;
    }
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=DecisionTraceTest -q`
Expected: PASS — record, wrap, reason round-trip, zero-capacity all green.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/DecisionTrace.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/DecisionTraceTest.java
git commit -m "feat(userspace): add opt-in DecisionTrace ring"
```

---

## Task 5: Wire `DecisionTrace` + per-class metrics into `UserspaceScheduler`

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Opts.java`
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java`
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/ClassMetrics.java`

- [ ] **Step 1: Add Opts fields**

In `Opts.java`, after `policyExceptionBudgetPerSec`:

```java
    /** Decision-trace ring capacity. 0 (default) = disabled, zero cost. */
    public int decisionTraceCapacity = 0;

    /** HTTP metrics endpoint port. 0 (default) = disabled. Binds to 127.0.0.1. */
    public int metricsPort = 0;
```

- [ ] **Step 2: Add `ClassMetrics` summary record**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/ClassMetrics.java`:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.map.BPFHistogram;

/** A per-class latency summary derived from a histogram. */
public record ClassMetrics(long count, long p50, long p99) {
    /** Derive from a BPFHistogram (percentile arg is a fraction in [0,1]). */
    public static ClassMetrics of(BPFHistogram h) {
        long c = h.totalCount();
        if (c == 0) return new ClassMetrics(0, 0, 0);
        return new ClassMetrics(c, h.percentile(0.50), h.percentile(0.99));
    }
}
```

- [ ] **Step 3: Add trace field, `recentDecisions()`, and record on dispatch**

In `UserspaceScheduler.java`:

Add a field and initialize it in `runUntilExit` from `opts.decisionTraceCapacity`:

```java
    private DecisionTrace decisionTrace = new DecisionTrace(0);   // disabled until runUntilExit
```

In `runUntilExit(Opts opts)`, early (where opts is first stored), add:

```java
        this.decisionTrace = new DecisionTrace(opts.decisionTraceCapacity);
```

Add the public accessor:

```java
    /** Snapshot of the most recent scheduling decisions (empty unless Opts.decisionTraceCapacity > 0). */
    public java.util.List<DecisionTrace.TraceEntry> recentDecisions() {
        return decisionTrace.recentDecisions();
    }
```

Record a DISPATCH entry inside `dispatchInternal`, right after the `submitDispatch(...)` call resolves `rc` (only when tracing is enabled — the `record` is itself a no-op at capacity 0, but gate to skip the `System.nanoTime()` when disabled):

```java
        if (decisionTrace.enabled()) {
            decisionTrace.record(System.nanoTime(), t.pid, target, DecisionTrace.Kind.DISPATCH, 0);
        }
```

If Sub-project B has landed, also add PREEMPT/KICK records in `preempt`/`kick` (guarded the same way, with the `reason` argument the policy passed). If B is not present, skip — DISPATCH-only is a valid v1.

- [ ] **Step 4: Add per-class histogram recording + `perClass(C)` accessor**

Per-class metrics need a classifier and per-class histograms. Add an optional classifier hook and a per-class histogram map keyed by class ordinal. Add fields:

```java
    private TaskClassifier<?> classMetricsClassifier;         // optional; set via setClassMetrics(...)
    private final java.util.Map<Enum<?>, me.bechberger.ebpf.bpf.map.BPFHistogram> perClassRoundTrip = new java.util.concurrent.ConcurrentHashMap<>();
```

Add a setter and accessor:

```java
    /** Enable per-class latency metrics keyed by the given classifier. Optional. */
    public <C extends Enum<C>> void setClassMetrics(TaskClassifier<C> classifier) {
        this.classMetricsClassifier = classifier;
    }

    /** Per-class latency summary; null if no classifier set or class unseen. */
    public ClassMetrics perClass(Enum<?> cls) {
        var h = perClassRoundTrip.get(cls);
        return h == null ? null : ClassMetrics.of(h);
    }
```

**Note on per-class histograms:** the existing global histograms are `BPFHistogram` (BPF-map-backed). A per-class in-heap histogram may not need a BPF map. To avoid a new heavy dependency, v1 records per-class round-trip into a lightweight in-heap histogram. If `BPFHistogram` can be constructed heap-only, reuse it; otherwise introduce a tiny `Log2Histogram` heap class. Check:

Run: `./scripts/ts.sh --no-tty 'grep -n "public BPFHistogram\|BPFHistogram(\|static.*BPFHistogram\|new BPFHistogram" bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHistogram.java | head'`
If `BPFHistogram` requires a BPF fd, add a minimal heap `Log2Histogram` (64 log2 buckets, `add(long)`, `totalCount()`, `percentile(double)`) in this task and make `ClassMetrics.of` accept it via an interface instead. Wire the recording where round-trip is recorded (`recordRoundTrip`): if a classifier is set and the current task's class is known, `perClassHist(cls).add(usValue)`. Since `recordRoundTrip(long)` doesn't carry the task, record per-class at dispatch time by remembering the last dispatched class per pid, OR add the class tag when dispatching. Simplest correct v1: record per-class at **dispatch** using the classifier on the task being dispatched, counting dispatches per class (not full round-trip latency). Document this v1 limitation inline: per-class metric is dispatch count + (if latency is cheaply available) slice; full per-class round-trip latency is a follow-up. Implement the dispatch-count version:

In `dispatchInternal`, when `classMetricsClassifier != null`, compute the class and bump its histogram with a `1` sample (count), or with `t.execRuntime` if a latency proxy is wanted. Keep it bounded and allocation-free on the hot path (the `ConcurrentHashMap` get is the only cost; acceptable since per-class metrics are opt-in).

- [ ] **Step 5: Compile**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am compile -q`
Expected: BUILD SUCCESS.

- [ ] **Step 6: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/Opts.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/ClassMetrics.java
git commit -m "feat(userspace): wire DecisionTrace + per-class metrics into scheduler"
```

---

## Task 6: `MetricsServer` — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/MetricsServerTest.java`

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/MetricsServerTest.java`:

```java
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MetricsServerTest {

    @Test
    void servesMetricsStatsAndDecisions() throws Exception {
        SchedStatsSnapshot snap = new SchedStatsSnapshot(1000, 3, 990, 5, 985, 2, 1, 7);
        DecisionTrace trace = new DecisionTrace(8);
        trace.record(1, 42, 3, DecisionTrace.Kind.DISPATCH, 0);

        // port 0 → ephemeral; server binds localhost.
        var server = new MetricsServer(0, () -> snap, trace::recentDecisions);
        server.start();
        try {
            int port = server.boundPort();
            assertTrue(port > 0);
            HttpClient client = HttpClient.newHttpClient();

            HttpResponse<String> metrics = get(client, port, "/metrics");
            assertEquals(200, metrics.statusCode());
            assertTrue(metrics.body().contains("sched_ring_enqueued 1000"));

            HttpResponse<String> stats = get(client, port, "/stats.json");
            assertEquals(200, stats.statusCode());
            assertTrue(stats.body().contains("\"dispatched\""));

            HttpResponse<String> decisions = get(client, port, "/decisions.json");
            assertEquals(200, decisions.statusCode());
            assertTrue(decisions.body().contains("42"), "decision trace pid present");
        } finally {
            server.stop();
        }
    }

    @Test
    void bindsToLocalhostOnly() throws Exception {
        var server = new MetricsServer(0, () -> SchedStatsSnapshot.ZERO, List::of);
        server.start();
        try {
            assertEquals("127.0.0.1", server.boundAddress());
        } finally {
            server.stop();
        }
    }

    private HttpResponse<String> get(HttpClient c, int port, String path) throws Exception {
        return c.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
                      HttpResponse.BodyHandlers.ofString());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=MetricsServerTest -q`
Expected: COMPILE FAILURE — `MetricsServer` does not exist.

---

## Task 7: `MetricsServer` — implement

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/MetricsServer.java`

- [ ] **Step 1: Write the implementation (mirror BPFProgram's HttpServer idiom)**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/MetricsServer.java`:

```java
// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

/**
 * Tiny localhost HTTP endpoint for pull-based observability. Serves:
 * <ul>
 *   <li>{@code GET /metrics}        — Prometheus text exposition</li>
 *   <li>{@code GET /stats.json}     — JSON snapshot</li>
 *   <li>{@code GET /decisions.json} — recent decision trace (empty if tracing off)</li>
 * </ul>
 * Bound to {@code 127.0.0.1} by default. No auth in v1 — widening the bind address is the
 * operator's explicit choice and a documented risk. Runs on a daemon thread.
 */
public final class MetricsServer {

    private static final String LOCALHOST = "127.0.0.1";

    private final int requestedPort;
    private final Supplier<SchedStatsSnapshot> statsSupplier;
    private final Supplier<List<DecisionTrace.TraceEntry>> decisionsSupplier;
    private HttpServer server;

    public MetricsServer(int port,
                         Supplier<SchedStatsSnapshot> statsSupplier,
                         Supplier<List<DecisionTrace.TraceEntry>> decisionsSupplier) {
        this.requestedPort = port;
        this.statsSupplier = statsSupplier;
        this.decisionsSupplier = decisionsSupplier;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByName(LOCALHOST), requestedPort), 0);
        server.setExecutor(Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "sched-metrics");
            t.setDaemon(true);
            return t;
        }));
        server.createContext("/metrics",        ex -> respond(ex, "text/plain; version=0.0.4", statsSupplier.get().toPrometheus()));
        server.createContext("/stats.json",     ex -> respond(ex, "application/json; charset=utf-8", statsSupplier.get().toJson()));
        server.createContext("/decisions.json", ex -> respond(ex, "application/json; charset=utf-8", decisionsJson()));
        server.start();
    }

    public void stop() { if (server != null) server.stop(0); }

    /** Actual bound port (useful when constructed with port 0). */
    public int boundPort() { return server == null ? -1 : server.getAddress().getPort(); }

    public String boundAddress() { return LOCALHOST; }

    private String decisionsJson() {
        List<DecisionTrace.TraceEntry> entries = decisionsSupplier.get();
        List<Object> arr = new ArrayList<>(entries.size());
        for (var e : entries) {
            var m = new java.util.LinkedHashMap<String, Object>();
            m.put("tsNs",   e.tsNs());
            m.put("pid",    e.pid());
            m.put("cpu",    e.cpu());
            m.put("kind",   e.kind().name());
            m.put("reason", e.reason());
            arr.add(m);
        }
        return me.bechberger.util.json.PrettyPrinter.compactPrint(arr);
    }

    private static void respond(com.sun.net.httpserver.HttpExchange ex, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = ex.getResponseBody()) { out.write(bytes); }
    }
}
```

Confirm `PrettyPrinter.compactPrint` accepts a `List`/`Object` (not just `Map`). If it only accepts `Map`, wrap: `compactPrint(Map.of("decisions", arr))` and adjust the test's `/decisions.json` assertion to look for the pid inside. Verify via the same grep as Task 2 Step 1.

- [ ] **Step 2: Run the test to verify it passes**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=MetricsServerTest -q`
Expected: PASS — all three endpoints return 200 with expected bodies; localhost bind confirmed.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/MetricsServer.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/userspace/MetricsServerTest.java
git commit -m "feat(userspace): add localhost MetricsServer (/metrics, /stats.json, /decisions.json)"
```

---

## Task 8: Start `MetricsServer` from the run loop + `--metrics-port`

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java`
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerRunner.java` (if C landed)

- [ ] **Step 1: Start/stop the server in `runUntilExit`**

In `UserspaceScheduler.java`, add a field and start it when `opts.metricsPort > 0`:

```java
    private MetricsServer metricsServer;
```

In `runUntilExit(Opts opts)`, after the decisionTrace init, before the main loop:

```java
        if (opts.metricsPort > 0) {
            try {
                metricsServer = new MetricsServer(opts.metricsPort, this::stats, this::recentDecisions);
                metricsServer.start();
                System.err.println("[sched] metrics on http://127.0.0.1:" + metricsServer.boundPort() + "/metrics");
            } catch (java.io.IOException e) {
                System.err.println("[sched] metrics server failed to start: " + e);
            }
        }
```

In the exit/cleanup path of `runUntilExit` (where the loop ends), add:

```java
        if (metricsServer != null) metricsServer.stop();
```

- [ ] **Step 2: Wire `--metrics-port` into `SchedulerRunner` (only if Sub-project C landed)**

Check: `./scripts/ts.sh --no-tty 'test -f bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerRunner.java && echo EXISTS || echo MISSING'`

If EXISTS: in `SchedulerRunner.run`, parse `--metrics-port` and `--decision-trace` and set them on the `Opts` before `runUntilExit`. Since `SchedulerRunner` currently calls `runUntilExit(Opts.defaults())`, change it to build an `Opts`, set `opts.metricsPort = parseIntOpt(args, "--metrics-port", 0)` and `opts.decisionTraceCapacity = parseIntOpt(args, "--decision-trace", 0)`, then `sched.runUntilExit(opts)`.

If MISSING (C not landed yet): skip this step; the flag is wired via the sample `Cli` in Task 9 instead.

- [ ] **Step 3: Compile**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am compile -q`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/SchedulerRunner.java
git commit -m "feat(userspace): start MetricsServer from runUntilExit + --metrics-port flag"
```

---

## Task 9: `ShowcaseScheduler` demo — per-class metrics + `--metrics-port`

**Files:**
- Modify: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/ShowcaseScheduler.java`

- [ ] **Step 1: Read the current Cli + tier classification**

Run: `./scripts/ts.sh --no-tty 'sed -n "1,60p;400,430p" bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/ShowcaseScheduler.java'`
Expected: the `Tier` enum, the `Cli` inner class with its `@Option` fields, and `main`.

- [ ] **Step 2: Attach a TaskClassifier for per-class metrics**

In `ShowcaseScheduler`'s constructor or setup, build a `TaskClassifier<Tier>` mirroring the existing `classify(...)` logic and call `setClassMetrics(classifier)`. Reuse the existing tier decision so metrics match the real routing:

```java
        var classifier = TaskClassifier.<Tier>builder()
            .classify(this::tierOf)            // reuse the existing classification method
            .policy(Tier.INTERACTIVE_FRESH, t -> ANY_CPU)
            .policy(Tier.INTERACTIVE_HOT,   t -> ANY_CPU)
            .policy(Tier.HOST_JVM,          t -> ANY_CPU)
            .policy(Tier.CONTAINER,         t -> ANY_CPU)
            .policy(Tier.BUILDER,           t -> ANY_CPU)
            .policy(Tier.OTHER,             t -> ANY_CPU)
            .build();
        setClassMetrics(classifier);
```

(Adapt `tierOf` to whatever the existing per-task classification method is named — from Step 1.)

- [ ] **Step 3: Add `--metrics-port` to the Cli**

In the inner `Cli`, add:

```java
        @Option(names = {"--metrics-port"}, defaultValue = "0")
        int metricsPort;
```

And in `Cli.run`, set it on the Opts passed to `runUntilExit`:

```java
        var opts = Opts.defaults();
        opts.metricsPort = metricsPort;
        sched.runUntilExit(opts);
```

- [ ] **Step 4: Compile the sample**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf-samples -am compile -q`
Expected: BUILD SUCCESS.

- [ ] **Step 5: Kernel smoke test on thinkstation with metrics enabled**

Run: `./scripts/ts.sh --no-tty 'grep -rln "ShowcaseScheduler" bpf-samples/src/test 2>/dev/null'`
If a smoke test exists, run it via vng: `./scripts/ts.sh ./scripts/run-tests-vng.sh <ShowcaseSmokeTestClass> 2>&1 | tail -30`
Otherwise, a manual check: attach with `--metrics-port 9900`, then from inside the same host `curl -s http://127.0.0.1:9900/metrics | head` shows the counters and `curl -s http://127.0.0.1:9900/stats.json` returns JSON.
Expected: endpoints serve live counters while the scheduler runs; per-class counts increment for observed tiers.

- [ ] **Step 6: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/ShowcaseScheduler.java
git commit -m "feat(samples): ShowcaseScheduler adds per-class metrics + --metrics-port"
```

---

## Task 10: Full regression

**Files:** (none — verification)

- [ ] **Step 1: Run all D unit tests + snapshot/existing histogram tests**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=SchedStatsSnapshotTest,DecisionTraceTest,MetricsServerTest,HistogramsTest -q`
Expected: BUILD SUCCESS, all PASS.

- [ ] **Step 2: Full bpf module test suite for regression**

Run: `./scripts/ts.sh ./mvnw -pl bpf -am test -q`
Expected: BUILD SUCCESS — no regressions from the snapshot/trace/server additions (all opt-in; defaults unchanged).

---

## Self-review notes

- **Spec coverage:** per-class metrics (Task 5, `setClassMetrics`/`perClass`/`ClassMetrics`) — with an explicit documented v1 limitation (dispatch-count rather than full round-trip latency) so it's not a silent gap; decision trace opt-in ring + `recentDecisions()` + reason (Tasks 3/4/5); `toJson`/`toPrometheus` (Tasks 1/2); HTTP endpoint with 3 routes, localhost default, JDK HttpServer (Tasks 6/7/8); `--metrics-port` (Task 8/9); zero-cost-when-unused (all gated on `Opts` fields defaulting to 0/off). Security note (localhost, no auth) documented in `MetricsServer` javadoc.
- **Type consistency:** `SchedStatsSnapshot` 8-field record used identically in tests, `toJson`/`toPrometheus`, and `MetricsServer`. `DecisionTrace.Kind`/`TraceEntry(tsNs,pid,cpu,kind,reason)`/`record(...)`/`recentDecisions()` identical across DecisionTrace, its test, MetricsServer, and the scheduler wiring. `ClassMetrics(count,p50,p99)` + `ClassMetrics.of(BPFHistogram)` consistent.
- **Decisions resolved in-plan:** (a) per-class histogram backing — Task 5 Step 4 verifies whether `BPFHistogram` is heap-constructible and falls back to a tiny heap `Log2Histogram` with an explicit grep, rather than assuming; (b) femtojson entry point (`compactPrint(Map)` vs `List`) verified by grep in Tasks 2 and 7; (c) `--metrics-port` wiring path branches on whether C's `SchedulerRunner` exists (Task 8 Step 2 / Task 9 Step 3).
- **Dependency order honored:** D depends on A + C; the plan header and Task 8 Step 2 both call this out and degrade gracefully if C isn't present.
- **Placeholder scan:** none — every code step is complete; the two "decision point" steps are concrete grep-and-branch instructions, not vague TODOs.
