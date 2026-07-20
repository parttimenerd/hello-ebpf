# scx_rusty Port (RustyScheduler) — Design

**Date:** 2026-07-20
**Goal:** Port the scx_rusty scheduler to Java on the `UserspaceScheduler` framework, faithfully reproducing its userspace domain load-balancing algorithm (single-NUMA scope), and add the reusable tooling the port reveals is missing — a CPU-topology helper, a pure load-balancing engine, and honest diagnostics.

**Why this project:** The framework already ships 39 sample schedulers and mature preempt/signals/harness APIs. The remaining value in "write a useful scheduler" is *discovery*: porting a real, battle-tested scheduler (scx_rusty) surfaces the genuine rough edges an author hits. Priorities: authoring ergonomics, offline testability, and diagnostics.

## Scope (Approach A: faithful core, single-NUMA)

**In scope:** rusty's per-domain push/pull load balancer (exact imbalance math, closest-to-xfer task selection, feasibility + preference filtering, only-if-reduces-imbalance guard), domain assignment, decayed duty-cycle load metric, `target_dom` re-assignment.

**Out of scope (documented simplifications vs. upstream rusty):**
- **Inter-NUMA balancing.** We model a single NUMA node (domains = LLC groups within it). The thinkstation CI node is single-socket, so multi-NUMA is untestable here. Upstream's node↔node balancing (`balance_between_nodes`) is not ported.
- **Infeasible-weight correction.** Upstream uses `scx_utils::LoadLedger`/`infeasible.rs` (~200 lines) to cap weights when a domain is over-committed. We use raw `weight` directly.
- **BPF-side ravg buckets.** Upstream accumulates per-task duty cycle in BPF and reads it via `ravg_read`. We compute the decayed duty cycle in userspace from `execRuntime` deltas (see Load Metric). Same *quantity*, computed userspace-side, decayed at both enqueue and LB-read time to match rusty's sampling at LB time.

## Architecture

Mirrors rusty's BPF↔userspace split, expressed in the framework's hooks:

- **Dispatch (hot path — `schedule()`):** each task has an assigned *domain* (a set of CPUs; default one domain per last-level cache). On enqueue, dispatch the task to an idle CPU **within its assigned domain**; if none idle, dispatch to `ANY_CPU` (kernel picks within constraints). This is rusty's "round-robin within domain."
- **Load balancing (cold path — `tick()`, ~1 s):** read every active task's decayed load, bucket by assigned domain, run rusty's push/pull algorithm, and re-assign `target_dom` on migrated tasks. No task is dispatched during `tick()`; migration only changes which domain the task's *next* enqueue targets — faithful to rusty, which just sets `target_dom`.

The hard-to-verify logic (the balancer) lives in a pure, kernel-free utility so it is fully unit-testable.

## Components & File Structure

### New sample
- **`bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustyScheduler.java`**
  Extends `UserspaceScheduler`. Overrides `schedule()` (domain-local dispatch), `tick()` (periodic load balance), plus a FemtoCli `Cli` inner class matching sibling samples. Holds per-pid load state and the pid→domain assignment. Wires framework data into `DomainLoadBalancer` and applies the returned migrations.

### New reusable framework utilities (in `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/`)
- **`CpuTopology.java`**
  `static CpuTopology detect()` and `static CpuTopology detect(Path sysfsRoot)` (injectable root for tests). Reads `/sys/devices/system/cpu/cpuN/cache/indexK/{level,shared_cpu_list}`, groups CPUs by highest-level (LLC) shared cache into domains. Missing/unreadable cache info → single domain of all online CPUs (never throws). Exposes `int nrDomains()`, `long cpuMask(int dom)`, `int domainOfCpu(int cpu)`, `int nrCpus()`.
- **`Domain.java`**
  Value + mutable load holder: `{int id; long cpuMask}` plus a `LoadEntity` ported 1:1 from rusty (`cost_ratio=0.05`, `xfer_ratio=0.50`, `push_max_ratio=0.50`; `imbal()=load_sum−load_avg`; `state()` = NeedsPush/NeedsPull/Balanced via `|imbal| > load_avg*cost_ratio`). Holds a sorted list of `TaskLoad`. `preferredDomMask` = the domain(s) a task has cache affinity with (its `prevCpu`'s domain); the balancer tries preferred pull domains first, then falls back to any feasible domain — matching rusty's two-pass `try_find_move_task`.
- **`DomainLoadBalancer.java`**
  The reusable push/pull engine. Input: `List<Domain>` each holding `TaskLoad{int pid; double load; long domMask; long preferredDomMask; boolean isKworker}`, plus `load_avg` and options (`skipKworkers`). Runs rusty's `balance_within_node` loop verbatim: pop busiest push-domain, pull into least-loaded, `tryFindMoveTask` picks the task whose load is closest to `xfer = min(pushImbal,pullImbal)*0.50` among feasible tasks (`domMask` bit set for pull domain, not kworker if skipped, not already migrated), preferring `preferredDomMask`, and only migrating if it reduces total imbalance. Output: `List<Migration>{int pid; int fromDom; int toDom}`. **No BPF, no I/O.**

### Docs
- New section in `docs/sched-ext/userspace.md`: "Porting scx_rusty: domain load balancing" — walks through `RustyScheduler`, `CpuTopology`, and `DomainLoadBalancer`.

## Load Metric

Per-pid state: `{double ewmaDutyCycle; long lastExecRuntime; long lastSeenNs}`.

**Decay** (half-life `H`, default 1 s → `α_dt = 1 − 2^(−dt/H)`). Applied both on enqueue *and* for every tracked pid at `tick()` read time (decay-at-read), so a dormant task decays exactly as rusty's ravg would when sampled at LB time.

On enqueue of task `t` at wall time `now`:
- `execDelta = max(0, t.execRuntime − lastExecRuntime)`
- `wallDelta = now − lastSeenNs`
- `instantDuty = wallDelta > 0 ? min(1.0, execDelta / (double) wallDelta) : 0.0`
- decay toward `instantDuty`: `ewmaDutyCycle += (instantDuty − ewmaDutyCycle) * α(wallDelta)`
- store `lastExecRuntime = t.execRuntime`, `lastSeenNs = now`

At `tick()` read time for a pid last seen `dt` ago: decay toward 0 over `dt` (`ewmaDutyCycle *= 2^(−dt/H)`), then update `lastSeenNs`.

**Task load = `ewmaDutyCycle * weight`** (`weight` from `QueuedTask.weight`, default 100) — rusty's `duty_cycle × weight`. Domain load = Σ task loads.

## Data Flow

**Dispatch (`schedule(tasks, count)`):**
1. For each task with an unknown pid: assign domain = `domainOfCpu(prevCpu)` if `prevCpu >= 0`, else `nextRoundRobinDomain()`.
2. Update that pid's load state (enqueue decay above).
3. Dispatch to an idle CPU within the assigned domain's `cpuMask` (scan idle bitmap over the mask); if none idle, `dispatchTask(t, ANY_CPU)`.

**Load balance (`tick()`):**
1. Decay-at-read every tracked pid; drop pids not seen for `> stalePidTicks` ticks (default 10) so maps stay bounded.
2. Build `TaskLoad` per pid (`domMask` from affinity → default all domains; `preferredDomMask` = the domain of the task's `prevCpu`, i.e. where it last ran — so the balancer prefers pulling a task into a domain it has cache affinity with, matching rusty. Falls back to `domMask` when `prevCpu < 0`).
3. Bucket into `Domain`s; `load_sum` per domain; `load_avg = totalLoad / nrDomains`.
4. `List<Migration> = DomainLoadBalancer.balance(domains, loadAvg, opts)`.
5. Apply each migration: set the pid's assigned domain to `toDom`. Next enqueue dispatches into the new domain.

## Testing

**Offline unit tests (no kernel, no root — primary coverage):**
- **`DomainLoadBalancerTest`** — pure engine. (a) hot vs cold domain → migrates task closest to xfer target; (b) balanced → no migration; (c) `domMask` infeasible → skipped; (d) `preferred` chosen over equal-load non-preferred; (e) only-if-reduces-imbalance guard blocks harmful move; (f) `skipKworkers` honored. Asserts exact `{pid,from,to}` decisions.
- **`CpuTopologyTest`** — fake sysfs temp tree → asserts LLC grouping; missing cache dir → single-domain fallback of N CPUs.
- **`RustyLoadMetricTest`** — under `SchedulerHarness.withVirtualClock`: a 100%-busy task's load converges toward `1.0*weight`; a mostly-sleeping task stays low; a task that goes dormant decays toward 0 at read time.
- **`RustySchedulerHarnessTest`** — end-to-end offline via `SchedulerHarness.forScheduler(new RustyScheduler()).withCpus(n)`: assert every dispatch targets a CPU inside the task's assigned domain; imbalance the load, `tick()`, assert migrations land.

**Kernel smoke test (thinkstation only, excluded from hosted CI job):**
- Add `rustySchedulerAttachesAndRuns` to `SchedulerSmokeTest`: attach, sleep 300 ms, assert still attached.

## Error Handling / Diagnostics

- `CpuTopology.detect()` never throws on missing/permission-denied sysfs; logs `"CpuTopology: no LLC cache info under <root>; using a single domain of N CPUs"` and returns a single all-CPU domain.
- Detection producing more domains than CPUs, or an empty-cpuMask domain → `IllegalStateException` naming the offending domain (a real bug — fail loud).
- `RustyScheduler` validates `nrDomains >= 1`; an out-of-range assigned domain throws with the pid and domain id (not a bare `ArrayIndexOutOfBoundsException`).
- Attach failures reuse the framework's existing diagnostics; no new work.

## Deliverable

A single PR against `main` (branch `feat/rusty-scheduler-port`) containing: the three reusable utilities, the `RustyScheduler` sample, the offline tests, the smoke test, and the docs section — building green on CI and passing tests on the thinkstation.
