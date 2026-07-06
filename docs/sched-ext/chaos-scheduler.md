# Chaos Scheduler

The `ChaosScheduler` is a **concurrency-fuzzing scheduler** built with hello-ebpf. It
deliberately perturbs scheduling to expose race conditions and concurrency bugs in Java
programs — the same class of bugs that are notoriously hard to reproduce deterministically.

**Source:** [`ChaosScheduler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/ChaosScheduler.java)  
**Blog post:** [Part 19 — Concurrency Testing using Custom Linux Schedulers](https://mostlynerdless.de/blog/2025/02/25/helle-ebpf-concurrency-testing-using-custom-linux-schedulers-19/)  
**Talks:** [p99conf 2025](https://speakerdeck.com/parttimenerd/concurrency-testing-using-custom-linux-schedulers-p99conf) · [FOSDEM 2025](https://archive.fosdem.org/2025/schedule/event/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers/) (co-authored with Jake Hillion, Meta)  
**LWN coverage:** [Concurrency testing with sched_ext](https://lwn.net/Articles/1007689/)  
**Related:** [scx_chaos upstream](https://www.youtube.com/watch?v=YdP0UE6gGkw) — Jake Hillion's LPC 2025 talk on the kernel-side counterpart

---

## The idea: scheduling as a fuzzer

Traditional concurrency testing injects delays via `Thread.sleep()` or byte-code
instrumentation. The chaos scheduler does it at the OS level: every task scheduled
through sched_ext is subject to controlled perturbations that no amount of
`synchronized` can hide from.

The four traits, each independently configurable:

| Trait | What it does |
|-------|-------------|
| **Random vtime delays** | Targeted tasks land in a vtime DSQ with a random delay up to `maxDelayNs` — effectively random scheduling order |
| **CPU frequency throttling** | All CPUs are randomly throttled to a fraction of peak performance on each tick, varying execution speed |
| **Slice degradation** | Targeted tasks get `SCX_SLICE_DFL / sliceDivisor` — more frequent context switches |
| **Cold-start penalty** | Tasks woken up for the first time get a further slice reduction, encouraging interleaving with newly-woken threads |

Together they create a scheduling environment that is deterministic in intent but
non-deterministic in execution — exactly what's needed to shake out race conditions.

---

## Running it

```bash
# Build once
cd bpf-samples && mvn package && cd ..

# Chaos all user tasks on the system
sudo ./run.sh ChaosScheduler

# Target only a specific process and its descendants (pass TGID = getpid())
sudo ./run.sh ChaosScheduler 12345

# Also set CPU performance target (0 = minimum, 1024 = full speed; default 512)
sudo ./run.sh ChaosScheduler 12345 512
```

Press `Ctrl-C` to stop. The previous scheduler is restored atomically.

---

## How it works

### Two DSQs

```
CHAOS_DSQ (vtime-ordered)  ← delayed/perturbed tasks
SHARED_DSQ (FIFO)          ← non-targeted tasks (kthreads, affinity-pinned, etc.)
```

`dispatch()` drains `CHAOS_DSQ` first, then falls back to `SHARED_DSQ`. This means
chaos targets compete on vtime while the rest of the system runs normally.

### The enqueue path

```java
@Override
public void enqueue(Ptr<task_struct> p, long enq_flags) {
    EnqFlags f = EnqFlags.passThrough(enq_flags);

    if (!isChaosTarget(p)) {
        shared.insert(p, SCX_SLICE_DFL.value(), f);
        return;
    }

    // Trait 3: slice degradation
    long slice = SCX_SLICE_DFL.value() / sliceDivisor.get();

    // Trait 4: cold-start penalty (first wakeup after sleep)
    Ptr<TaskState> state = taskState.bpf_getOrCreate(p);
    if (state != null && state.val().wakeups == 1) {
        slice = slice / 4;
    }

    // Trait 1: random vtime delay
    long delay = maxDelayNs.get();
    if (delay > 0) {
        long vtime = vtimeNow.get() + BPFJ.bpfRandBounded(delay);
        chaos.insertVtime(p, slice, vtime, f);
    } else {
        shared.insert(p, slice, f);
    }
}
```

### CPU frequency throttling (trait 2)

```java
@Override
public void tick(Ptr<task_struct> p) {
    int perfTarget = cpuPerfTarget.get();
    if (perfTarget < 1024) {
        // ±25% jitter around target
        int jitter = BPFJ.bpfRandBounded(perfTarget / 2 + 1);
        int perf = perfTarget - perfTarget / 4 + jitter;
        scx_bpf_cpuperf_set(scx_bpf_task_cpu(p), Math.min(perf, 1024));
    }
}
```

`scx_bpf_cpuperf_set` writes the CPU's performance level directly via cpufreq —
it varies actual execution speed, not just scheduling order.

### Targeting

`isChaosTarget(p)` returns **false** for kthreads and affinity-pinned or
migration-disabled tasks. For user tasks it returns **true** unconditionally
when `targetTgid == 0`, or when the task is in the specified TGID's descendant
tree (walks `real_parent` up to 8 levels) when `targetTgid != 0`.

The 8-level bound is required because the BPF verifier rejects unbounded loops.

---

## Tuning knobs

All knobs are `GlobalVariable`s — you can write them from Java before or after attach:

| Field | Default | Meaning |
|-------|---------|---------|
| `targetTgid` | 0 | TGID to target; 0 = all user tasks |
| `maxDelayNs` | 5 000 000 (5 ms) | Maximum random vtime delay per task |
| `cpuPerfTarget` | 512 | CPU performance level (0–1024); 1024 disables throttling |
| `sliceDivisor` | 4 | `SCX_SLICE_DFL / sliceDivisor` = per-task slice for chaos tasks |

---

## Using it from a test harness

```java
try (var sched = BPFProgram.load(ChaosScheduler.class)) {
    // Only perturb this JVM process (and its forked children)
    sched.targetTgid.set((int) ProcessHandle.current().pid());

    // Increase randomness: 10 ms max delay, minimum CPU speed
    sched.maxDelayNs.set(10_000_000L);
    sched.cpuPerfTarget.set(128);

    sched.attachScheduler();

    runConcurrentTest();  // races are now far more likely to surface

    sched.isSchedulerAttachedProperly();  // watchdog hasn't fired?
}
```

To run your test suite under chaos:

```bash
sudo ./run.sh ChaosScheduler $(pgrep -f "java.*MyTestSuite") &
mvn test -pl mymodule
```

Or use the `SchedulerExtension` JUnit 5 integration — see the [Cookbook](cookbook.md#testing-your-scheduler).

---

## The p99conf / FOSDEM 2025 talk

The talk "Concurrency Testing using Custom Linux Schedulers" (co-authored with Jake
Hillion from Meta, who brought the same ideas to kernel `scx_chaos`) walks through:

1. Why classical concurrency testing (sleep injection, byte-code instrumentation)
   is hard to scale
2. How sched_ext lets you control scheduling at OS level with no application changes
3. A live demo of `ChaosScheduler` catching a deadlock in a production Java service
4. The `bpf_for_each_dsq` lambda feature (Parts 18–19 of the blog series) that makes
   vtime manipulation from BPF clean to express in Java

**Slides (p99conf):** [speakerdeck.com/parttimenerd/concurrency-testing-using-custom-linux-schedulers-p99conf](https://speakerdeck.com/parttimenerd/concurrency-testing-using-custom-linux-schedulers-p99conf)  
**Slides + video (FOSDEM 2025):** [archive.fosdem.org](https://archive.fosdem.org/2025/schedule/event/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers/)

<video controls width="100%" preload="metadata"
       src="https://video.fosdem.org/2025/ud6215/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers.av1.webm"
       type="video/webm">
  <a href="https://video.fosdem.org/2025/ud6215/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers.mp4">Download video (FOSDEM 2025)</a>
</video>

### What the press said

LWN.net covered the scheduler in
[*Concurrency testing with sched_ext*](https://lwn.net/Articles/1007689/).
Note: the LWN piece is a condensed summary — the
[blog post](https://mostlynerdless.de/blog/2025/02/25/helle-ebpf-concurrency-testing-using-custom-linux-schedulers-19/)
has the full narrative.

> "When a thread is ready to run, instead of assigning it to a CPU right away, their
> scheduler will put it to sleep for a random amount of time based on some configurable
> parameters."

> "The idea of running threads in a random order is not new. There are plenty of
> specialized concurrency testing tools that do something similar. But
> concurrency-fuzz-scheduler is not nearly as fine-grained as such tools usually are."

> "Hillion and Bechberger's concurrency-fuzz-scheduler is a promising example of a
> sched_ext scheduler that does something more than act as a testbed for scheduling
> ideas."

---

## Further reading

- [Cookbook](cookbook.md) — testing infrastructure, watchdog, `SchedulerExtension`
- [Callbacks Reference](callbacks.md) — `runnable()`, `tick()`, `BPFTaskStorage`
- [Part 19 blog post](https://mostlynerdless.de/blog/2025/02/25/helle-ebpf-concurrency-testing-using-custom-linux-schedulers-19/) — full narrative walkthrough
- [scx_chaos (Jake Hillion, LPC 2025)](https://www.youtube.com/watch?v=YdP0UE6gGkw) — upstream kernel `scx_chaos`, the spiritual twin

---

*Next: [Fun Schedulers](fun-schedulers.md)*
