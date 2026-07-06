# sched-ext Documentation Improvements

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Overhaul the sched-ext documentation section to be more welcoming and fun, link all relevant talks, add navigation, and add new pages for the sound scheduler and fun schedulers.

**Architecture:** Edit existing pages in-place plus create two new pages (`sched-ext/sound-scheduler.md`, `sched-ext/fun-schedulers.md`). Update `mkdocs.yml` nav once at the end. No code changes — docs only.

**Tech Stack:** MkDocs Material, Markdown, embedded YouTube iframes, Speakerdeck preview images.

---

## Context for all tasks

**Current sched-ext nav order** (from `mkdocs.yml`):
```
- Overview: sched-ext/index.md
- Writing a Scheduler: sched-ext/guide.md
- Kernelspace Scheduler: sched-ext/kernel-side.md
- Userspace Scheduler: sched-ext/userspace.md
- Callbacks Reference: sched-ext/callbacks.md
- Cookbook: sched-ext/cookbook.md
```

**Final sched-ext nav order** (after all tasks):
```
- Overview: sched-ext/index.md
- Writing a Scheduler: sched-ext/guide.md
- Kernelspace Scheduler: sched-ext/kernel-side.md
- Userspace Scheduler: sched-ext/userspace.md
- Callbacks Reference: sched-ext/callbacks.md
- Cookbook: sched-ext/cookbook.md
- Sound Scheduler: sched-ext/sound-scheduler.md
- Fun Schedulers: sched-ext/fun-schedulers.md
```

**Bottom-of-page navigation pattern** (use in every sched-ext page):
```markdown
---

*Next: [Page Name](next-page.md)*
```

Sequence: index → guide → kernel-side → userspace → callbacks → cookbook → sound-scheduler → fun-schedulers.

**Key external links to use throughout:**
- Kernel docs: `https://docs.kernel.org/scheduler/sched-ext.html`
- BPF struct_ops: `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/sched_ext_ops/`
- Sound of Scheduling YouTube: `https://www.youtube.com/watch?v=ihAGd8GN90w`
- Sound scheduler source: `https://github.com/parttimenerd/loudness-scheduler`
- Taskclicker: `https://github.com/Mr-Pine/taskclicker`
- scx_rustland_core: `https://github.com/sched-ext/scx/tree/main/rust/scx_rustland_core`

**eBPF Summit talk embed** (eBPF Summit 2024 — Writing a Linux Scheduler in Java with eBPF):
```html
<iframe width="560" height="315" src="https://www.youtube.com/embed/bWs5GHYpYxg" title="Writing a Linux Scheduler in Java with eBPF — eBPF Summit 2024" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
```
(Use the same video ID `bWs5GHYpYxg` from the index.md — this is the eBPF-summit scheduler talk.)

**Sound of Scheduling embed:**
```html
<iframe width="560" height="315" src="https://www.youtube.com/embed/ihAGd8GN90w" title="Sound of Scheduling — Writing Linux Schedulers in Java with eBPF" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
```

**Graphics to use (from `docs/superpowers/graphics-catalog.md`):**
- CPU time-slicing: `https://files.speakerdeck.com/presentations/23196bda93134fd39a46549087f9965f/preview_slide_10.jpg` (Talk 3, slide 10)
- Work-stealing DSQ: `https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_60.jpg` (Talk 4, slide 60)
- Scheduler dance diagram: `https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler_dance-2000x1847.png`
- Task control flow (userspace): `https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png`
- Lottery bowl: `https://mostlynerdless.de/wp-content/uploads/2024/12/lottery_bowl.png`

**Origin story text** (for index.md introduction):
> It all started when I was naive enough to propose a talk at the eBPF Summit on writing Linux schedulers in Java — then I had to implement it. The result turned out to be genuinely useful: hello-ebpf can now replace the Linux CPU scheduler with pure Java code.

---

### Task 1 — Update `sched-ext/index.md`

**Files:**
- Modify: `docs/sched-ext/index.md`

#### What to change

1. **Top-of-page header block** — replace the current blog-series line with a richer block:

```markdown
# sched_ext — Overview

**Kernel docs:** [docs.kernel.org/scheduler/sched-ext.html](https://docs.kernel.org/scheduler/sched-ext.html) · **BPF program type:** [BPF_PROG_TYPE_STRUCT_OPS/sched_ext_ops](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/sched_ext_ops/)  
**Blog series:** [Part 15 — Write a custom scheduler in Java](https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/) · [Part 16 — Userspace scheduler](https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/) · [Part 17 — Lottery scheduler](https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/) · [Part 18 — bpf_for_each](https://mostlynerdless.de/blog/2024/12/27/hello-ebpf-writing-a-lottery-scheduler-in-pure-java-with-bpf-for-each-support-18/)  
**Source:** [`SchedulerBase.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/SchedulerBase.java) · [`Scheduler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java)
```

2. **Origin story paragraph** — insert right after the header block, before the "Prerequisites" section:

```markdown
It all started when I was naive enough to propose a talk at the eBPF Summit on writing
Linux schedulers in Java — then I had to implement it. The result turned out to be
genuinely useful: hello-ebpf can now replace the Linux CPU scheduler with pure Java code,
all as a normal jar file, with no kernel patching required.

<iframe width="560" height="315" src="https://www.youtube.com/embed/bWs5GHYpYxg" title="Writing a Linux Scheduler in Java with eBPF — eBPF Summit 2024" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
```

3. **Diagram** — insert after "Why sched_ext?" section, before "Quick start":

```markdown
![CPU time-slicing: tasks A and B alternating on the CPU timeline](https://files.speakerdeck.com/presentations/23196bda93134fd39a46549087f9965f/preview_slide_10.jpg)

![Global DSQ dispatching to per-CPU local queues via work-stealing](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_60.jpg)
```

4. **Task control flow diagram** — insert after "Quick start" section (move from userspace.md):

```markdown
The diagram below shows how the dispatching works across the kernel and userspace scheduler paths:

![Tasks flow from kernel enqueue through DSQs to CPU dispatch](https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png)
```

5. **Bottom navigation** — append at very end:

```markdown
---

*Next: [Writing a Scheduler](guide.md)*
```

- [ ] Step 1: Read `docs/sched-ext/index.md` in full.
- [ ] Step 2: Apply all five changes above in a single edit pass.
- [ ] Step 3: Verify the file renders correctly: `cd /Users/i560383_1/code/experiments/hello-ebpf && python3 -m mkdocs build --config-file mkdocs.yml 2>&1 | grep -E 'ERROR|WARNING|sched-ext'` (should be clean).
- [ ] Step 4: Commit: `docs(sched-ext): enrich index with origin story, diagrams, kernel links, next-page nav`.

---

### Task 2 — Add bottom-nav to `sched-ext/guide.md`, `sched-ext/kernel-side.md`, `sched-ext/cookbook.md`

These three pages need bottom navigation added. We do them together to keep it atomic.

**Files:**
- Modify: `docs/sched-ext/guide.md`
- Modify: `docs/sched-ext/kernel-side.md`
- Modify: `docs/sched-ext/cookbook.md`

- [ ] Step 1: Read all three files.
- [ ] Step 2: Append to `guide.md`:
  ```markdown
  ---
  
  *Next: [Kernelspace Scheduler](kernel-side.md)*
  ```
- [ ] Step 3: Append to `kernel-side.md`:
  ```markdown
  ---
  
  *Next: [Userspace Scheduler](userspace.md)*
  ```
- [ ] Step 4: Append to `cookbook.md`:
  ```markdown
  ---
  
  *Next: [Sound Scheduler](sound-scheduler.md)*
  ```
- [ ] Step 5: Run mkdocs build check.
- [ ] Step 6: Commit: `docs(sched-ext): add next-page navigation to guide, kernel-side, cookbook`.

---

### Task 3 — Update `sched-ext/userspace.md`

**Files:**
- Modify: `docs/sched-ext/userspace.md`

#### What to change

1. **Mark page as experimental** — add a warning admonition right after the header block (after the Javadoc links, before the "A userspace scheduler moves…" paragraph):

```markdown
!!! warning "Highly experimental"
    The userspace scheduler is under active development and the API may change between
    releases. It has been tested on Linux 6.12–6.14 (kernel ≥ 6.12 required). If you
    hit issues, please [open an issue](https://github.com/parttimenerd/hello-ebpf/issues)
    with the verifier log attached.
```

2. **Remove blog post links** from the header — there is no dedicated blog post on userspace scheduling yet. Replace the "Blog series" paragraph with:

```markdown
**See also:** [scx_rustland_core](https://github.com/sched-ext/scx/tree/main/rust/scx_rustland_core) (the Rust pattern this port is based on) · [sched_ext kernel docs](https://docs.kernel.org/scheduler/sched-ext.html)
```

3. **Remove the task_control_diagram image** (it moves to index.md in Task 1) — delete the line:
   ```
   ![Tasks enqueue into a scheduling queue; CPUs ask for new tasks and return finished ones; a task-settings map controls policy](https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png)
   ```

4. **Add a replacement diagram** — insert a simple ASCII architecture diagram right after "How it works" heading:

```markdown
```
Java policy (your code)
        │ policy(task) → cpu
        ▼
   UserspaceScheduler
        │
  BPFUserRingBuffer (Java→kernel)
        │
  UserspaceSchedulerBase (BPF)
        │   enqueue: task → queued BPFRingBuffer (kernel→Java)
        │   dispatch: read dispatched ring → scx_bpf_dsq_insert
        ▼
   Linux kernel (sched_ext)
```
```

5. **Bottom navigation** — append at very end:

```markdown
---

*Next: [Callbacks Reference](callbacks.md)*
```

- [ ] Step 1: Read `docs/sched-ext/userspace.md` in full.
- [ ] Step 2: Apply all five changes in a single edit pass (experimental warning, remove/replace blog series links, remove diagram, add ASCII diagram, add nav).
- [ ] Step 3: Run mkdocs build check.
- [ ] Step 4: Commit: `docs(sched-ext/userspace): mark experimental, link rustland, replace diagram, add next-page nav`.

---

### Task 4 — Update `sched-ext/callbacks.md`

**Files:**
- Modify: `docs/sched-ext/callbacks.md`

#### What to change

1. **Header block** — replace the current "How callbacks work" intro text header with a proper page header:

```markdown
# sched_ext — Callback Reference

**Javadoc:** [`Scheduler`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/Scheduler.html) · [`SchedulerBase`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/SchedulerBase.html) · [`DispatchQueue`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/sched/DispatchQueue.html)  
**BPF reference:** [sched_ext_ops — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/sched_ext_ops/) · [sched-ext kernel docs](https://docs.kernel.org/scheduler/sched-ext.html)  
**Source:** [`Scheduler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java) · [`SchedulerBase.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/SchedulerBase.java)

## How callbacks work
```

2. **Bottom navigation** — append at very end:

```markdown
---

*Next: [Cookbook](cookbook.md)*
```

- [ ] Step 1: Read `docs/sched-ext/callbacks.md` in full.
- [ ] Step 2: Apply both changes.
- [ ] Step 3: Run mkdocs build check.
- [ ] Step 4: Commit: `docs(sched-ext/callbacks): add Javadoc links, ebpf.io link, next-page nav`.

---

### Task 5 — Create `sched-ext/sound-scheduler.md`

**Files:**
- Create: `docs/sched-ext/sound-scheduler.md`

Full content to write:

```markdown
# Sound Scheduler

The sound scheduler is a CPU scheduler written in hello-ebpf that **controls how many
CPU cores your program uses based on ambient sound level.** Shout at your computer and
your application actually runs faster — the scheduler detects the loudness via the
microphone and scales core allocation proportionally.

This was demonstrated live at Chemnitz Linux Days 2025, where the audience participated
by shouting at a screen.

<iframe width="560" height="315" src="https://www.youtube.com/embed/ihAGd8GN90w" title="Sound of Scheduling — Writing Linux Schedulers in Java with eBPF" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

**Blog post:** [Part 20 — A Scheduler Controlled by Sound](https://mostlynerdless.de/blog/2025/03/25/hello-ebpf-a-scheduler-controlled-by-sound-20/)  
**Source:** [github.com/parttimenerd/loudness-scheduler](https://github.com/parttimenerd/loudness-scheduler)  
**Talk:** [Sound of Scheduling — Speakerdeck](https://speakerdeck.com/parttimenerd/sound-of-scheduling-writing-linux-schedulers-in-java-with-ebpf)

---

## How it works

The scheduler extends a simple FIFO kernelspace scheduler and adds two global BPF variables
that the Java main loop updates every 100 milliseconds:

- **`numCpus`** — how many cores tasks are allowed to use (scales with loudness 1–N)
- **`sliceNs`** — per-task time slice duration (also adjusted dynamically)

The `selectCPU` callback restricts usable cores to `numCpus` while still respecting
per-task CPU affinity constraints. The `enqueue` callback scales time slices inversely
with queue depth to stay responsive under load.

As a bonus, singing a note close to a configured frequency (e.g. 440 Hz) reduces the
time slice — frequency scaling as a scheduling knob.

```java
// The Java main loop polls the microphone every 100 ms
while (running) {
    double loudness = microphone.getRmsLevel();
    int cores = Math.max(1, (int)(loudness * availableCpus));
    prog.numCpus.set(cores);
    prog.sliceNs.set(computeSlice(cores));
    Thread.sleep(100);
}
```

The BPF side reads `numCpus` as a global variable — a zero-cost read from the kernel
because global variables are memory-mapped into the BPF program's address space.

---

## Why this is a good hello-ebpf demo

It shows all the pieces working together:

| Component | Role |
|-----------|------|
| `@BPF` class + `@BPFFunction` | The scheduler's BPF callbacks |
| `GlobalVariable<Integer>` | `numCpus` and `sliceNs` — written by Java, read in BPF |
| `SchedulerBase` + `DispatchQueue` | FIFO foundation |
| Java main loop | Polls microphone, updates globals |

The interesting part is not the scheduler algorithm — it's that the **scheduling policy
is controlled by a Java thread reading a microphone**, with changes taking effect in under
100 ms, all without a kernel patch.

---

## Running it

Clone and build the loudness-scheduler repository:

```bash
git clone https://github.com/parttimenerd/loudness-scheduler
cd loudness-scheduler
mvn package
sudo java -jar target/loudness-scheduler.jar
```

Requires a microphone (or any ALSA input device) and Linux ≥ 6.11 with sched_ext enabled.

---

*Next: [Fun Schedulers](fun-schedulers.md)*
```

- [ ] Step 1: Write the file as specified above.
- [ ] Step 2: Run mkdocs build check (without nav entry yet — page will be orphaned but should build cleanly with `not_in_nav` if needed, or add to nav directly in this task).
- [ ] Step 3: Add to `mkdocs.yml` nav under sched_ext section: `- Sound Scheduler: sched-ext/sound-scheduler.md` (after `Cookbook`).
- [ ] Step 4: Run mkdocs build check.
- [ ] Step 5: Commit: `docs(sched-ext): add sound-scheduler page`.

---

### Task 6 — Create `sched-ext/fun-schedulers.md`

**Files:**
- Create: `docs/sched-ext/fun-schedulers.md`

Full content to write:

```markdown
# Fun Schedulers

sched_ext makes writing weird and creative schedulers surprisingly accessible. Here are
some schedulers built with hello-ebpf that show just how far you can take it.

---

## Sound Scheduler

Shout at your computer to make it run faster. The scheduler reads the microphone every
100 ms and scales the number of CPU cores allocated to your program with loudness. See
the [dedicated page](sound-scheduler.md) for the full write-up.

**Source:** [github.com/parttimenerd/loudness-scheduler](https://github.com/parttimenerd/loudness-scheduler)

---

## Taskclicker

> "Taskclicker lets you experience scheduling first hand, literally. It's a clicker-game
> scheduler GUI where you have to click on tasks to schedule them."

Taskclicker is a Linux CPU scheduler where **you are the scheduler.** A GUI shows you all
runnable tasks; you click on a task to dispatch it to a CPU. Earn virtual syscalls to buy
upgrades.

It implements first-come-first-served (FCFS) scheduling backed by hello-ebpf's sched_ext
support, submitted as an entry to the sched-ext-kit-contest.

**Source:** [github.com/Mr-Pine/taskclicker](https://github.com/Mr-Pine/taskclicker)

---

## Minimal Scheduler

The simplest possible scheduler that works: two methods, no extra DSQs, about 20 lines of
Java. A good starting point if you want to build something.

**Source:** [`MinimalScheduler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java)

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "minimal_scheduler")
public abstract class MinimalScheduler extends SchedulerBase implements Scheduler {

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(MinimalScheduler.class)) {
            program.runSchedulerLoop();
        }
    }
}
```

---

## Lottery Scheduler

Assigns each task a random time slice drawn from a uniform distribution. Tasks with a
longer slice advance less in the virtual-time DSQ, producing a fair lottery among all
runnable tasks without per-task bookkeeping.

**Blog post:** [Part 17 — Writing a Lottery Scheduler in Java with sched_ext](https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/)

![Lottery bowl: tasks enter, CPUs draw randomly](https://mostlynerdless.de/wp-content/uploads/2024/12/lottery_bowl.png)

---

## Your scheduler here?

If you build something interesting with hello-ebpf sched_ext support, open a PR or file
an issue to add it to this page.

---

*[Back to Overview](index.md)*
```

- [ ] Step 1: Write the file as specified above.
- [ ] Step 2: Add to `mkdocs.yml` nav: `- Fun Schedulers: sched-ext/fun-schedulers.md` (after `Sound Scheduler`).
- [ ] Step 3: Run mkdocs build check.
- [ ] Step 4: Commit: `docs(sched-ext): add fun-schedulers page`.

---

### Task 7 — Final verification

- [ ] Step 1: Run `cd /Users/i560383_1/code/experiments/hello-ebpf && python3 -m mkdocs build --config-file mkdocs.yml 2>&1 | grep -E 'ERROR|WARNING'` — must be clean.
- [ ] Step 2: Navigate to `http://127.0.0.1:8001/hello-ebpf/sched-ext/` in browser (if dev server is running) and confirm:
  - Origin story + YouTube embed appear
  - Two diagrams appear
  - Kernel docs link is in header
  - "Next: Writing a Scheduler" link at bottom
- [ ] Step 3: Check `http://127.0.0.1:8001/hello-ebpf/sched-ext/callbacks/` for Javadoc links.
- [ ] Step 4: Check `http://127.0.0.1:8001/hello-ebpf/sched-ext/sound-scheduler/` loads the new page.
- [ ] Step 5: Check `http://127.0.0.1:8001/hello-ebpf/sched-ext/fun-schedulers/` loads the new page.
