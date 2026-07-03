# hello-ebpf Documentation Style Guide

This guide governs all pages in `docs/`. Every Spec 2 page-authoring task
checks its output here before requesting review.

---

## Rule 1 — Problem → cause → fix

Every troubleshooting entry states the problem, its root cause, and then the
fix. Never present a fix without the cause.

**Good** (from `docs/userspace-scheduler.md`):
> **Watchdog kills the scheduler after ~30 s under load** — this is the
> `timeout_ms` task-stall watchdog. The Java run loop is not draining fast
> enough, typically because: 1. GC pauses (run with ZGC). 2. `policy()` is
> blocking on I/O. It must not.

**Bad:**
> If you get a watchdog timeout, use ZGC.

---

## Rule 2 — Terse, declarative

No hedging: "usually", "in some cases", "you might want to". State kernel
realities and framework guarantees directly.

**Good** (from `docs/userspace-scheduler.md`):
> At most one sched_ext scheduler can be attached at a time.

**Bad:**
> Usually you can only attach one sched_ext scheduler at a time.

---

## Rule 3 — Every claim carries an artifact

Every assertion is backed by a code block, a shell command, a file path, a
kernel-config line, a link to a source file, or a link to a sample. Prose
without an artifact is a smell.

**Good** (from `docs/sched_ext.md`):
> Verify: `ls /sys/kernel/sched_ext` should exist

**Bad:**
> You need a recent kernel with sched_ext support.

---

## Rule 4 — Short code blocks

Code blocks are ≤ 15 lines by default; up to ≤ 30 lines when the example
genuinely needs the extra lines. Anything past 30 lines lives in a real
sample file and is included via `--8<--` (see Rule 10).

**Good:** An 8-line snippet showing exactly one concept.

**Bad:** A 60-line listing that includes boilerplate imports, main(), and
helper methods that are not the point of the example.

---

## Rule 5 — Cross-link to source

Use relative paths from the `docs/` directory to link to Java source files:
`../bpf-samples/src/main/java/…`. MkDocs resolves these to GitHub via
`repo_url`. Do not use absolute GitHub URLs for in-repo source links; they
break on forks.

**Good:** `[HelloWorld.java](../bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/HelloWorld.java)`

**Bad:** `https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/…`

---

## Rule 6 — Sectioning mode

Process pages (Getting Started, Userspace Scheduler) are sectioned by
numbered progression: §1, §2, §3. Reference pages (Diagnostics, Annotations
catalog, BPFJ catalog) are sectioned by symbol: one heading per symbol or
symbol group. Do not mix modes within one page.

**Good** (reference mode, from `docs/diagnostics.md`): Each diagnostic class
gets its own heading; subheadings cover fields.

**Bad:** A reference page that opens with §1 Background, §2 Overview,
§3 The symbols.

---

## Rule 7 — Motivation before mechanics

Any page introducing a new concept opens with "why" before "how". A reader
who does not yet know whether they care must be able to answer "should I keep
reading?" from the first section.

**Good** (from `docs/shared-maps.md`): Opens with "Why split a program at
all?" before showing `@SharedFrom`.

**Bad:** A page that opens with the API signature and lets readers infer
what problem it solves.

---

## Rule 8 — Concrete kernel realities

Never write "recent kernels support X". Write "kernel ≥ 6.11 with
`CONFIG_SCHED_CLASS_EXT=y`". Include the verification command when
non-obvious.

**Good** (from `docs/userspace-scheduler.md`):
> Linux kernel **≥ 6.12** built with `CONFIG_SCHED_CLASS_EXT=y`. Verify
> with `ls /sys/kernel/sched_ext`.

**Bad:**
> Requires a recent kernel.

---

## Rule 9 — No emoji, no exclamation marks, limited admonitions

No emoji anywhere. No exclamation marks. Use `!!! warning`, `!!! note`, or
`!!! tip` admonitions only for genuine hazards, hard kernel gates, or
"this doc lags the code" warnings — never for filler emphasis.

**Good:** `!!! warning "Requires CAP_BPF + CAP_SYS_ADMIN"` on a page where
running without those capabilities silently fails.

**Bad:** `!!! tip "This is really cool!"` — filler.

---

## Rule 10 — Snippet-comment discipline

Comments inside `[start:name]/[end:name]` regions included via `--8<--` are
documentation for two audiences: they render in the published docs *and* sit
in a compiled source file. Every comment inside an included region must read
as a sentence a reader would want to see. No `// TODO`, no scratch notes, no
"obvious from context" comments. Put developer-only comments outside the
markers.

**Good:**

```java
// [start:xdp_counter]
// Drop the packet if the per-CPU counter exceeds the limit.
if (count.get() > MAX_PKTS) return XdpAction.DROP;
// [end:xdp_counter]
```

**Bad:**

```java
// [start:xdp_counter]
// TODO: check limit
if (count.get() > MAX_PKTS) return XdpAction.DROP;
// [end:xdp_counter]
```

---

## Rule 11 — External content attribution

Every diagram mirrored from ebpf.io (CC-BY 4.0) or the maintainer's blog
series carries:

1. A caption with the template:
   `Source: [Title](URL) by [Author]. Licensed under [CC-BY 4.0](../LICENSE-CC-BY-4.0.md).`
2. A row in `docs/assets/ebpf-io/CREDITS.md` (for ebpf.io content) or
   `docs/assets/blog/CREDITS.md` (for blog content).
3. The image file in `docs/assets/ebpf-io/` or `docs/assets/blog/`.

Third-party logos (Cilium, Falco, Linux, LLVM) are never mirrored — the
CC-BY grant covers ebpf.io's own authored content, not third-party trademarks
that appear on the site.

Full rules: [`research/research-external-attribution.md`](research/research-external-attribution.md).

---

## Reader-test gate (Spec 2 only)

For every new or rewritten page in Spec 2, a fresh subagent with no prior
context reads the page cold and reports what it did not understand. This gate
is defined here so Spec 2 tasks can reference it by name: **"reader-test
gate"**. The spec-compliance reviewer for each Spec 2 task applies it.
