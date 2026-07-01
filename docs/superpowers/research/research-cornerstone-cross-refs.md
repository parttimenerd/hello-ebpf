# Research: cornerstone samples and cross-reference red line

Synthesis doc identifying the ~10 canonical sample programs that carry the
whole hello-ebpf story, the narrative arc ("red line") that connects them,
and the external-content cross-references (blog / ebpf.io / scx / docs.ebpf.io)
attached to each sample.

Companion to:
- [`research-blog-series.md`](research-blog-series.md)
- [`research-ebpf-io-diagrams.md`](research-ebpf-io-diagrams.md)
- [`research-docs-ebpf-io.md`](research-docs-ebpf-io.md)
- [`research-scx-docs.md`](research-scx-docs.md)
- [`research-external-attribution.md`](research-external-attribution.md)

## 1. The red line

hello-ebpf's story arcs the same way the eBPF ecosystem itself does: from
observing existing kernel behaviour, to acting on packets in flight, to
enforcing policy, to replacing kernel policy entirely. Each cornerstone
sample is one waypoint on that arc.

**Arc, in one sentence per stage:**

1. **Observe** — attach to something the kernel already does and watch it.
2. **Stream** — carry structured events out to user space at high rate.
3. **Filter** — decide whether a packet lives or dies at line rate.
4. **Govern** — enforce policy on both directions of the network stack.
5. **Compose** — combine multiple programs and share state between them.
6. **Decide** — replace kernel policy for a whole subsystem (scheduling).
7. **Extend** — write scheduler policy in userspace Java, kernel-assisted.

The samples below are the anchors for each stage. Every hello-ebpf feature
worth documenting shows up in at least one of them, and the arc is short
enough to sit on a single "getting started" page.

## 2. Cornerstone sample selection criteria

A sample earns cornerstone status if it satisfies **all** of:

1. **Lives in `bpf-samples/src/main/java/me/bechberger/ebpf/samples/`** today
   (not an artifact of an old blog post that's been renamed away).
2. **Has a blog post that teaches it end-to-end** — one of the 22 Hello eBPF
   posts (see [`research-blog-series.md`](research-blog-series.md) §3).
3. **Exercises a distinct part of the framework** — an annotation, a helper,
   a hook, or a runtime capability that no other cornerstone already covers.
4. **Loads on a stock 6.14+ kernel without special config**, so a reader
   working through the arc doesn't need to rebuild a kernel until they get
   to sched-ext.

Samples that fail any criterion become supporting examples in the cookbook,
not cornerstones. Example rejections:

- `HelloBuffer` (perf event buffers) — superseded by `RingSample`; fails (1).
- `HelloMap` / `HelloStructMap` (Part 2 originals) — renamed to `HashMapSample`
  / `MapSample`; fails (1).
- `Taskclicker` (Part 20) — not in `bpf-samples/`; fails (1).
- `BlockHTTP2` (Part 14) — repo has `BlockHTTP` and `CGroupBlockHTTPEgress`;
  the Part 14 blog naming has drifted; fails (1).

## 3. The ten cornerstones

Ordered along the red line, one row per stage.

| # | Stage | Sample | Blog post | Teaches |
|---|---|---|---|---|
| 1 | Observe (syscall) | `HelloWorld` | [Part 1](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/) | Attach a program to `execve`, print `bpf_trace_printk`. First eBPF program. |
| 2 | Stream (map) | `HashMapSample` | [Part 2](https://mostlynerdless.de/blog/2024/01/12/hello-ebpf-recording-data-in-basic-ebpf-maps-2/) | `@BPFMapDefinition` HASH map, kernel writes / user reads. |
| 3 | Stream (ring buffer) | `RingSample` | [Part 6](https://mostlynerdless.de/blog/2024/03/12/hello-ebpf-ring-buffers-in-libbpf-6/) | Modern kernel→user streaming via ring buffer, with `@Type` structs. |
| 4 | Filter (XDP drop) | `XDPPacketFilter` | [Part 9](https://mostlynerdless.de/blog/2024/04/22/hello-ebpf-xdp-based-packet-filter-9/) | Drop packets at XDP by IP; parse Ethernet/IP headers from Java. |
| 5 | Govern (XDP + TC) | `PacketLogger` | [Part 13](https://mostlynerdless.de/blog/2024/08/13/hello-ebpf-a-packet-logger-in-pure-java-using-tc-and-xdp-hooks-13/) | Observe both ingress (XDP) and egress (TC) with shared struct definitions. |
| 6 | Compose (tail calls) | `TailCallDemo` | [Part 4](https://mostlynerdless.de/blog/2024/02/12/hello-ebpf-tail-calls-and-your-first-ebpf-application-4/) | One program tail-calls another; stack replaced, no return. |
| 7 | Compose (state) | `GlobalVariableSample` | [Part 10](https://mostlynerdless.de/blog/2024/05/21/hello-ebpf-global-variables-10/) | `GlobalVariable<T>` for shared state without a map lookup. |
| 8 | Govern (firewall) | `Firewall` | [Part 14](https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/) | Feature-length XDP+TC rule engine driven from user space by map updates. |
| 9 | Decide (kernel-side scheduler) | `FCFSScheduler` | [Part 15](https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/) | First `@Scheduler`, struct_ops program, per-CPU DSQ, `select_cpu`/`enqueue`/`dispatch`. |
| 10 | Extend (userspace scheduler) | `LotteryScheduler` | [Part 18](https://mostlynerdless.de/blog/2024/12/27/hello-ebpf-writing-a-lottery-scheduler-in-pure-java-with-bpf-for-each-support-18/) | Pure-Java lottery scheduling on `UserspaceSchedulerBase` with `bpf_for_each_dsq` + `@Lambda`. |

## 4. Coverage matrix — which framework feature does each cornerstone exercise?

Rows are hello-ebpf features; columns are the cornerstones (numbered as in §3).
An `x` means the sample is the primary teaching vehicle for that feature; a
`.` means the sample uses the feature but doesn't lead with it.

| Feature | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|
| `@BPF` class + `main()` | x | . | . | . | . | . | . | . | . | . |
| `@BPFFunction` | x | . | . | . | . | . | . | . | . | . |
| `@BPFMapDefinition` HASH | . | x | . | . | . | . | . | . | . | . |
| `@BPFMapDefinition` RINGBUF | . | . | x | . | . | . | . | . | . | . |
| `@Type` structs | . | . | x | . | x | . | . | . | . | . |
| XDP hook | . | . | . | x | x | . | . | x | . | . |
| TC hook | . | . | . | . | x | . | . | x | . | . |
| Tail calls | . | . | . | . | . | x | . | . | . | . |
| `GlobalVariable<T>` | . | . | . | . | . | . | x | . | . | . |
| CO-RE / BTF (`ethhdr`, `iphdr`) | . | . | . | . | x | . | . | . | . | . |
| Compiler plugin (Java→C) | . | . | . | x | x | . | . | . | x | x |
| `@Scheduler` struct_ops | . | . | . | . | . | . | . | . | x | x |
| DSQs (local/global) | . | . | . | . | . | . | . | . | x | x |
| `UserspaceSchedulerBase` | . | . | . | . | . | . | . | . | . | x |
| `bpf_for_each_dsq` + `@Lambda` | . | . | . | . | . | . | . | . | . | x |
| BPFArena + `@InArena Ptr<T>` | . | . | . | . | . | . | . | . | . | x |

Every framework feature has at least one primary cornerstone. That's the
"complete" test — if a feature had no `x`, either the arc is missing a stage
or the feature is an implementation detail that doesn't need a cornerstone.

## 5. Cross-references per cornerstone

For each cornerstone, the four external anchors: **B** = blog post, **E** =
ebpf.io diagram, **S** = scx anchor (only for #9 and #10), **D** =
docs.ebpf.io further reading. Attribution rules per
[`research-external-attribution.md`](research-external-attribution.md).

### 1. `HelloWorld` — Observe (syscall)

- **B**: [Part 1](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/).
  The Part 1 URL in `docs/index.md` is currently a 404; the correct slug is
  `hello-ebpf-developing-ebpf-apps-in-java-1` (see
  [`research-blog-series.md`](research-blog-series.md) §2).
- **E**: `hook-overview.png` from `/what-is-ebpf/` — the canonical "hook zoo"
  (see [`research-ebpf-io-diagrams.md`](research-ebpf-io-diagrams.md) #14).
  Anchor image for `getting-started/how-it-works.md`.
- **S**: n/a.
- **D**: [Program types overview](https://docs.ebpf.io/linux/program-type/) for
  the reader who wants to see the full attach-point matrix beyond what
  hello-ebpf's cornerstones cover.

### 2. `HashMapSample` — Stream (map)

- **B**: [Part 2](https://mostlynerdless.de/blog/2024/01/12/hello-ebpf-recording-data-in-basic-ebpf-maps-2/).
  Note post shows `HelloMap`/`HelloStructMap`; explain the sample rename in a
  footnote.
- **E**: `map-architecture.png` — kernel-side / user-side view with syscall
  between. Primary anchor image for `maps.md`.
- **Blog diagram** (secondary): Part 2's `ebpf_maps-2000x425.png` (map as
  kernel↔user bridge) — reinforces `map-architecture.png`.
- **S**: n/a.
- **D**: [Map types index](https://docs.ebpf.io/linux/map-type/) for the reader
  who wants the full HASH/ARRAY/PERCPU/etc. matrix.

### 3. `RingSample` — Stream (ring buffer)

- **B**: [Part 6](https://mostlynerdless.de/blog/2024/03/12/hello-ebpf-ring-buffers-in-libbpf-6/)
  and [Part 7](https://mostlynerdless.de/blog/2024/03/22/hello-ebpf-auto-layouting-structs-7/)
  (Part 7 explains the `@Type` struct padding that ring buffer entries rely on).
- **E**: reuse `map-architecture.png` (ring buffers are a map type).
- **Blog diagrams**: Part 6 `ring_buffer.png` and Part 7
  `struct_layout-2000x760.png` — pair these; the struct layout diagram is the
  clearest illustration of what `@Type` produces.
- **S**: n/a.
- **D**: [`BPF_MAP_TYPE_RINGBUF`](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/)
  for the kernel-side ringbuf API.

### 4. `XDPPacketFilter` — Filter (XDP drop)

- **B**: [Part 9](https://mostlynerdless.de/blog/2024/04/22/hello-ebpf-xdp-based-packet-filter-9/).
- **E**: `hook-overview.png` (already used on `getting-started/how-it-works.md`
  — cross-reference from `xdp.md` rather than re-embed).
- **Blog diagrams**: Part 9 `network_stack-2000x517.png` (Ethernet/IP/TCP/HTTP
  layers) and `xdp_filter-1-2000x1005.png` (Java config ↔ XDP kernel program).
- **S**: n/a.
- **D**: [`BPF_PROG_TYPE_XDP`](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/).

### 5. `PacketLogger` — Govern (XDP + TC)

- **B**: [Part 13](https://mostlynerdless.de/blog/2024/08/13/hello-ebpf-a-packet-logger-in-pure-java-using-tc-and-xdp-hooks-13/).
- **E**: none direct — reuse `hook-overview.png` if the reader hasn't seen it.
- **Blog diagrams**: Part 13 `network_stack-1.png` (Linux network stack with
  XDP + TC hook points) is the single best illustration of why you want both.
- **S**: n/a.
- **D**: [`BPF_PROG_TYPE_SCHED_CLS`](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/)
  for TC, plus the XDP page from #4.

### 6. `TailCallDemo` — Compose (tail calls)

- **B**: [Part 4](https://mostlynerdless.de/blog/2024/02/12/hello-ebpf-tail-calls-and-your-first-ebpf-application-4/).
- **E**: `tailcall.png` — the only decent public diagram of tail-call
  semantics ("call, replace stack, no return"). Anchor image for
  `tail-calls.md`.
- **Blog diagram**: Part 4 `tail_call-2000x599.png` (stack frames with vs
  without tail call) reinforces the ebpf.io diagram.
- **S**: n/a.
- **D**: none direct; docs.ebpf.io doesn't have a dedicated tail-call page.

### 7. `GlobalVariableSample` — Compose (state)

- **B**: [Part 10](https://mostlynerdless.de/blog/2024/05/21/hello-ebpf-global-variables-10/).
- **E**: none direct.
- **Blog diagram**: Part 10 `memory_segments.png` (process memory segments
  including `.data`/`.rodata`/`.bss`) — good anchor for `global-variables.md`.
- **S**: n/a.
- **D**: [`BPF_MAP_TYPE_ARRAY`](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_ARRAY/)
  (global variables are backed by a single-slot array map).

### 8. `Firewall` — Govern (rule engine)

- **B**: [Part 14](https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/).
  Post also references `BlockHTTP2` (drifted). Point cookbook readers at
  `BlockHTTP` and `CGroupBlockHTTPEgress` in the repo.
- **E**: reuse `hook-overview.png` if not already shown.
- **Blog diagrams**: firewall UI screenshots are `cookbook.md`-appropriate but
  optional (they age fast).
- **S**: n/a.
- **D**: XDP + SCHED_CLS pages from #4 and #5.

### 9. `FCFSScheduler` — Decide (kernel-side scheduler)

- **B**: [Part 15](https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/).
- **E**: `hook-overview.png` — struct_ops is one of the entries on it; nothing
  scheduler-specific on ebpf.io.
- **Blog diagrams**: Part 15 `Slide12-2000x1125.png` (two tasks time-sliced;
  anchor for `sched-ext/index.md`) and `scheduler_dance-2000x1847.png`
  (per-CPU local DSQs and global DSQ; anchor for `sched-ext/kernel-side.md`).
- **S**: scx anchors from [`research-scx-docs.md`](research-scx-docs.md):
  - Concept: `OVERVIEW.md` — scheduling cycle and DSQs
  - Prereqs: `INSTALL.md` — 6.12+ kernel + distro packages
  - ABI: [`kernel.org/doc/html/latest/scheduler/sched-ext.html`](https://www.kernel.org/doc/html/latest/scheduler/sched-ext.html)
  - Tutorial: [scx wiki Home](https://github.com/sched-ext/scx/wiki) — minimal
    C round-robin scheduler; pair side-by-side with `FCFSScheduler`.
- **D**: none direct — docs.ebpf.io doesn't cover sched-ext specifically; scx
  and kernel.org are the anchors.

### 10. `LotteryScheduler` — Extend (userspace scheduler)

- **B**: [Part 17](https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/)
  (userspace variant, initial) and
  [Part 18](https://mostlynerdless.de/blog/2024/12/27/hello-ebpf-writing-a-lottery-scheduler-in-pure-java-with-bpf-for-each-support-18/)
  (pure-Java variant with `bpf_for_each_dsq` + `@Lambda`).
  Also relevant: [Part 16](https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/)
  for the `taskcontrol` / `UserspaceSchedulerBase` architecture.
- **E**: none direct.
- **Blog diagrams**: Part 16 `task_control_diagram-2000x1680.png` (Java runtime
  ↔ BPF maps ↔ kernel scheduler) is the primary anchor for
  `sched-ext/userspace.md`. Part 17 `lottery_bowl.png` for the lottery-specific
  cookbook entry.
- **S**: primary anchor is
  [`scheds/rust/scx_rustland/README.md`](https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_rustland/README.md)
  — scx_rustland_core is what hello-ebpf's `UserspaceSchedulerBase` mirrors.
  Secondary: [`scheds/rust/scx_rusty/README.md`](https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_rusty/README.md)
  for the hybrid pattern.
- **D**: none direct.

## 6. Non-cornerstone samples (supporting cast)

These live in the cookbook or reference pages, not on the main arc. Each is
still worth a blog cross-link.

| Sample | Blog | Where it belongs |
|---|---|---|
| `TCDropEveryThirdOutgoingPacket` | Part 13 | `tc.md` (simplest TC example) |
| `XDPDropEveryThirdPacket` | Part 12 | `xdp.md` (simplest XDP example) |
| `LogOpenAt2Calls` | Part 6 companion | `cookbook.md` (syscall tracing) |
| `MapSample` | Part 2 followup | `maps.md` (BPF array + PERCPU) |
| `CGroupBlockHTTPEgress` | Part 14 sidebar | `cookbook.md` (cgroup hook) |
| `BlockHTTP` | Part 14 sidebar | `cookbook.md` |
| `WeightedRRSample` | Part 15 followup | `sched-ext/kernel-side.md` |
| `TaskStorageScheduler` | Part 16 | `sched-ext/userspace.md` |
| `SampleScheduler` | Part 15 | `sched-ext/kernel-side.md` (skeleton) |
| `ChaosScheduler` | Part 19 | `sched-ext/cookbook.md` (concurrency fuzzer) |

Part 20's `Taskclicker` is deliberately not here — the sample isn't in
`bpf-samples`. Docs writers can link the blog post from `sched-ext/cookbook.md`
under a "playful examples" section without cross-referencing an in-repo sample.

## 7. Corrections carried forward from research

Fold these into Spec 1 brief + Spec 2 authoring:

1. **Blog post count is 20, not 18.**
   [`research-blog-series.md`](research-blog-series.md) §1–§2 confirmed 20
   numbered posts + Part 14.5 + 2 preambles. Earlier session assumption of 18
   (which the user affirmed as "correct" before the research completed) is
   stale. Fix `docs/index.md` line 101 accordingly.
2. **`docs/index.md` Part 1 URL is a 404.** Replace
   `writing-ebpf-programs-in-java-with-hello-ebpf-1-hello-world` with
   `hello-ebpf-developing-ebpf-apps-in-java-1`.
3. **Part 19 URL contains the typo `helle-ebpf`.** Preserve verbatim in any
   cross-link — "correcting" it makes the link 404.
4. **docs.ebpf.io is not a BCC/Python tutorial site.** It is a modern Linux
   kernel reference (last updated 2026-06-29). Update Spec 1 brief's stance
   from cautious to liberal. See
   [`research-docs-ebpf-io.md`](research-docs-ebpf-io.md).
5. **scx C-scheduler READMEs no longer exist.** The `scheds/c/scx_simple/`
   path in the earlier Spec 1 brief is stale; C schedulers moved to kernel
   `tools/sched_ext/` and `scx-c-examples`. See
   [`research-scx-docs.md`](research-scx-docs.md) §"Notes and gotchas".
6. **Sample-drift footnote convention.** For each blog post that references a
   renamed/removed sample (Parts 2, 3, 8, 14, 20), the Spec 2 page authoring
   task adds a one-line footnote: "*In the blog post this sample is called
   `X`; it is now `Y` in the repo.*" Do not update the blog posts.

## 8. Handoff to Spec 2

Spec 2's per-page authoring tasks should each reference this doc for:

- Which cornerstone(s) the page teaches (row from §3).
- Which framework features are the primary teaching load (columns from §4).
- Which external anchors to link and which diagrams to mirror (§5).
- Attribution and CREDITS discipline (delegated to
  [`research-external-attribution.md`](research-external-attribution.md)).

The order of Spec 2 page authoring should follow the red line (§1) rather
than nav order. That keeps the accumulated framework vocabulary consistent —
`maps.md` is written after `hello.md` so it can rely on `@BPF`/`@BPFFunction`
already being introduced, and `sched-ext/*` is written last so it can rely
on tail calls, arenas, and global variables all being established.
