# Research: hello-ebpf blog series

This document catalogs the "Hello eBPF" blog series on mostlynerdless.de so that documentation writers can (a) cross-link the correct posts from the right docs pages, and (b) know which images/diagrams from the posts would be worth mirroring into the repo.

## 1. Summary

- Total posts in scope: **22** (2 preamble posts + 20 numbered posts from Part 1 through Part 20, plus the special "Part 14.5" resource-collection post).
- README currently lists **19** URLs (2 preamble + 16 numbered + 1 "14.5"). It has not been updated with Parts 17, 18, 19, and 20 (which were published between Dec 2024 and Mar 2025).
- `docs/index.md` claims an "18-part blog series" AND its "Part 1" link is a **404** — the linked slug `writing-ebpf-programs-in-java-with-hello-ebpf-1-hello-world` does not exist. The real Part 1 URL is `hello-ebpf-developing-ebpf-apps-in-java-1`. Neither the count nor the link is currently correct.
- Correct count for the series: 20 numbered posts (Part 1 through Part 20), plus one supplementary "Part 14.5" resources post, plus 2 unnumbered preamble posts on Python module tracing and Panama. Numbered installments = 20; total "hello-ebpf-family" posts = 22.
- Arc of the series: Parts 1–4 use **bcc** (libbcc via Panama); Parts 5–11 pivot to **libbpf** and gradually replace hand-written C with Java-generated C (annotation-processor-based struct layout, then whole C-code generation); Parts 12–14 introduce the **Java compiler plugin** that lets developers write eBPF logic directly in Java (XDP, TC, firewall); Parts 15–20 extend the framework to **sched-ext** (custom Linux schedulers written in Java, including sound-controlled, lottery, and concurrency-fuzzing variants).

## 2. Reconciliation notes

- **README claim** (`README.md` lines 100–122): "Blog Posts" list containing 19 entries (2 preamble + Parts 1–16 + Part 14.5). No mention of "18-part" or a total.
- **docs/index.md claim** (line 101): "This project is accompanied by an 18-part blog series that walks through each feature step by step". Line 103 links to `https://mostlynerdless.de/blog/2024/02/11/writing-ebpf-programs-in-java-with-hello-ebpf-1-hello-world/` — verified 404 via WebFetch.
- **Ground truth**, verified by fetching `https://mostlynerdless.de/page/2/`, `https://mostlynerdless.de/page/3/`, `https://mostlynerdless.de/page/4/`, and the individual post URLs listed below:
  - Parts 1–16 exist at the slugs in README (with the exception that README refers to Part 3 as "perf event buffers" but the actual URL slug is `hello-ebpf-recording-data-in-event-buffers-3`, and Part 7 was actually published Mar 25 2024 per the page metadata even though README lists Mar 22).
  - **Part 17** exists: `https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/` (Dec 17, 2024).
  - **Part 18** exists: `https://mostlynerdless.de/blog/2024/12/27/hello-ebpf-writing-a-lottery-scheduler-in-pure-java-with-bpf-for-each-support-18/` (Dec 27, 2024).
  - **Part 19** exists at a URL with a typo — `helle-ebpf` rather than `hello-ebpf`: `https://mostlynerdless.de/blog/2025/02/25/helle-ebpf-concurrency-testing-using-custom-linux-schedulers-19/` (Feb 25, 2025). Any cross-links must use the mistyped slug or they 404.
  - **Part 20** exists: `https://mostlynerdless.de/blog/2025/03/25/hello-ebpf-a-scheduler-controlled-by-sound-20/` (Mar 25, 2025).
  - No Part 21 or later exists as of the fetch (checked via next/prev navigation on Part 20 — the "next" link is a non-series post about developing Java on a phone, dated May 9 2025).
- **Verdict**: Update both README (add 17, 18, 19, 20) and `docs/index.md` (change "18-part" to "20-part", fix the Part 1 URL, ideally link to the canonical archive listing instead of a single post).

## 3. Post inventory

### Preamble A — Finding all used Classes, Methods and Functions of a Python Module

- **Date**: Dec 1, 2023
- **URL**: https://mostlynerdless.de/blog/2023/12/01/finding-all-used-classes-methods-and-functions-of-a-python-module/
- **Teaches**: Using Python's `sys.settrace` to track which classes/methods/functions of a module are actually invoked during execution. Preamble — motivates the author's later need to explore libbcc's Python API.
- **Primary sample**: no matching sample (Python utility, not part of the Java repo).
- **Target nav page**: `NONE`.
- **Diagrams**: none technical; only the site logo (`cropped-Wandzeichnung-Körper-freigestellt-klein.png`).

### Preamble B — From C to Java Code using Panama

- **Date**: Dec 11, 2023
- **URL**: https://mostlynerdless.de/blog/2023/12/11/from-c-to-java-code-using-panama/
- **Teaches**: Calling C standard library functions from Java through Project Panama (FFM API), including `errno` handling and `jextract`-generated bindings.
- **Primary sample**: `HelloWorld`, `HelloWorldJExtract` — these are pedagogical (not in `bpf-samples`); no matching sample in the current repo.
- **Target nav page**: `NONE`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2023/12/panama-2000x981.png — Panama project header image (screenshot/branding).

### Part 1 — Hello eBPF: Developing eBPF Apps in Java (1)

- **Date**: Dec 31, 2023 (README says "Jan 01, 2024" but the URL and page metadata are Dec 31).
- **URL**: https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/
- **Teaches**: Introduces the hello-ebpf library. Attaches to `execve` via libbcc and Panama; motivates why Java + eBPF is worth pursuing.
- **Primary sample**: `HelloWorld` (early bcc-based version; the current `bpf-samples/.../samples/HelloWorld.java` uses the compiler plugin, so the naming matches but the implementation has evolved).
- **Target nav page**: `getting-started/hello.md` (with a "history" pointer to `getting-started/how-it-works.md`).
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2023/12/image-20.png — "eBPF overview" quote block from ebpf.io (screenshot).
  - https://mostlynerdless.de/wp-content/uploads/2023/12/text2102.png — hello-ebpf logo/branding (hand-drawn).
  - https://mostlynerdless.de/wp-content/uploads/2023/12/image-23.png — Extended eBPF ecosystem overview with Java Duke mascot (hand-drawn/diagram, likely worth mirroring).

### Part 2 — Hello eBPF: Recording data in basic eBPF maps (2)

- **Date**: Jan 12, 2024
- **URL**: https://mostlynerdless.de/blog/2024/01/12/hello-ebpf-recording-data-in-basic-ebpf-maps-2/
- **Teaches**: eBPF maps as the primary kernel↔user-space channel; hash maps holding counters, then struct-valued maps.
- **Primary sample**: `HashMapSample`. Post also references early `HelloMap`/`HelloStructMap` prototypes that are not in the current repo (superseded by `HashMapSample` / `MapSample` under `samples/demo/`).
- **Target nav page**: `maps.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/01/ebpf_maps-1000x288.png — header (chart).
  - https://mostlynerdless.de/wp-content/uploads/2024/01/sockets_and_shared_mem-2000x865.png — sockets vs shared-memory IPC comparison (hand-drawn diagram; **strong mirror candidate**).
  - https://mostlynerdless.de/wp-content/uploads/2024/01/ebpf_maps-2000x425.png — eBPF map as bidirectional bridge between kernel and user space (hand-drawn; **strong mirror candidate for `maps.md`**).

### Part 3 — Hello eBPF: Recording data in perf event buffers (3)

- **Date**: Jan 29, 2024
- **URL**: https://mostlynerdless.de/blog/2024/01/29/hello-ebpf-recording-data-in-event-buffers-3/
- **Teaches**: Per-CPU perf event buffers for streaming data (execve pid/uid/comm) out of the kernel; also introduces the JUnit + Docker + virtme test rig.
- **Primary sample**: no direct match — post uses `HelloBuffer`, an early prototype since replaced by the ring-buffer-based samples (`RingSample`, `LogOpenAt2Calls`). Perf event buffers are largely superseded by ring buffers in modern hello-ebpf.
- **Target nav page**: `maps.md` (perf event buffer subsection) or `cookbook.md`. Note in the doc that perf event buffers are historical; users should prefer ring buffers.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/01/perf_event_buffer.png — perf event buffer architecture (hand-drawn; mirror candidate).

### Part 4 — Hello eBPF: Tail calls and your first eBPF application (4)

- **Date**: Feb 12, 2024
- **URL**: https://mostlynerdless.de/blog/2024/02/12/hello-ebpf-tail-calls-and-your-first-ebpf-application-4/
- **Teaches**: eBPF tail calls (jump between programs without growing the stack), used to build a syscall-logging CLI.
- **Primary sample**: `TailCallDemo` (current) — the post's CLI is an earlier standalone app; `TailCallDemo` is the retained pedagogical equivalent.
- **Target nav page**: `tail-calls.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/02/tail_call-2000x599.png — stack-frame comparison with vs without tail call (hand-drawn; **strong mirror candidate for `tail-calls.md`**).
  - https://mostlynerdless.de/wp-content/uploads/2024/02/image-1.png — tail-call mechanism graphic from ebpf.io (screenshot/reused).
  - Terminal outputs of `./run.sh --skip-others` and `./run.sh` — code-listings/terminal (not linked images).

### Part 5 — Hello eBPF: First steps with libbpf (5)

- **Date**: Feb 26, 2024
- **URL**: https://mostlynerdless.de/blog/2024/02/26/hello-ebpf-first-steps-with-libbpf-5/
- **Teaches**: Why libbcc's runtime-Clang model is problematic; introduces the annotation-processor-based libbpf path that compiles eBPF at build time and produces a self-contained JAR.
- **Primary sample**: `HelloWorld` (the libbpf variant that becomes today's default).
- **Target nav page**: `getting-started/how-it-works.md` and `architecture/plugin.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/02/bcc_vs_bpf-1-2000x1125.png — libbcc vs libbpf compile-flow comparison (hand-drawn; **strong mirror candidate for `architecture/plugin.md`**).
  - https://mostlynerdless.de/wp-content/uploads/2024/02/IMG_2772-2000x690.jpeg — conference travel photo (skip).

### Part 6 — Hello eBPF: Ring buffers in libbpf (6)

- **Date**: Mar 12, 2024
- **URL**: https://mostlynerdless.de/blog/2024/03/12/hello-ebpf-ring-buffers-in-libbpf-6/
- **Teaches**: Ring buffers as the successor to perf event buffers for kernel→user data streaming; the `openat` example.
- **Primary sample**: `RingSample` (still present at `bpf-samples/.../samples/RingSample.java` and `samples/demo/RingSample.java`).
- **Target nav page**: `maps.md` (ring buffer section). Possibly cross-link from `cookbook.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/03/ring_buffer.png — ring-buffer structure (hand-drawn; mirror candidate).

### Part 7 — Hello eBPF: Auto Layouting Structs (7)

- **Date**: Mar 22, 2024 (post page shows Mar 25; README lists Mar 22).
- **URL**: https://mostlynerdless.de/blog/2024/03/22/hello-ebpf-auto-layouting-structs-7/
- **Teaches**: How struct alignment works on x86-64; the annotation processor that emits properly padded struct definitions on both C and Java sides.
- **Primary sample**: `RingSample`; also a `TypeProcessingSample` that no longer exists by that exact name in the repo (superseded by the `@Type` annotation flow used across `MapSample`, `HashMapSample`, etc.).
- **Target nav page**: `reference/annotations.md` (the `@Type` annotation) and `architecture/plugin.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/03/struct_layout-2000x760.png — struct memory layout of `e_pid`/`e_filename`/`e_comm` (hand-drawn; strong mirror candidate).
  - https://mostlynerdless.de/wp-content/uploads/2024/03/image-2-2000x1623.png — System V ABI alignment table (screenshot).
  - https://mostlynerdless.de/wp-content/uploads/2024/03/struct_layout2-2000x772.png — padding waste in an unaligned struct (hand-drawn; strong mirror candidate).

### Part 8 — Hello eBPF: Generating C Code (8)

- **Date**: Apr 9, 2024
- **URL**: https://mostlynerdless.de/blog/2024/04/09/hello-ebpf-generating-c-code-8/
- **Teaches**: A C AST + pretty-printer inside the annotation processor that generates C struct/map definitions from Java records; foundation for later "pure Java" work.
- **Primary sample**: no direct match — `TypeProcessingSample2` is a demo class that has since been absorbed into `bpf-processor` / `bpf-compiler-plugin`.
- **Target nav page**: `architecture/plugin.md`.
- **Diagrams**: only the site logo image; no technical diagrams in the post itself. Notable snippet: an example of generated C struct output vs the source Java record — worth quoting in `architecture/plugin.md`.

### Part 9 — Hello eBPF: XDP-based Packet Filter (9)

- **Date**: Apr 22, 2024
- **URL**: https://mostlynerdless.de/blog/2024/04/22/hello-ebpf-xdp-based-packet-filter-9/
- **Teaches**: XDP hook basics + a domain-name-to-IP blocklist that drops matching IPv4 packets in kernel; walk-through of the network protocol stack.
- **Primary sample**: `XDPPacketFilter` (also `XDPPacketFilter2` variant).
- **Target nav page**: `xdp.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/04/network_stack-2000x517.png — Ethernet → IP → TCP/UDP → HTTP layer stack (hand-drawn; mirror candidate for `xdp.md` and `tc.md`).
  - https://mostlynerdless.de/wp-content/uploads/2024/04/xdp_filter-1-2000x1005.png — Java-side config/log component talking to the XDP kernel program (hand-drawn; **strong mirror candidate for `xdp.md`**).

### Part 10 — Hello eBPF: Global Variables (10)

- **Date**: May 21, 2024
- **URL**: https://mostlynerdless.de/blog/2024/05/21/hello-ebpf-global-variables-10/
- **Teaches**: The `GlobalVariable<T>` construct and how it's implemented under the hood via BPF `.data`/`.rodata` sections.
- **Primary sample**: `GlobalVariableSample` (in `samples/demo/`).
- **Target nav page**: `global-variables.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/05/memory_segments.png — process memory segments (stack/heap/data/bss/text) (hand-drawn; mirror candidate for `global-variables.md`).

### Part 11 — Hello eBPF: BPF Type Format and 13 Thousand Generated Java Classes (11)

- **Date**: Jul 2, 2024
- **URL**: https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/
- **Teaches**: BTF as compact binary type metadata in the running kernel; how hello-ebpf generates ~13k Java classes from vmlinux BTF so kernel structs are usable in Java.
- **Primary sample**: `ethhdr` (the eth-header BTF struct is used pedagogically; no dedicated sample class — the pattern shows up across `XDPPacketFilter`, `PacketLogger`, etc.).
- **Target nav page**: `architecture/plugin.md` (BTF section) and `reference/bpfj.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/07/u32_tree-2000x377.png — typedef chain for `__u32` as a tree (hand-drawn; mirror candidate).
  - https://mostlynerdless.de/wp-content/uploads/2024/07/ethhdr-2000x1111.png — full type tree for `struct ethhdr` (hand-drawn; **strong mirror candidate for `architecture/plugin.md`**).
  - https://mostlynerdless.de/wp-content/uploads/2024/07/PXL_20240701_171548883-2000x736.jpg — author photo (skip).

### Part 12 — Hello eBPF: Write your eBPF application in Pure Java (12)

- **Date**: Jul 30, 2024
- **URL**: https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/
- **Teaches**: The Java compiler plugin that translates Java methods on `BPFProgram` into eBPF C at build time — the pivot to "pure Java" hello-ebpf.
- **Primary sample**: `XDPDropEveryThirdPacket`, `HashMapSample`.
- **Target nav page**: `getting-started/how-it-works.md`, `architecture/plugin.md`, and `reference/bpfj.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/07/image-2.png — IDE autocomplete showing BPF helper functions (screenshot; nice-to-have for `reference/bpfj.md`).
  - https://mostlynerdless.de/wp-content/uploads/2024/07/image.png — hover-doc popup on a BPF helper (screenshot).
  - https://mostlynerdless.de/wp-content/uploads/2024/07/compiler_pipeline-2000x1125.png — annotation processor + compiler plugin pipeline (hand-drawn; **strong mirror candidate for `architecture/plugin.md`**).

### Part 13 — Hello eBPF: A Packet Logger in Pure Java using TC and XDP Hooks (13)

- **Date**: Aug 13, 2024
- **URL**: https://mostlynerdless.de/blog/2024/08/13/hello-ebpf-a-packet-logger-in-pure-java-using-tc-and-xdp-hooks-13/
- **Teaches**: Combining XDP (ingress) and TC (egress) to observe both directions of the packet flow with unified struct definitions shared kernel↔user.
- **Primary sample**: `PacketLogger` (also `BasePacketParser`; `TCDropEveryThirdOutgoingPacket` is a companion for TC alone).
- **Target nav page**: `tc.md` (primary) and cross-link from `xdp.md`. Also `cookbook.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/08/image-2000x1136.png — PacketLogger demo output showing captured packets (screenshot; nice-to-have).
  - https://mostlynerdless.de/wp-content/uploads/2024/08/network_stack-1.png — Linux network stack with XDP and TC hook points (hand-drawn; **strong mirror candidate for `tc.md` and `xdp.md`**).
  - https://mostlynerdless.de/wp-content/uploads/2024/08/table.png — table of accessible `__sk_buff` fields in TC (screenshot of a table; useful for `tc.md` if we can reproduce as markdown).

### Part 14 — Hello eBPF: Building a Lightning Fast Firewall with Java & eBPF (14)

- **Date**: Aug 27, 2024
- **URL**: https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/
- **Teaches**: A rule-based firewall driven by a Spring Boot web UI; XDP + TC combined; rules updated from userspace via maps.
- **Primary sample**: `Firewall`, `FirewallSpring`, `BasePacketParser`. Post also references `BlockHTTP2` — the current repo has `BlockHTTP` (under `samples/demo/`) and `CGroupBlockHTTPEgress`; the `BlockHTTP2` name has drifted.
- **Target nav page**: `cookbook.md` (feature-length firewall example) with cross-links from `xdp.md` and `tc.md`.
- **Diagrams**:
  - Google-hosted slidesz image — firewall web-UI dashboard slide (screenshot; likely ephemeral, avoid mirroring).
  - https://mostlynerdless.de/wp-content/uploads/2024/08/image-1.png — adding an HTTP block rule for google.com in the UI (screenshot).
  - https://mostlynerdless.de/wp-content/uploads/2024/08/image-2.png — triggering the blocked request (screenshot).
  - https://mostlynerdless.de/wp-content/uploads/2024/08/image-3.png — blocked-packets log display (screenshot).

### Part 14.5 — Hello eBPF: Collection of Resources for eBPF (14.5)

- **Date**: Sep 10, 2024
- **URL**: https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-collection-of-resources-for-ebpf-14-5/
- **Teaches**: Curated list of eBPF learning resources (talks, tutorials, docs, community links) after JavaZone 2024.
- **Primary sample**: no matching sample (linkdump post).
- **Target nav page**: link from a top-level "Learn more" / resources section in `index.md`. No dedicated feature page.
- **Diagrams**: only the site logo and small thumbnails for related posts; nothing to mirror.

### Part 15 — Hello eBPF: Writing a Linux scheduler in Java with eBPF (15)

- **Date**: Sep 10, 2024
- **URL**: https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/
- **Teaches**: The `Scheduler` interface backed by sched-ext, with FIFO and weighted implementations, plus a benchmark comparison against stock CFS/EEVDF.
- **Primary sample**: `FCFSScheduler`, `WeightedRRSample`, `SampleScheduler` — post references `FIFOScheduler` and `WeightedScheduler` which correspond to today's `FCFSScheduler` and `WeightedRRSample`.
- **Target nav page**: `sched-ext/index.md` and `sched-ext/kernel-side.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/09/image.png — Scheduler-interface implementation code (code listing screenshot).
  - https://mostlynerdless.de/wp-content/uploads/2024/09/Slide12-2000x1125.png — two tasks A and B time-sliced on one CPU (hand-drawn; **strong mirror candidate for `sched-ext/index.md`**).
  - https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler_dance-2000x1847.png — per-CPU local DSQs and global DSQ (hand-drawn; **strong mirror candidate for `sched-ext/kernel-side.md`**).
  - https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler-keynote-2000x553.png — race-condition illustration (hand-drawn).
  - https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler-keynote2-2000x714.png — deadlock scenario (hand-drawn).
  - https://mostlynerdless.de/wp-content/uploads/2024/09/image-1.png — Renaissance benchmark bar chart (chart; nice-to-have).
  - https://mostlynerdless.de/wp-content/uploads/2024/09/image-2.png — Renaissance benchmark with outlier replaced (chart).
  - https://mostlynerdless.de/wp-content/uploads/2024/09/image-6-2000x1125.png — concluding image (skip unless review shows relevance).

### Part 16 — Hello eBPF: Control task scheduling with a custom scheduler written in Java (16)

- **Date**: Dec 3, 2024
- **URL**: https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/
- **Teaches**: A REST-controllable scheduler that can pause/resume individual Java threads without POSIX signals; introduces the `ThreadControl` library.
- **Primary sample**: `TaskStorageScheduler` is closely related; no direct 1:1 sample for the post's `BaseScheduler`/`ClockThread` demo — see also the `taskcontrol` module.
- **Target nav page**: `sched-ext/userspace.md` and `sched-ext/cookbook.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png — task-control architecture with BPF maps between Java runtime and kernel scheduler (hand-drawn; **strong mirror candidate for `sched-ext/userspace.md`**).
  - https://mostlynerdless.de/wp-content/uploads/2024/12/PXL_20241201_140537228.MP_-2000x1125.jpg — museum travel photo (skip).

### Part 17 — Hello eBPF: Writing a Lottery Scheduler in Java with sched-ext (17)

- **Date**: Dec 17, 2024
- **URL**: https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/
- **Teaches**: A classical lottery-scheduling algorithm implemented on top of the taskcontrol module — priorities become weighted lottery tickets.
- **Primary sample**: `LotteryScheduler` (and `LotterySample`).
- **Target nav page**: `sched-ext/cookbook.md`.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/12/lottery_bowl.png — lottery-drawing-bowl illustration for the scheduler (hand-drawn; **strong mirror candidate for `sched-ext/cookbook.md`**).
  - https://mostlynerdless.de/wp-content/uploads/2024/12/image.png — small unspecified image near post end (skip unless review confirms).
  - Site-logo image (skip).

### Part 18 — Hello eBPF: Writing a Lottery Scheduler in Pure Java with bpf_for_each Support (18)

- **Date**: Dec 27, 2024
- **URL**: https://mostlynerdless.de/blog/2024/12/27/hello-ebpf-writing-a-lottery-scheduler-in-pure-java-with-bpf-for-each-support-18/
- **Teaches**: Lambda expressions as arguments to `@BuiltinBPFFunction`s (specifically `bpf_for_each_dsq`), letting the lottery scheduler be written in Java without embedded C. Introduces `Box<T>` for closure-scope workarounds.
- **Primary sample**: `LotteryScheduler` (pure-Java variant).
- **Target nav page**: `sched-ext/cookbook.md` and `reference/bpfj.md` (lambda/`$lambda` docs).
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2024/12/PXL_20241226_131910050.MP_-2000x1125.jpg — the author's cat (skip).
- **Notable snippet**: contains a table/list of the specific transformations `bpf_for_each_dsq` performs on a Java lambda — worth pulling verbatim into `reference/bpfj.md`.

### Part 19 — Hello eBPF: Concurrency Testing using Custom Linux Schedulers (19)

- **Date**: Feb 25, 2025
- **URL**: https://mostlynerdless.de/blog/2025/02/25/helle-ebpf-concurrency-testing-using-custom-linux-schedulers-19/ (**typo `helle-ebpf` is part of the canonical URL**; do not "correct" it or the link 404s).
- **Teaches**: A fuzzing scheduler that pseudo-randomly pauses/resumes threads to expose concurrency bugs; presented at FOSDEM 2025.
- **Primary sample**: `ChaosScheduler` is the closest match (naming has drifted since the post — the post uses `FIFOScheduler` + `TaskContext` + `SchedulerSetting`).
- **Target nav page**: `sched-ext/cookbook.md`. Also link from any future "testing" or "fuzzing" doc.
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2025/02/image-1.png — deadlock scenario (hand-drawn; mirror candidate).
  - https://mostlynerdless.de/wp-content/uploads/2025/02/image-2.png — task-control scheduler overview (hand-drawn/diagram; mirror candidate).
  - https://mostlynerdless.de/wp-content/uploads/2025/02/image-3.png — START/RUNNING/SLEEPING state machine (state-diagram; **strong mirror candidate**).
  - https://mostlynerdless.de/wp-content/uploads/2025/02/image-4.png — Brussels street photo (skip).
  - https://mostlynerdless.de/wp-content/uploads/2025/02/image-5.png — producer-consumer example architecture (diagram; mirror candidate).

### Part 20 — Hello eBPF: A scheduler controlled by sound (20)

- **Date**: Mar 25, 2025
- **URL**: https://mostlynerdless.de/blog/2025/03/25/hello-ebpf-a-scheduler-controlled-by-sound-20/
- **Teaches**: A scheduler whose "usable CPU count" is driven by ambient microphone loudness — a demo/talk companion piece for Chemnitzer Linux-Tage.
- **Primary sample**: no matching sample class in `bpf-samples` — the `taskclicker` demo lives outside the main sample directory or has not been ported into `bpf-samples/`. Confirm with maintainer whether it should be added or documented as external.
- **Target nav page**: `sched-ext/cookbook.md` (playful example section).
- **Diagrams**:
  - https://mostlynerdless.de/wp-content/uploads/2025/03/image.png — Taskclicker scheduler-game GUI (screenshot; nice-to-have for the cookbook page).
  - Site logo and gravatar (skip).

## 4. Diagrams inventory

Priorities: rows tagged "hand-drawn diagram" or "state diagram" are the primary mirror candidates; screenshots and charts are optional; photographs are always skip.

| Post | Image URL | Description | Type | Suggested target doc page |
|------|-----------|-------------|------|---------------------------|
| Preamble B | https://mostlynerdless.de/wp-content/uploads/2023/12/panama-2000x981.png | Panama header image | screenshot | defer |
| 1 | https://mostlynerdless.de/wp-content/uploads/2023/12/image-20.png | ebpf.io overview quote | screenshot | defer |
| 1 | https://mostlynerdless.de/wp-content/uploads/2023/12/text2102.png | hello-ebpf logo | hand-drawn | `index.md` |
| 1 | https://mostlynerdless.de/wp-content/uploads/2023/12/image-23.png | Extended eBPF ecosystem with Java Duke | hand-drawn | `getting-started/how-it-works.md` |
| 2 | https://mostlynerdless.de/wp-content/uploads/2024/01/sockets_and_shared_mem-2000x865.png | Sockets vs shared-memory IPC | hand-drawn | `maps.md` |
| 2 | https://mostlynerdless.de/wp-content/uploads/2024/01/ebpf_maps-2000x425.png | eBPF map as kernel↔user bridge | hand-drawn | `maps.md` |
| 3 | https://mostlynerdless.de/wp-content/uploads/2024/01/perf_event_buffer.png | Perf event buffer architecture | hand-drawn | `maps.md` (historical note) |
| 4 | https://mostlynerdless.de/wp-content/uploads/2024/02/tail_call-2000x599.png | Stack frames with vs without tail call | hand-drawn | `tail-calls.md` |
| 4 | https://mostlynerdless.de/wp-content/uploads/2024/02/image-1.png | Tail-call graphic (ebpf.io) | screenshot | defer |
| 5 | https://mostlynerdless.de/wp-content/uploads/2024/02/bcc_vs_bpf-1-2000x1125.png | libbcc vs libbpf compile flows | hand-drawn | `architecture/plugin.md` |
| 6 | https://mostlynerdless.de/wp-content/uploads/2024/03/ring_buffer.png | Ring buffer structure | hand-drawn | `maps.md` |
| 7 | https://mostlynerdless.de/wp-content/uploads/2024/03/struct_layout-2000x760.png | Struct layout `e_pid`/`e_filename`/`e_comm` | hand-drawn | `reference/annotations.md` |
| 7 | https://mostlynerdless.de/wp-content/uploads/2024/03/image-2-2000x1623.png | System V ABI alignment table | screenshot | defer |
| 7 | https://mostlynerdless.de/wp-content/uploads/2024/03/struct_layout2-2000x772.png | Wasted padding in unaligned struct | hand-drawn | `reference/annotations.md` |
| 8 | (no technical images) | – | – | – |
| 9 | https://mostlynerdless.de/wp-content/uploads/2024/04/network_stack-2000x517.png | Ethernet→IP→TCP→HTTP layer stack | hand-drawn | `xdp.md` (also `tc.md`) |
| 9 | https://mostlynerdless.de/wp-content/uploads/2024/04/xdp_filter-1-2000x1005.png | Java config/log ↔ XDP kernel program | hand-drawn | `xdp.md` |
| 10 | https://mostlynerdless.de/wp-content/uploads/2024/05/memory_segments.png | Process memory segments (data/bss/…) | hand-drawn | `global-variables.md` |
| 11 | https://mostlynerdless.de/wp-content/uploads/2024/07/u32_tree-2000x377.png | Typedef chain for `__u32` | hand-drawn | `architecture/plugin.md` |
| 11 | https://mostlynerdless.de/wp-content/uploads/2024/07/ethhdr-2000x1111.png | Full type tree of `struct ethhdr` | hand-drawn | `architecture/plugin.md` |
| 12 | https://mostlynerdless.de/wp-content/uploads/2024/07/image-2.png | IDE autocomplete for BPF helpers | screenshot | `reference/bpfj.md` (optional) |
| 12 | https://mostlynerdless.de/wp-content/uploads/2024/07/image.png | Hover-doc on BPF helper | screenshot | defer |
| 12 | https://mostlynerdless.de/wp-content/uploads/2024/07/compiler_pipeline-2000x1125.png | Annotation processor + compiler plugin pipeline | hand-drawn | `architecture/plugin.md` |
| 13 | https://mostlynerdless.de/wp-content/uploads/2024/08/image-2000x1136.png | PacketLogger demo output | screenshot | `tc.md` (optional) |
| 13 | https://mostlynerdless.de/wp-content/uploads/2024/08/network_stack-1.png | Linux network stack with XDP + TC hook points | hand-drawn | `tc.md` (also `xdp.md`) |
| 13 | https://mostlynerdless.de/wp-content/uploads/2024/08/table.png | Accessible `__sk_buff` fields | screenshot (table) | reproduce as markdown in `tc.md` |
| 14 | https://mostlynerdless.de/wp-content/uploads/2024/08/image-1.png | Firewall UI: add block rule | screenshot | `cookbook.md` (optional) |
| 14 | https://mostlynerdless.de/wp-content/uploads/2024/08/image-2.png | Firewall UI: triggering request | screenshot | defer |
| 14 | https://mostlynerdless.de/wp-content/uploads/2024/08/image-3.png | Firewall UI: blocked-packet log | screenshot | defer |
| 14.5 | (only thumbnails) | – | – | defer |
| 15 | https://mostlynerdless.de/wp-content/uploads/2024/09/Slide12-2000x1125.png | Two tasks A and B time-sliced on one CPU | hand-drawn | `sched-ext/index.md` |
| 15 | https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler_dance-2000x1847.png | Per-CPU local DSQs and global DSQ | hand-drawn | `sched-ext/kernel-side.md` |
| 15 | https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler-keynote-2000x553.png | Race condition illustration | hand-drawn | `sched-ext/kernel-side.md` |
| 15 | https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler-keynote2-2000x714.png | Deadlock scenario | hand-drawn | `sched-ext/kernel-side.md` |
| 15 | https://mostlynerdless.de/wp-content/uploads/2024/09/image-1.png | Renaissance benchmark chart | chart | `sched-ext/index.md` (optional) |
| 15 | https://mostlynerdless.de/wp-content/uploads/2024/09/image-2.png | Renaissance benchmark (outlier fix) | chart | defer |
| 16 | https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png | Task-control architecture (Java↔BPF maps↔kernel) | hand-drawn | `sched-ext/userspace.md` |
| 17 | https://mostlynerdless.de/wp-content/uploads/2024/12/lottery_bowl.png | Lottery-bowl analogy for the lottery scheduler | hand-drawn | `sched-ext/cookbook.md` |
| 18 | (photograph only) | – | – | – |
| 19 | https://mostlynerdless.de/wp-content/uploads/2025/02/image-1.png | Deadlock scenario for concurrency-fuzz demo | hand-drawn | `sched-ext/cookbook.md` |
| 19 | https://mostlynerdless.de/wp-content/uploads/2025/02/image-2.png | Task-control scheduler overview | hand-drawn | `sched-ext/cookbook.md` |
| 19 | https://mostlynerdless.de/wp-content/uploads/2025/02/image-3.png | START/RUNNING/SLEEPING state machine | state diagram | `sched-ext/cookbook.md` |
| 19 | https://mostlynerdless.de/wp-content/uploads/2025/02/image-5.png | Producer-consumer example | hand-drawn | `sched-ext/cookbook.md` |
| 20 | https://mostlynerdless.de/wp-content/uploads/2025/03/image.png | Taskclicker scheduler-game GUI | screenshot | `sched-ext/cookbook.md` (optional) |

## 5. Open questions

1. **Broken canonical link in docs/index.md**: the Part 1 URL (`writing-ebpf-programs-in-java-with-hello-ebpf-1-hello-world`) is a 404. Almost certainly a slug the author considered but never used. Should be replaced with `hello-ebpf-developing-ebpf-apps-in-java-1`.
2. **Part 19 URL typo (`helle-ebpf`)**: the canonical published URL is misspelled. Any docs link must preserve the typo. Consider filing a WordPress redirect on the blog side, but for the repo just document it once.
3. **Renamed/removed samples referenced by posts**:
   - Part 2 shows `HelloMap` and `HelloStructMap` — repo now has `HashMapSample`, `MapSample`.
   - Part 3 shows `HelloBuffer` — no equivalent (perf event buffer style not retained; only ring buffer samples exist).
   - Part 8 shows `TypeProcessingSample2` — folded into internal processor modules.
   - Part 14 references `BlockHTTP2` — current repo has `BlockHTTP` and `CGroupBlockHTTPEgress`.
   - Part 20's `Taskclicker` sample is not in `bpf-samples` at all.
   Documentation writers should decide whether to (a) footnote each blog post with "sample has since been renamed to X" or (b) update the blog posts (out of scope for the repo).
4. **Part 15 sample naming drift**: post mentions `FIFOScheduler` and `WeightedScheduler`; the repo's canonical equivalents are `FCFSScheduler` and `WeightedRRSample`. Suggest cross-referencing both names.
5. **README date drift**: README lists Part 1 as "Jan 01, 2024" but the URL and page metadata are Dec 31, 2023; Part 7 is "Mar 22" in README but "Mar 25" on the page. Minor — probably not worth changing unless updating for Parts 17–20 anyway.
6. **README count update**: adding Parts 17, 18, 19, 20 brings the README from 19 to 23 bullet items. Coordinate with the "20-part" phrasing in docs/index.md.

## 6. Related talks

The blog series is complemented by conference talks cataloged in [`research-talks.md`](research-talks.md). Blog posts often have a companion talk (for example, Part 15 pairs with the FOSDEM 2025 "Writing Linux Schedulers in Java" session; the sched_ext strand pairs with LPC 2024/2025 microconference material) — see the cross-link table in `research-talks.md` for the full mapping, and use it alongside this document when picking anchors for the sched-ext and getting-started pages.
