# Graphics Catalog — Slides & Blog Posts

This document catalogs all usable diagrams and graphics from Johannes Bechberger's
conference talks and blog series that can be embedded in the hello-ebpf documentation.
Only **diagrams, architecture charts, flow diagrams, and benchmark charts** are listed;
text-only slides, memes, and photos are omitted.

Each entry has a direct image URL, a one-line description, and a suggested target doc page.

---

## How to embed a slide image

Speakerdeck preview images are permanent, public URLs. Embed them directly in Markdown:

```markdown
![Alt text](https://files.speakerdeck.com/presentations/{DECK_ID}/preview_slide_{N}.jpg)
```

Blog images are hosted on `mostlynerdless.de/wp-content/uploads/`. Prefer the canonical
`-2000x…` size where available (1–2 MB JPEG). If the image needs to appear in CI/offline
builds, download it to `docs/assets/blog/` and update `docs/assets/blog/CREDITS.md`.

---

## Talk 1 — Building a Lightning-Fast Firewall with Java and eBPF (NDC Security 2025)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/building-a-lightning-fast-firewall-with-java-and-ebpf-javazone-2024  
**Deck ID:** `6af5d84c05dd4c029585af11d66586fb`

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 20 | [`preview_slide_20.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_20.jpg) | Full eBPF runtime pipeline: User Land (source→compile→bytecode) and Linux Kernel (bpf syscall → Verifier → JIT → hooks) | `getting-started/how-it-works.md` |
| 26 | [`preview_slide_26.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_26.jpg) | XDP hook position: packet arrives at NIC → XDP fires before kernel network stack continues | `xdp.md` |
| 29 | [`preview_slide_29.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_29.jpg) | BPF map data-sharing: BPF Program ↔ BPF Map (key→value) ↔ Userland Program | `maps.md` |
| 32 | [`preview_slide_32.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_32.jpg) | Benchmark chart: packet drop rate (Mpps) for iptables, nftables, Java eBPF firewall, C eBPF firewall | `xdp.md` (XDP performance section) |
| 34 | [`preview_slide_34.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_34.jpg) | hello-ebpf 3-layer arch: User land (Java→C→Bytecode) / Kernel (loaded+attached to hooks) / Hardware | `getting-started/how-it-works.md` |
| 40 | [`preview_slide_40.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_40.jpg) | Brendan Gregg's "Linux Events & BPF support" full hook-point map | `getting-started/how-it-works.md` |
| 46 | [`preview_slide_46.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_46.jpg) | eBPF verifier flow: bytecode → control-flow graph → type checker → range analysis → approved/rejected | `getting-started/how-it-works.md` |
| 48 | [`preview_slide_48.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_48.jpg) | Ring buffer event flow: kernel BPF writes event → ring buffer → userland Java callback reads | `maps.md` (ring buffer section) |
| 60 | [`preview_slide_60.jpg`](https://files.speakerdeck.com/presentations/6af5d84c05dd4c029585af11d66586fb/preview_slide_60.jpg) | Full hello-ebpf architecture overview: annotation processor + compiler plugin + runtime attach flow | `getting-started/how-it-works.md` |

---

## Talk 2 — hello-ebpf: Writing eBPF Programs Directly in Java (short variant)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/hello-ebpf-writing-ebpf-programs-directly-in-java  
**Deck ID:** `192834e4c7c6402ab8a28a920682351c`

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 6 | [`preview_slide_6.jpg`](https://files.speakerdeck.com/presentations/192834e4c7c6402ab8a28a920682351c/preview_slide_6.jpg) | eBPF overview: safe sandboxed programs run in kernel, triggered by events | `getting-started/how-it-works.md` |
| 7 | [`preview_slide_7.jpg`](https://files.speakerdeck.com/presentations/192834e4c7c6402ab8a28a920682351c/preview_slide_7.jpg) | eBPF pipeline: source → compile → bytecode → verifier → JIT → native code in kernel | `getting-started/how-it-works.md` |
| 8 | [`preview_slide_8.jpg`](https://files.speakerdeck.com/presentations/192834e4c7c6402ab8a28a920682351c/preview_slide_8.jpg) | Brendan Gregg's Linux Events & BPF hook map (full, dark background) | `getting-started/how-it-works.md` |
| 12 | [`preview_slide_12.jpg`](https://files.speakerdeck.com/presentations/192834e4c7c6402ab8a28a920682351c/preview_slide_12.jpg) | hello-ebpf 3-layer arch: Java Code → C Code → BPF Bytecode / Kernel / Hardware | `getting-started/how-it-works.md` |
| 16 | [`preview_slide_16.jpg`](https://files.speakerdeck.com/presentations/192834e4c7c6402ab8a28a920682351c/preview_slide_16.jpg) | BPF map types overview table: hash, array, ring buffer, perf event, LRU, prog array | `maps.md` |
| 18 | [`preview_slide_18.jpg`](https://files.speakerdeck.com/presentations/192834e4c7c6402ab8a28a920682351c/preview_slide_18.jpg) | BTF type tree: struct task_struct with nested pointer fields and offsets | `getting-started/how-it-works.md` (CO-RE section) |
| 21 | [`preview_slide_21.jpg`](https://files.speakerdeck.com/presentations/192834e4c7c6402ab8a28a920682351c/preview_slide_21.jpg) | eBPF verifier flow: program graph analysis → safe/rejected decision | `getting-started/how-it-works.md` |
| 26 | [`preview_slide_26.jpg`](https://files.speakerdeck.com/presentations/192834e4c7c6402ab8a28a920682351c/preview_slide_26.jpg) | XDP hook position: packet at NIC → XDP → kernel network stack | `xdp.md` |

---

## Talk 3 — Writing a Linux Scheduler in Java with eBPF (eBPF Summit 2024)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/writing-a-linux-scheduler-in-java-with-ebpf  
**Deck ID:** `23196bda93134fd39a46549087f9965f`

This deck contains a 7-step animated build-up of the CPU time-slicing diagram
(slides 3–10). Use the final frame (slide 10) for a static doc.

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 2 | [`preview_slide_2.jpg`](https://files.speakerdeck.com/presentations/23196bda93134fd39a46549087f9965f/preview_slide_2.jpg) | Process A and B fanning out to CPU 1 and CPU 2 (multi-CPU dispatch overview) | `sched-ext/index.md` |
| 10 | [`preview_slide_10.jpg`](https://files.speakerdeck.com/presentations/23196bda93134fd39a46549087f9965f/preview_slide_10.jpg) | CPU time-slicing: Process A and B alternating on CPU — A-B-A-A-B-A timeline (final frame) | `sched-ext/index.md` |
| 17 | [`preview_slide_17.jpg`](https://files.speakerdeck.com/presentations/23196bda93134fd39a46549087f9965f/preview_slide_17.jpg) | hello-ebpf 3-layer arch adapted for scheduler: Java→C→Bytecode / sched-ext / Hardware | `sched-ext/index.md` |

---

## Talk 4 — Sound of Scheduling: Writing Linux Schedulers in Java with eBPF

**Speakerdeck:** https://speakerdeck.com/parttimenerd/sound-of-scheduling-writing-linux-schedulers-in-java-with-ebpf  
**Deck ID:** `3a45bfdc15384a939b3ead644ea09b40`

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 10 | [`preview_slide_10.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_10.jpg) | Baking analogy for CPU scheduling: Cantucini–Focaccia–Cantucini time-slice timeline | `sched-ext/index.md` (intro) |
| 15 | [`preview_slide_15.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_15.jpg) | Multiple processes fanning out to CPU 1 and CPU 2 (parallel dispatch) | `sched-ext/index.md` |
| 22 | [`preview_slide_22.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_22.jpg) | Process A/B alternating on CPU — time-slicing final frame | `sched-ext/index.md` |
| 40 | [`preview_slide_40.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_40.jpg) | eBPF runtime pipeline (partial build): source → compile → bytecode | `getting-started/how-it-works.md` |
| 45 | [`preview_slide_45.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_45.jpg) | BPF map data-sharing: eBPF Program ↔ BPF Map ↔ Userland Program with sample data | `maps.md` |
| 50 | [`preview_slide_50.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_50.jpg) | eBPF ecosystem wheel: Use Cases / User Space (SDKs + projects) / Kernel Runtime | `getting-started/how-it-works.md` |
| 60 | [`preview_slide_60.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_60.jpg) | Work-stealing queue architecture: Tasks → Global DSQ → Local DSQ (CPU 1) / Local DSQ (CPU 2) | `sched-ext/index.md` or `sched-ext/kernel-side.md` |

---

## Talk 5 — Writing a Minimal Scheduler with eBPF, sched_ext and C (CLT 2025)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/writing-a-minimal-scheduler-with-ebpf-sched-ext-and-c  
**Deck ID:** `833416d3400746568f568b1d2a7ade56`

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 2 | [`preview_slide_2.jpg`](https://files.speakerdeck.com/presentations/833416d3400746568f568b1d2a7ade56/preview_slide_2.jpg) | Task 1/2 fanning out to CPU 1/2 (multi-CPU dispatch concept) | `sched-ext/index.md` |
| 10 | [`preview_slide_10.jpg`](https://files.speakerdeck.com/presentations/833416d3400746568f568b1d2a7ade56/preview_slide_10.jpg) | Task 1-2-1-1-2-1 time-slicing timeline (final frame of animation) | `sched-ext/index.md` |
| 18 | [`preview_slide_18.jpg`](https://files.speakerdeck.com/presentations/833416d3400746568f568b1d2a7ade56/preview_slide_18.jpg) | Intel Xeon die photo annotated "Just two cores / Just one L3 cache" — why CFS was simpler then | `sched-ext/index.md` (background context) |
| 28 | [`preview_slide_28.jpg`](https://files.speakerdeck.com/presentations/833416d3400746568f568b1d2a7ade56/preview_slide_28.jpg) | Full eBPF runtime: User Land dev pipeline + Linux Kernel (syscall → Verifier → JIT → hooks) | `getting-started/how-it-works.md` |

---

## Blog Post Images

### Blog 1 — Hello eBPF: Developing eBPF Apps in Java (Part 1, Dec 2023)

https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`image-20.png`](https://mostlynerdless.de/wp-content/uploads/2023/12/image-20.png) | eBPF ecosystem (dark theme): concentric rings — Use Cases / User Space / Kernel Runtime with project logos | `getting-started/how-it-works.md` |
| [`image-23.png`](https://mostlynerdless.de/wp-content/uploads/2023/12/image-23.png) | eBPF ecosystem (light theme): Use Cases / Projects (Katran, Cilium, Falco) / SDKs / Application / Kernel Runtime | `getting-started/how-it-works.md` |

---

### Blog 11 — BTF and 13,000 Generated Java Classes (Part 11, Jul 2024)

https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`u32_tree-2000x377.png`](https://mostlynerdless.de/wp-content/uploads/2024/07/u32_tree-2000x377.png) | Minimal BTF type tree: TYPEDEF `__u32` → INT `unsigned int` (4 bytes, unsigned encoding) | `getting-started/how-it-works.md` (CO-RE section) |
| [`ethhdr-2000x1111.png`](https://mostlynerdless.de/wp-content/uploads/2024/07/ethhdr-2000x1111.png) | BTF type tree for `ethhdr` struct: 3 members (h_dest, h_source, h_proto) with byte offsets → ARRAY → TYPEDEF → INT hierarchy | `getting-started/how-it-works.md` (CO-RE section) |

---

### Blog 12 — Write Your eBPF Application in Pure Java (Part 12, Jul 2024)

https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`compiler_pipeline-2000x1125.png`](https://mostlynerdless.de/wp-content/uploads/2024/07/compiler_pipeline-2000x1125.png) | **Key diagram.** Full compiler pipeline: Java Code → Annotation Preprocessor → Preprocessed Code → Java Compiler (with AST walking) → generated C → clang → .o bundled in jar | `getting-started/how-it-works.md` *(already embedded)* |

---

### Blog 14 — Building a Lightning-Fast Firewall with Java & eBPF (Part 14, Aug 2024)

https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`image-1.png`](https://mostlynerdless.de/wp-content/uploads/2024/08/image-1.png) | XDP firewall program structure screenshot (code in context) | `xdp.md` or `samples/index.md` |
| [`image-2.png`](https://mostlynerdless.de/wp-content/uploads/2024/08/image-2.png) | Firewall rule API or architecture screenshot | `xdp.md` |
| [`image-3.png`](https://mostlynerdless.de/wp-content/uploads/2024/08/image-3.png) | Performance benchmark chart: iptables vs nftables vs Java eBPF vs C eBPF | `xdp.md` (performance note) |

---

### Blog 15 — Writing a Linux Scheduler in Java with eBPF (Part 15, Sep 2024)

https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`Slide12-2000x1125.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/Slide12-2000x1125.png) | CPU scheduling concept: Process A and B → CPU with A-B-A-A-B-A time-slice timeline | `sched-ext/index.md` |
| [`scheduler-keynote-2000x553.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler-keynote-2000x553.png) | Wide timeline diagram — scheduler interaction or concurrency model | `sched-ext/index.md` |
| [`scheduler-keynote2-2000x714.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler-keynote2-2000x714.png) | Second scheduler architecture view — callback flow or enqueue/dispatch | `sched-ext/callbacks.md` |
| [`scheduler_dance-2000x1847.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler_dance-2000x1847.png) | **"Scheduler dance" sequence diagram.** Kernel ↔ userspace scheduler callback flow: enqueue → dispatch → consume loop with task arrows | `sched-ext/callbacks.md` |
| [`image-1.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/image-1.png) | Benchmark box-plot: Weighted Sample vs Default EEVDF vs FIFO scheduler (compilation time) | `sched-ext/index.md` |
| [`image-2.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/image-2.png) | Benchmark box-plot (second run): same three schedulers, tighter FIFO variance | `sched-ext/index.md` |

---

### Blog 16 — Control Task Scheduling with a Custom Scheduler Written in Java (Part 16, Dec 2024)

https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`task_control_diagram-2000x1680.png`](https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png) | **Task control flow diagram.** Task 1/2 → enqueue → Scheduling Queue (with Task Settings BPF map lookup) → consume → CPU 1/2, with feedback loop | `sched-ext/userspace.md` |

---

### Blog 17 — Writing a Lottery Scheduler in Java with sched_ext (Part 17, Dec 2024)

https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`lottery_bowl.png`](https://mostlynerdless.de/wp-content/uploads/2024/12/lottery_bowl.png) | Lottery bowl illustration: visual metaphor for probabilistic task selection | `sched-ext/index.md` (examples section) |

---

## Summary by Target Doc Page

### `getting-started/how-it-works.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ Already embedded | `compiler_pipeline-2000x1125.png` | Full Java→C→BPF compile pipeline |
| ★★★ Add | Deck `6af5d84c05dd4c029585af11d66586fb` slide 20 | eBPF runtime: user land dev + kernel verify/JIT/attach |
| ★★★ Add | Deck `6af5d84c05dd4c029585af11d66586fb` slide 40 | Brendan Gregg's Linux Events hook map |
| ★★ Add | `ethhdr-2000x1111.png` | BTF type tree for `ethhdr` (CO-RE section) |
| ★★ Add | `u32_tree-2000x377.png` | Minimal BTF type tree for u32 |
| ★★ Add | Deck `192834e4c7c6402ab8a28a920682351c` slide 21 | eBPF verifier flow graph |
| ★ Optional | `image-23.png` (blog 1) | eBPF ecosystem wheel (light theme) |

### `xdp.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ Add | Deck `6af5d84c05dd4c029585af11d66586fb` slide 26 | XDP hook position in network stack |
| ★★ Add | Deck `6af5d84c05dd4c029585af11d66586fb` slide 32 | Benchmark: iptables vs nftables vs Java/C eBPF |

### `maps.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ Add | Deck `6af5d84c05dd4c029585af11d66586fb` slide 29 | BPF map data-sharing diagram |
| ★★ Add | Deck `6af5d84c05dd4c029585af11d66586fb` slide 48 | Ring buffer event flow diagram |
| ★ Optional | Deck `192834e4c7c6402ab8a28a920682351c` slide 16 | BPF map types table |

### `sched-ext/index.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ Add | Deck `23196bda93134fd39a46549087f9965f` slide 10 | CPU time-slicing: A-B-A-A-B-A timeline |
| ★★★ Add | `scheduler_dance-2000x1847.png` | Scheduler callback flow sequence |
| ★★★ Add | `task_control_diagram-2000x1680.png` | Task control + BPF map feedback loop |
| ★★ Add | Deck `3a45bfdc15384a939b3ead644ea09b40` slide 60 | Global DSQ → Local DSQ work-stealing queue |
| ★★ Add | `image-1.png` / `image-2.png` (blog 15) | Benchmark box-plots for schedulers |
| ★ Optional | `Slide12-2000x1125.png` | Same time-slicing diagram (blog version) |
| ★ Optional | `lottery_bowl.png` | Lottery scheduling metaphor |

### `sched-ext/callbacks.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ Add | `scheduler-keynote2-2000x714.png` | Callback invocation flow |

---

## Notes on attribution

All slide images are © Johannes Bechberger. The blog post images are reproduced from
[mostlynerdless.de](https://mostlynerdless.de/blog/) with the author's permission.
When adding images to the docs, add a row to `docs/assets/blog/CREDITS.md`:

```
| filename | https://mostlynerdless.de/wp-content/uploads/... | Blog post N | YYYY-MM-DD |
```

For Speakerdeck slides embedded by direct URL there is nothing to download; just add a
caption crediting the talk title and conference.
