# Graphics Catalog — Slides & Blog Posts

This document catalogs all usable diagrams and graphics from Johannes Bechberger's
conference talks and blog series that can be embedded in the hello-ebpf documentation.
Only **diagrams, architecture charts, flow diagrams, and benchmark charts** are listed;
text-only slides, memes, and photos are omitted.

Each entry has a direct image URL, a one-line description, and a suggested target doc page.

> **All deck IDs and slide numbers in this document are verified by actually loading the
> image URL in a browser and screenshotting it. Do not add entries without doing the same.**

---

## How to embed a slide image

Speakerdeck preview images are permanent, public URLs. Embed them directly in Markdown:

```markdown
![Alt text](https://files.speakerdeck.com/presentations/{DECK_ID}/preview_slide_{N}.jpg)
```

Blog images are hosted on `mostlynerdless.de/wp-content/uploads/`. Prefer the canonical
`-2000x…` size where available. If the image needs to appear in CI/offline builds,
download it to `docs/assets/blog/` and update `docs/assets/blog/CREDITS.md`.

---

## Talk 1 — Building a Lightning Fast Firewall with Java & eBPF (JavaZone 2024)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/building-a-lightning-fast-firewall-with-java-and-ebpf-javazone-2024  
**Deck ID:** `6e75aaa3377e4650b6108f49a9241249`  
**Co-presenter:** Mohammed Aboullaite (Spotify). Dated September 2, 2024.

Diagrams verified by visual inspection:

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 10 | [`preview_slide_10.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_10.jpg) | Packet-dropping performance bar chart (Cloudflare data): iptables PREROUTING baseline | `xdp.md` |
| 12 | [`preview_slide_12.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_12.jpg) | Same chart extended with XDP at ~10 Mpps — dramatic speed advantage over iptables | `xdp.md` |
| 14 | [`preview_slide_14.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_14.jpg) | XDP chart with "even faster with offloading" annotation for NIC-offloaded XDP | `xdp.md` |
| 24 | [`preview_slide_24.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_24.jpg) | eBPF compile pipeline: source → bytecode → bpf syscall → verifier | `getting-started/how-it-works.md` |
| 30 | [`preview_slide_30.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_30.jpg) | eBPF Maps: userland and kernel programs both accessing a central Maps store | `maps.md` |
| 32 | [`preview_slide_32.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_32.jpg) | eBPF hooks across the full Linux network stack layers (XDP, TC, socket, etc.) | `getting-started/how-it-works.md` |
| 38 | [`preview_slide_38.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_38.jpg) | eBPF Ecosystem layered stack: Use Cases → Projects → SDKs → Kernel Runtime | `getting-started/how-it-works.md` |
| 50 | [`preview_slide_50.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_50.jpg) | XDP hook position: NIC → XDP (red arrow) before Linux Network Stack → Application | `xdp.md` |
| 54 | [`preview_slide_54.jpg`](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_54.jpg) | hello-ebpf compiler pipeline: Java Code → Annotation Preprocessor → Java Compiler → AST → Plugin → BPF bytecode | `getting-started/how-it-works.md` |

---

## Talk 2 — hello-ebpf: Writing eBPF Programs Directly in Java (LPC 2024)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/hello-ebpf-writing-ebpf-programs-directly-in-java  
**Deck ID:** `fa14b57b593b48b1a48c2767e5177eca`

Diagrams verified by visual inspection:

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 2 | [`preview_slide_2.jpg`](https://files.speakerdeck.com/presentations/fa14b57b593b48b1a48c2767e5177eca/preview_slide_2.jpg) | eBPF Ecosystem layered stack (Use Cases / Projects / SDKs / Kernel Runtime) | `getting-started/how-it-works.md` |
| 26 | [`preview_slide_26.jpg`](https://files.speakerdeck.com/presentations/fa14b57b593b48b1a48c2767e5177eca/preview_slide_26.jpg) | Annotation preprocessor before/after: `GlobalVariable<@Unsigned Integer>` → `u32 count SEC(".data")` | `getting-started/how-it-works.md` |
| 38 | [`preview_slide_38.jpg`](https://files.speakerdeck.com/presentations/fa14b57b593b48b1a48c2767e5177eca/preview_slide_38.jpg) | VMLinux generation pipeline: BTF + Man Pages + Helper Docs → 13k Java Classes / BPFHelpers | `getting-started/how-it-works.md` (CO-RE section) |

---

## Talk 3 — Writing a Linux Scheduler in Java with eBPF (eBPF Summit 2024)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/writing-a-linux-scheduler-in-java-with-ebpf  
**Deck ID:** `23196bda93134fd39a46549087f9965f`

Slides 3–10 are an animated build-up of the CPU time-slicing diagram. Use slide 10 (final frame) in docs.

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 2 | [`preview_slide_2.jpg`](https://files.speakerdeck.com/presentations/23196bda93134fd39a46549087f9965f/preview_slide_2.jpg) | Process A and B fanning out to CPU 1 and CPU 2 (multi-CPU dispatch) | `sched-ext/index.md` |
| 10 | [`preview_slide_10.jpg`](https://files.speakerdeck.com/presentations/23196bda93134fd39a46549087f9965f/preview_slide_10.jpg) | CPU time-slicing: A and B alternating — A-B-A-A-B-A timeline (final frame) | `sched-ext/index.md` |
| 17 | [`preview_slide_17.jpg`](https://files.speakerdeck.com/presentations/23196bda93134fd39a46549087f9965f/preview_slide_17.jpg) | hello-ebpf 3-layer arch adapted for scheduler: Java→C→Bytecode / sched-ext / Hardware | `sched-ext/index.md` |

---

## Talk 4 — Sound of Scheduling: Writing Linux Schedulers in Java with eBPF

**Speakerdeck:** https://speakerdeck.com/parttimenerd/sound-of-scheduling-writing-linux-schedulers-in-java-with-ebpf  
**Deck ID:** `3a45bfdc15384a939b3ead644ea09b40`

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 10 | [`preview_slide_10.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_10.jpg) | Baking analogy for CPU scheduling: Cantucini–Focaccia–Cantucini time-slice timeline | `sched-ext/index.md` |
| 15 | [`preview_slide_15.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_15.jpg) | Multiple processes fanning out to CPU 1 and CPU 2 | `sched-ext/index.md` |
| 22 | [`preview_slide_22.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_22.jpg) | Process A/B time-slicing final frame | `sched-ext/index.md` |
| 45 | [`preview_slide_45.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_45.jpg) | BPF map data-sharing: eBPF Program ↔ BPF Map ↔ Userland Program with sample data | `maps.md` |
| 60 | [`preview_slide_60.jpg`](https://files.speakerdeck.com/presentations/3a45bfdc15384a939b3ead644ea09b40/preview_slide_60.jpg) | Work-stealing queue architecture: Tasks → Global DSQ → Local DSQ (CPU 1) / Local DSQ (CPU 2) | `sched-ext/index.md` or `sched-ext/kernel-side.md` |

---

## Talk 5 — Writing a Minimal Scheduler with eBPF, sched_ext and C (CLT 2025)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/writing-a-minimal-scheduler-with-ebpf-sched-ext-and-c  
**Deck ID:** `833416d3400746568f568b1d2a7ade56`

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 2 | [`preview_slide_2.jpg`](https://files.speakerdeck.com/presentations/833416d3400746568f568b1d2a7ade56/preview_slide_2.jpg) | Task 1/2 fanning out to CPU 1/2 (multi-CPU dispatch concept) | `sched-ext/index.md` |
| 10 | [`preview_slide_10.jpg`](https://files.speakerdeck.com/presentations/833416d3400746568f568b1d2a7ade56/preview_slide_10.jpg) | Task 1-2-1-1-2-1 time-slicing timeline (final frame) | `sched-ext/index.md` |
| 28 | [`preview_slide_28.jpg`](https://files.speakerdeck.com/presentations/833416d3400746568f568b1d2a7ade56/preview_slide_28.jpg) | Full eBPF runtime: User Land dev pipeline + Linux Kernel (syscall → Verifier → JIT → hooks) | `getting-started/how-it-works.md` |

---

## Talk 6 — Concurrency Testing Using Custom Linux Schedulers (p99conf 2025)

**Speakerdeck:** https://speakerdeck.com/parttimenerd/concurrency-testing-using-custom-linux-schedulers-p99conf  
**Deck ID:** `14494d3b0cfe4804b55ff3e0664bc675`

| Slide | Image URL | Description | Suggested page |
|------:|-----------|-------------|----------------|
| 6 | [`preview_slide_6.jpg`](https://files.speakerdeck.com/presentations/14494d3b0cfe4804b55ff3e0664bc675/preview_slide_6.jpg) | CPU0 timeline showing tasks T0/T1/T2 interleaved — motivates deterministic scheduling for concurrency testing | `sched-ext/index.md` |
| 18 | [`preview_slide_18.jpg`](https://files.speakerdeck.com/presentations/14494d3b0cfe4804b55ff3e0664bc675/preview_slide_18.jpg) | Scheduler dance: tasks → Scheduler → Global Queue → Local Queues (CPU1/CPU2) with work-stealing | `sched-ext/index.md` |

---

## Blog Post Images

All blog images are from [mostlynerdless.de](https://mostlynerdless.de/blog/) and are
verified accessible (HTTP 200). Descriptions for blog images marked with `*` are inferred
from surrounding context — load the URL to confirm before embedding.

### Blog 1 — Hello eBPF: Developing eBPF Apps in Java (Part 1, Dec 2023)

https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`image-20.png`](https://mostlynerdless.de/wp-content/uploads/2023/12/image-20.png) | eBPF ecosystem diagram* | `getting-started/how-it-works.md` |
| [`image-23.png`](https://mostlynerdless.de/wp-content/uploads/2023/12/image-23.png) | eBPF ecosystem diagram (light theme)* | `getting-started/how-it-works.md` |

---

### Blog 11 — BTF and 13,000 Generated Java Classes (Part 11, Jul 2024)

https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`u32_tree-2000x377.png`](https://mostlynerdless.de/wp-content/uploads/2024/07/u32_tree-2000x377.png) | BTF type tree for u32: TYPEDEF `__u32` → INT `unsigned int` (4 bytes) | `getting-started/how-it-works.md` (CO-RE section) |
| [`ethhdr-2000x1111.png`](https://mostlynerdless.de/wp-content/uploads/2024/07/ethhdr-2000x1111.png) | BTF type tree for `ethhdr`: 3 members with byte offsets → ARRAY → TYPEDEF → INT | `getting-started/how-it-works.md` (CO-RE section) |

---

### Blog 12 — Write Your eBPF Application in Pure Java (Part 12, Jul 2024)

https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`compiler_pipeline-2000x1125.png`](https://mostlynerdless.de/wp-content/uploads/2024/07/compiler_pipeline-2000x1125.png) | **Key diagram — already embedded.** Full compiler pipeline: Java → Annotation Preprocessor → Java Compiler → generated C → clang → .o in jar | `getting-started/how-it-works.md` *(already embedded)* |

---

### Blog 14 — Building a Lightning-Fast Firewall (Part 14, Aug 2024)

https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`image-1.png`](https://mostlynerdless.de/wp-content/uploads/2024/08/image-1.png) | XDP firewall program screenshot* | `xdp.md` |
| [`image-2.png`](https://mostlynerdless.de/wp-content/uploads/2024/08/image-2.png) | Firewall rule API screenshot* | `xdp.md` |
| [`image-3.png`](https://mostlynerdless.de/wp-content/uploads/2024/08/image-3.png) | Performance benchmark chart: iptables vs nftables vs Java/C eBPF* | `xdp.md` |

---

### Blog 15 — Writing a Linux Scheduler in Java with eBPF (Part 15, Sep 2024)

https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`Slide12-2000x1125.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/Slide12-2000x1125.png) | CPU scheduling concept slide: Process A/B → CPU time-slice timeline | `sched-ext/index.md` |
| [`scheduler-keynote-2000x553.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler-keynote-2000x553.png) | Wide scheduler interaction diagram* | `sched-ext/index.md` |
| [`scheduler-keynote2-2000x714.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler-keynote2-2000x714.png) | Scheduler callback flow diagram* | `sched-ext/callbacks.md` |
| [`scheduler_dance-2000x1847.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler_dance-2000x1847.png) | **Scheduler dance.** Kernel ↔ userspace callback flow: enqueue → dispatch → consume loop | `sched-ext/callbacks.md` |
| [`image-1.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/image-1.png) | Benchmark box-plot: Weighted Sample vs EEVDF vs FIFO scheduler (compilation time) | `sched-ext/index.md` |
| [`image-2.png`](https://mostlynerdless.de/wp-content/uploads/2024/09/image-2.png) | Benchmark box-plot (second run): same three schedulers | `sched-ext/index.md` |

---

### Blog 16 — Control Task Scheduling with a Custom Scheduler (Part 16, Dec 2024)

https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`task_control_diagram-2000x1680.png`](https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png) | **Task control flow.** Task 1/2 → enqueue → Scheduling Queue (BPF map lookup) → consume → CPU 1/2 with feedback loop | `sched-ext/userspace.md` |

---

### Blog 17 — Writing a Lottery Scheduler in Java with sched_ext (Part 17, Dec 2024)

https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/

| Image URL | Description | Suggested page |
|-----------|-------------|----------------|
| [`lottery_bowl.png`](https://mostlynerdless.de/wp-content/uploads/2024/12/lottery_bowl.png) | Lottery bowl illustration: probabilistic task selection metaphor | `sched-ext/index.md` |

---

## Summary by target doc page

### `getting-started/how-it-works.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ already embedded | `compiler_pipeline-2000x1125.png` | Full Java→C→BPF compile pipeline |
| ★★★ | Talk 1 slide 24 | eBPF compile pipeline diagram |
| ★★★ | Talk 1 slide 32 | eBPF hooks across Linux network stack layers |
| ★★★ | Talk 1 slide 54 | hello-ebpf annotation processor + compiler plugin flow |
| ★★ | `ethhdr-2000x1111.png` | BTF type tree (CO-RE section) |
| ★★ | `u32_tree-2000x377.png` | Minimal BTF type tree (CO-RE section) |
| ★★ | Talk 2 slide 26 | Annotation preprocessor before/after expansion |
| ★★ | Talk 2 slide 38 | BTF → 13k Java classes generation pipeline |

### `xdp.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ | Talk 1 slide 50 | XDP position: NIC → XDP before Linux Network Stack |
| ★★★ | Talk 1 slides 10/12/14 | Packet-drop benchmark progression (iptables → XDP) |

### `maps.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ | Talk 1 slide 30 | BPF map data-sharing: BPF Program ↔ Map ↔ Userland |
| ★★ | Talk 4 slide 45 | Same map-sharing diagram, different visual style |

### `sched-ext/index.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ | Talk 3 slide 10 | CPU time-slicing A-B-A-A-B-A timeline |
| ★★★ | Talk 4 slide 60 | Global DSQ → Local DSQ work-stealing queue |
| ★★ | Talk 6 slide 18 | Scheduler dance: tasks → Global Queue → Local Queues |
| ★★ | `image-1.png` / `image-2.png` (blog 15) | Scheduler benchmark box-plots |

### `sched-ext/callbacks.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ | `scheduler_dance-2000x1847.png` | Kernel ↔ userspace callback sequence |
| ★★ | `scheduler-keynote2-2000x714.png` | Callback flow diagram |

### `sched-ext/userspace.md`

| Priority | Image | What it shows |
|----------|-------|---------------|
| ★★★ | `task_control_diagram-2000x1680.png` | Task control + BPF map feedback loop |

---

## Notes on attribution

All slide images are © Johannes Bechberger. Blog post images are reproduced from
[mostlynerdless.de](https://mostlynerdless.de/blog/) with the author's permission.
When downloading a blog image to `docs/assets/blog/`, add a row to `docs/assets/blog/CREDITS.md`:

```
| filename | https://mostlynerdless.de/wp-content/uploads/... | Blog post N | YYYY-MM-DD |
```

For Speakerdeck slides embedded by direct URL, add a caption crediting the talk and conference.
