# Research: talks and podcast episodes

This document catalogs talks and podcast episodes that are worth cross-linking
from hello-ebpf's documentation. Its shape mirrors `research-blog-series.md`
(post-by-post inventory + cross-link plan) and `research-scx-docs.md`
(canonical-anchor table). Spec 2 page-authoring tasks will consult it to pick
a "further watching" link per page.

## 1. Summary

- **Total items cataloged: 21.**
  - **Author (Johannes Bechberger) talks: 11** (LPC 2024, eBPF Summit 2024,
    JavaZone 2024, Devoxx BE 2024, Øredev 2024, CPH DevFest 2024, JavaForum
    Malmö / FooCafe 2025, three FOSDEM 2025 talks, JCon Europe 2025, NDC
    Security 2025, p99conf 2025). Plus one adjacent podcast (airhacks.fm).
    Slides for every recent talk live under a single speakerdeck.com/parttimenerd
    account; videos are hosted on the conference's own channel.
  - **Tech Over Tea episodes on eBPF / sched_ext: 1 full episode** (#210, David
    Vernet, Mar 2024, 1h55m). Five short 8–11 min follow-up clips exist on the
    same channel but are all excerpts of #210 — they are listed once under
    "Rejected but worth knowing" so the next researcher doesn't rediscover them.
    No Andrea Righi, Changwoo Min, Jake Hillion, or Emil Tsalapatis episode
    exists on the Tech Over Tea channel as of the scrape date.
  - **sched_ext micro-conferences: 2 (LPC 2024 + LPC 2025).** Between them
    ~18 talks — full tables below. LPC 2023 had no dedicated sched_ext MC (the
    project pre-mainline lived under the Scheduler MC); we skip it.
- **Value tiers** (see §5 for the mapping to hello-ebpf pages):
  - **high** (11): the FOSDEM 2025 sched_ext-and-C talk, the eBPF Summit 2024
    keynote, the LPC 2024 hello-ebpf talk, the JavaPro 2025 hello-ebpf talk,
    the FOSDEM 2025 concurrency-testing talk, the p99conf 2025 concurrency-
    testing talk, the FooCafe "Sound of Scheduling" talk, David Vernet's LPC
    2024 status-and-plans talk, Andrea Righi's LPC 2024 user-space framework
    talk, Emil Tsalapatis's LPC 2025 arena-based data structures talk, and
    Tech Over Tea #210.
  - **medium** (7): the four JavaZone/Devoxx/Øredev/CPH firewall talks (they
    all cover the same content — pick one), NDC Security 2025 firewall, the
    Changwoo Min LPC 2024 Steam Deck talk, Jake Hillion's LPC 2025 scx_chaos
    talk (companion to hello-ebpf's ChaosScheduler).
  - **low** (3): airhacks.fm ep on Java + eBPF (early context, superseded by
    later talks); LPC 2024 "Shipping sched-ext" roundtable and "Underground
    culture around custom CPU schedulers" (both distro-facing, not code-facing).
- **Top 5 talks to cross-link:**
  1. FOSDEM 2025, "Writing a Minimal Scheduler with eBPF, sched_ext, and C"
     (author) — pairs with `sched-ext/kernel-side.md` as the C counterpart to
     hello-ebpf's Java scheduler tutorial.
  2. eBPF Summit 2024 keynote, "Writing a Linux scheduler in Java with eBPF"
     (author) — canonical "why this project exists" video for
     `sched-ext/index.md`.
  3. LPC 2024, "hello-ebpf: Writing eBPF programs directly in Java" (author,
     eBPF Track, 30 min, slides + video) — authoritative overview for `index.md`
     or `getting-started/how-it-works.md`.
  4. LPC 2024, "The current status and future potential of sched_ext" (David
     Vernet) — canonical upstream framing for `sched-ext/index.md`.
  5. FOSDEM 2025, "Concurrency Testing using Custom Linux Schedulers" (author,
     with slides + video) — companion for `sched-ext/cookbook.md`
     ChaosScheduler section.

## 2. Author's talks

Order: newest first. All slide decks are at speakerdeck.com/parttimenerd
unless otherwise noted; videos are at the conference's own channel.

### p99conf 2025 — Concurrency Testing using Custom Linux Schedulers

- **Event + date:** p99conf online, Nov 13, 2025 (co-authored with Jake Hillion,
  Meta).
- **Slides:** https://speakerdeck.com/parttimenerd/concurrency-testing-using-custom-linux-schedulers-p99conf
- **Video:** not yet posted publicly at scrape time; p99conf typically publishes
  recordings ~2 weeks after the event on their YouTube channel.
- **Abstract:** New features of the Linux kernel allow developing custom
  schedulers; the talk shows how to write a basic scheduler and use it to fuzz
  for concurrency bugs or optimize for specific workloads.
- **Topic keywords:** concurrency, fuzzing, chaos, ChaosScheduler, scx_chaos.
- **Suggested cross-link target:** `sched-ext/cookbook.md`.

### JCon Europe 2025 — hello-ebpf: Writing eBPF Programs Directly in Java

- **Event + date:** JCon Europe (online), May 12–15, 2025. Also delivered at
  jPrime and other Java events in 2025.
- **Slides:** https://speakerdeck.com/parttimenerd/hello-ebpf-writing-ebpf-programs-directly-in-java-6e325b19-2c79-45cc-9b88-d938978ff5f2
  (May 14, 2025).
- **Video (JAVAPRO channel):** https://www.youtube.com/watch?v=j1KoSaA-6PI
  (published 2025-08-05, 40 min). Note the channel is "JAVAPRO", not JCon.
- **Duration:** 40 min.
- **Abstract:** While eBPF libraries exist for Rust and Go, none exist for Java.
  The talk shows hello-ebpf's technology, its use, and how to implement a basic
  packet filter and a simple Linux scheduler without writing a single line of C.
- **Topic keywords:** overview, packet filter, scheduler, XDP, sched_ext,
  compiler plugin, annotation processor.
- **Suggested cross-link target:** `index.md` (project landing) and
  `getting-started/how-it-works.md`.

### GPN23 — Sound of Scheduling: Writing Linux Schedulers in Java with eBPF

- **Event + date:** Gulaschprogrammiernacht (GPN23), Karlsruhe, Jun 19–22, 2025.
  Prior showings: JUG Karlsruhe (May 7, 2025), FooCafe Java Forum Malmö (Jan 20,
  2025).
- **Slides:** https://speakerdeck.com/parttimenerd/sound-of-scheduling-writing-linux-schedulers-in-java-with-ebpf
  (dated Feb 5, 2025 for the Malmö version).
- **Video (FooCafe channel, Malmö version):** https://www.youtube.com/watch?v=ihAGd8GN90w
  (published 2025-05-05, 66 min).
- **Duration:** ~60–66 min depending on venue.
- **Abstract:** A custom scheduler maps each running process to a musical note,
  making system activity audible; a MIDI keyboard controls the scheduler live.
  Covers eBPF basics, sched_ext, and hello-ebpf's Java-only scheduler workflow.
- **Topic keywords:** scheduler, sched_ext, live demo, playful example,
  taskclicker.
- **Suggested cross-link target:** `sched-ext/cookbook.md` (companion for Part
  20 blog post — "A scheduler controlled by sound").

### NDC Security 2025 — Building a lightning fast Firewall with Java & eBPF

- **Event + date:** NDC Security, Oslo, Jan 2025.
- **Slides:** re-use of the JavaZone 2024 deck below.
- **Video (NDC Conferences channel):** https://www.youtube.com/watch?v=16Rv7IWGoDk
  (published 2025-03-26, 47 min). Solo talk (no Aboullaite co-presenter for this
  security-track version).
- **Duration:** 47 min.
- **Abstract:** eBPF-powered firewall with a Spring Boot web UI, XDP + TC
  hooks, and userspace-managed rule maps. Security-track framing.
- **Topic keywords:** firewall, XDP, TC, Spring Boot, security.
- **Suggested cross-link target:** `cookbook.md` (feature-length firewall
  example). Secondary link from `xdp.md` and `tc.md`.

### FOSDEM 2025 (three talks, Feb 1, 2025)

Speaker page: https://archive.fosdem.org/2025/schedule/speaker/johannes_bechberger/

#### FOSDEM 2025 — Writing a Minimal Scheduler with eBPF, sched_ext, and C

- **Track:** eBPF DevRoom.
- **Event page:** https://archive.fosdem.org/2025/schedule/event/fosdem-2025-4458-writing-a-minimal-scheduler-with-ebpf-schedext-and-c/
- **Slides (FOSDEM archive):** https://archive.fosdem.org/2025/events/attachments/fosdem-2025-4458-writing-a-minimal-scheduler-with-ebpf-schedext-and-c/slides/238306/fosdem25_cV753lO.pdf
  (also at speakerdeck.com/parttimenerd/writing-a-minimal-scheduler-with-ebpf-sched-ext-and-c).
- **Video (FOSDEM mirror):** https://video.fosdem.org/2025/k4201/fosdem-2025-4458-writing-a-minimal-scheduler-with-ebpf-schedext-and-c.mp4
- **Duration:** 20 min (18:20–18:40).
- **Abstract:** Develop a basic FIFO scheduler in C on top of sched_ext to give
  a hands-on intro to custom scheduling. Deliberately uses C rather than
  hello-ebpf so the audience can see what the Java layer is generating.
- **Topic keywords:** minimal scheduler, C reference, sched_ext, FIFO, teaching.
- **Suggested cross-link target:** `sched-ext/kernel-side.md` — this is the
  clearest side-by-side C companion to hello-ebpf's Java scheduler tutorial.
  Also useful from `sched-ext/index.md` as "what does the C version look like".

#### FOSDEM 2025 — Concurrency Testing using Custom Linux Schedulers

- **Track:** Testing and Continuous Delivery DevRoom.
- **Event page:** https://archive.fosdem.org/2025/schedule/event/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers/
- **Slides:** https://archive.fosdem.org/2025/events/attachments/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers/slides/237928/fosdem25_5gMVToG.pdf
- **Video:** https://video.fosdem.org/2025/ud6215/fosdem-2025-4489-concurrency-testing-using-custom-linux-schedulers.mp4
- **Duration:** 25 min (12:20–12:45).
- **Abstract:** Use a custom scheduler to pseudo-randomly pause/resume threads
  to expose concurrency bugs — a companion to blog Part 19.
- **Topic keywords:** concurrency, fuzzing, ChaosScheduler, deadlocks, race
  conditions.
- **Suggested cross-link target:** `sched-ext/cookbook.md` (ChaosScheduler
  section).

#### FOSDEM 2025 — Advancing Java Profiling with JFR, eBPF and user context

- **Track:** Free Java DevRoom.
- **Event page:** https://archive.fosdem.org/2025/schedule/event/fosdem-2025-4848-advancing-java-profiling-achieving-precision-and-stability-with-jfr-ebpf-and-user-context/
- **Duration:** 25 min (17:30–17:55).
- **Abstract:** How eBPF-based profiling complements JFR; the JDK 25 CPU-time
  profiler. **Only tangentially eBPF+Java; not a hello-ebpf demo talk.**
- **Topic keywords:** profiling, JFR, JDK 25, CPU-time profiler.
- **Suggested cross-link target:** none — profiling is out of scope for
  hello-ebpf docs. Included here for completeness only; consider omitting from
  the "further watching" set.

### JavaZone 2024 — Building a Lightning Fast Firewall with Java & eBPF

- **Event + date:** JavaZone 2024, Oslo, Sep 4–5, 2024. Co-presented with
  Mohammed Aboullaite.
- **Slides:** https://speakerdeck.com/parttimenerd/building-a-lightning-fast-firewall-with-java-and-ebpf-javazone-2024
  (Sep 2, 2024).
- **Video (Vimeo, JavaZone channel):** https://vimeo.com/1006550543
- **Duration:** ~50 min.
- **Abstract:** eBPF is the cutting-edge cloud-native tech; this talk builds a
  firewall on top of hello-ebpf, combining XDP (ingress) and TC (egress) with
  a Spring Boot management UI.
- **Topic keywords:** firewall, XDP, TC, Spring Boot.
- **Suggested cross-link target:** `cookbook.md` (feature-length firewall
  example). Prefer this recording over NDC Security 2025 for architectural
  detail; prefer NDC Security 2025 for the security-audience framing.

### eBPF Summit 2024 — Writing a Linux scheduler in Java with eBPF (keynote)

- **Event + date:** eBPF Summit 2024, Sep 11–12, 2024.
- **Slides:** https://speakerdeck.com/parttimenerd/writing-a-linux-scheduler-in-java-with-ebpf
  (Sep 10, 2024). Deck description says "Keynote at eBPF Summit 2024."
- **Video (eBPF & Cilium Community channel):** https://www.youtube.com/watch?v=JWwX3uCEPO8
  (published 2024-09-12, 10 min).
- **Duration:** 10 min (keynote lightning talk).
- **Abstract:** sched_ext lets you write a Linux scheduler with eBPF; hello-ebpf
  makes it accessible to Java developers.
- **Topic keywords:** sched_ext, keynote, project pitch.
- **Suggested cross-link target:** `sched-ext/index.md` — the shortest and
  crispest "why hello-ebpf" pitch on record. Also cross-link from `index.md`.

### LPC 2024 — hello-ebpf: Writing eBPF programs directly in Java

- **Event + date:** Linux Plumbers Conference 2024, Vienna, Sep 20, 2024, 18:00,
  Hall N1. eBPF Track (not the sched_ext MC — worth noting for citation
  accuracy).
- **Contribution page:** https://lpc.events/event/18/contributions/1951/
- **Slides:** https://lpc.events/event/18/contributions/1951/attachments/1382/3392/slides.pdf
- **Video:** https://www.youtube.com/watch?v=bWs5GHYpYxg
- **Duration:** 30 min.
- **Abstract:** Same as JCon Europe 2025 (both descend from a shared abstract);
  this is the first LPC-track appearance of the project.
- **Topic keywords:** LPC, overview, packet filter, scheduler.
- **Suggested cross-link target:** `getting-started/how-it-works.md` or
  `architecture/plugin.md` — the LPC crowd asked deeper technology questions
  than the JCon crowd, so the Q&A section is the most valuable part.

### Øredev 2024 — Write your own Firewall with Java & eBPF

- **Event + date:** Øredev, Malmö, Nov 2024. Co-presented with Aboullaite.
- **Video (Øredev channel):** https://www.youtube.com/watch?v=fhioB5DSh14
  (published 2024-11-24, 41 min).
- **Duration:** 41 min.
- **Abstract:** Firewall talk, Nordic-audience framing.
- **Suggested cross-link target:** none primary — JavaZone 2024 and NDC 2025
  cover the same content with more archival stability. Listed here so the next
  researcher knows it exists.

### CPH DevFest 2024 — Build a lightning fast Firewall with Java & eBPF

- **Event + date:** Copenhagen Developers Festival, Aug 29–30, 2024. Solo.
- **Video (NDC/CPH channel):** https://www.youtube.com/watch?v=WYwHiDyMK68
  (published 2024-12-22, 58 min).
- **Duration:** 58 min — the longest form of the firewall talk.
- **Suggested cross-link target:** `cookbook.md` when a longer explanation is
  desired; otherwise deferred to JavaZone 2024.

### Devoxx Belgium 2024 — Building a Lightning Fast Firewall with Java & eBPF

- **Event + date:** Devoxx BE, Antwerp, Oct 7–11, 2024. Co-presented with
  Aboullaite.
- **Video (Devoxx channel):** https://www.youtube.com/watch?v=bbvDK4U9cqI
  (published 2024-10-10, 52 min).
- **Duration:** 52 min.
- **Suggested cross-link target:** same as JavaZone/CPH/Øredev — pick one.
  Devoxx has the largest audience reach for a Java-community reader.

### airhacks.fm — Java and eBPF (adjacent podcast, not Tech Over Tea)

- **Show + date:** Adam Bien's airhacks.fm, Feb 11, 2024. This is the earliest
  long-form recording of Bechberger discussing hello-ebpf; predates all
  conference talks.
- **Video:** https://www.youtube.com/watch?v=DpazifWgcG0 (57 min).
- **Suggested cross-link target:** `index.md` as an "origin story" pointer.
  Value tier low because the technology has evolved substantially since Feb
  2024 (all libbcc, no compiler plugin yet).

## 3. Tech Over Tea episodes

### #210 — David Vernet, Linux Kernel Scheduler Developer

- **Show + date:** Tech Over Tea (Brodie Robertson), Mar 8, 2024.
- **URL:** https://www.youtube.com/watch?v=Ta0imAIz31M
- **Duration:** 1h55m (PT115M19S).
- **Abstract:** David Vernet, then at Meta and the primary sched_ext
  maintainer, walks through kernel scheduling, sched_ext's design and status,
  and the pragmatics of upstream Linux development.
- **Topic keywords:** sched_ext, kernel process, Meta production use, upstream.
- **Suggested cross-link target:** `sched-ext/index.md` — the canonical
  "long-form intro to what sched_ext is and why it exists" resource. Pair
  with Vernet's LPC 2024 talk (below) for the technical follow-up.

No other Tech Over Tea episode covers eBPF or sched_ext in depth as of the
scrape date. Andrea Righi, Changwoo Min, and Jake Hillion have not appeared on
the show. Five short clips (`eqJ_cj0qB28`, `EQjhSEHvrOU`, `1G59pi59oc8`,
`i741N-R-Ucc`, `moibGPgHOD0`) are all 8–11 min excerpts of #210 published Mar
10–14 2024 — see §6.

## 4. sched_ext micro-conferences

### LPC 2024 — Sched-Ext: The BPF extensible scheduler class MC

- **Overview:** https://lpc.events/event/18/sessions/192/ (session ID 192,
  Vienna, Sep 18 2024, Hall L1).

| Title | Speaker(s) | Slides | Video | Suggested cross-link |
| --- | --- | --- | --- | --- |
| The current status and future potential of sched_ext | David Vernet (Meta) | [pdf](https://lpc.events/event/18/contributions/1694/attachments/1515/3188/sched_ext%20status%20and%20plans.pdf) | (slides only; no video linked on the LPC page — likely omitted, since neighbouring talks have video) | `sched-ext/index.md` (canonical upstream framing) |
| Design a user-space framework to implement sched_ext schedulers | Andrea Righi (NVIDIA) | [pdf](https://lpc.events/event/18/contributions/1712/attachments/1397/3156/design-user-space-framework.pdf) | [youtu.be/5ncW9UvxUyU](https://www.youtube.com/watch?v=5ncW9UvxUyU) | `sched-ext/userspace.md` (**primary anchor** — this talk defines scx_rustland_core, which hello-ebpf's userspace runtime mirrors) |
| Using sched_ext to improve frame rates on the SteamDeck | Changwoo Min (Igalia) | [pdf](https://lpc.events/event/18/contributions/1713/attachments/1425/3058/scx_lavd-lpc-mc-24.pdf) | [youtu.be/1FxOszo0H3I](https://www.youtube.com/watch?v=1FxOszo0H3I) | `sched-ext/cookbook.md` (interactive/latency-aware patterns) |
| Optimizing Google Search and beyond with pluggable scheduling | Barret Rhoden + Josh Don (Google) | [pdf](https://lpc.events/event/18/contributions/1687/attachments/1434/3063/LPC%202024_%20Google%20+%20pluggable%20scheduling.pdf) | [youtu.be/D3iWa6OaZF8](https://www.youtube.com/watch?v=D3iWa6OaZF8) | `sched-ext/cookbook.md` (production case study) |
| A case for using para-virtualized scheduling information with sched_ext | Himadri Chhaya-Shailesh (Inria) | [pdf](https://lpc.events/event/18/contributions/1714/attachments/1490/3151/paravirt-schedinfo-for-schedext.pdf) | [youtu.be/w0ysOih7_Q8](https://www.youtube.com/watch?v=w0ysOih7_Q8) | (not linked; VM-specific) |
| Deploying and managing sched_ext schedulers in CachyOS | Peter Jung + Piotr Górski (CachyOS) | [pdf](https://lpc.events/event/18/contributions/1873/attachments/1417/3036/sched-ext%20CachyOS.pdf) | [youtu.be/NiU-1tip4OM](https://www.youtube.com/watch?v=NiU-1tip4OM) | `sched-ext/cookbook.md` (deployment war story) |
| Shipping sched-ext: Linux distributions roundtable | Giovanni Gherdovich (SUSE), et al. | [pdf](https://lpc.events/event/18/contributions/1693/attachments/1480/3130/scx-roundtab-lpc.pdf) | [youtu.be/CXrYCeSePUs](https://www.youtube.com/watch?v=CXrYCeSePUs) | (not linked; distro-facing) |
| "Hey, psst, try this." Underground culture around custom CPU schedulers | Gherdovich, Jung, Górski, Chen, Suzuki, Al Marri | [pdf](https://lpc.events/event/18/contributions/1772/attachments/1518/3191/custom-scheds.pdf) | [youtu.be/A_3NugYJkwQ](https://www.youtube.com/watch?v=A_3NugYJkwQ) | (not linked; historical context) |

Two adjacent LPC 2024 talks live outside the sched_ext MC but are relevant:

- **"Crafting a Linux kernel scheduler that runs in user-space using Rust"** —
  Andrea Righi, LPC 2024 Refereed Track,
  https://lpc.events/event/18/contributions/1723/ — slides
  `crafting-user-space-scheduler-in-rust.pdf`, videos `vul2v-pQnAY` and
  `UK6XX27mK3c`. Longer-form companion to Righi's MC talk. Cross-link from
  `sched-ext/userspace.md`.
- **"Paravirt scheduling with eBPF"** — Joel Fernandes + Vineeth Remanan Pillai
  (Google), https://lpc.events/event/18/contributions/1733/ — slides only,
  `pvsched_lpc24.pdf`. Not linked from hello-ebpf docs.

### LPC 2025 — Sched-Ext: The BPF extensible scheduler class MC

- **Overview:** https://lpc.events/event/19/sessions/229 (session ID 229, Tokyo,
  Dec 11 2025, Hall B3/B4). All talks have slides + YouTube video via
  the standard LPC pipeline.

| Title | Speaker(s) | Slides | Video | Suggested cross-link |
| --- | --- | --- | --- | --- |
| sched_ext: current status and future plans | Andrea Righi (NVIDIA) | [pdf](https://lpc.events/event/19/contributions/2035/attachments/1720/4085/LPC2025_%20sched_ext_%20current%20status%20and%20future%20plans.pdf) | [youtu.be/lQ26nF5Ctv4](https://www.youtube.com/watch?v=lQ26nF5Ctv4) | `sched-ext/index.md` (state-of-the-project, 2025) |
| From Fragmentation to Integration: Enhancing sched_ext BPF Scheduler Interoperability with Linux | Daniel Hodges (Meta) | [pdf](https://lpc.events/event/19/contributions/2037/attachments/1858/4068/LPC2025_slides-2.pdf) | [youtu.be/29khcwouLV8](https://www.youtube.com/watch?v=29khcwouLV8) | `sched-ext/kernel-side.md` (kfunc integration patterns) |
| Can ProxyExec and sched_ext get along? | John Stultz (Google) | [pdf](https://lpc.events/event/19/contributions/2032/attachments/1726/3866/LPC%20ProxyExec%20%26%20SCHED_EXT.pdf) | [youtu.be/Ab65z2klt9w](https://www.youtube.com/watch?v=Ab65z2klt9w) | (not linked; proxy-execution edge case) |
| scx_chaos: Pushing the sched_ext API to schedule badly | Jake Hillion (Meta) | [pdf](https://lpc.events/event/19/contributions/2038/attachments/1912/4092/LPC2025%20scx_chaos.pdf) | [youtu.be/YdP0UE6gGkw](https://www.youtube.com/watch?v=YdP0UE6gGkw) | `sched-ext/cookbook.md` (ChaosScheduler kin — Hillion co-authored the p99conf 2025 talk with Bechberger) |
| Scheduler composability with arena-based data structures | Emil Tsalapatis (Meta) | [pdf](https://lpc.events/event/19/contributions/2036/attachments/1909/4139/Scheduler%20Composability%20with%20Arenas.pdf) | [youtu.be/mNIUvpXlsDg](https://www.youtube.com/watch?v=mNIUvpXlsDg) | `arenas.md` (**primary anchor for the arena-based scheduler pattern** — hello-ebpf's `BPFArena` implements the same pattern) |
| Accelerating AI training fleets with sched_ext | Pat Somaru + Valentin Andrei + Patrick Lu (Meta) | [pdf](https://lpc.events/event/19/contributions/2039/attachments/1872/4121/%5BLPC%5D%20Accelerating_AI_Training_With_Sched_Ext%20v3.pdf) | [youtu.be/9NA2vNEJDLE](https://www.youtube.com/watch?v=9NA2vNEJDLE) | `sched-ext/cookbook.md` (Meta AI production war story) |
| The Current Status and Future Direction of the LAVD Scheduler | Changwoo Min (Igalia) | [pdf](https://lpc.events/event/19/contributions/2033/attachments/1898/4059/The_Current_Status_and_Future_Direction_of_the_LAVD_Scheduler-lpc2025.pdf) | [youtu.be/Rz-T8vtHsXs](https://www.youtube.com/watch?v=Rz-T8vtHsXs) | `sched-ext/userspace.md` (secondary — LAVD comparison) |
| How do we make a Steamdeck scheduler work on large servers | David Dai + Ryan Newton (Meta) | [pdf](https://lpc.events/event/19/contributions/2099/attachments/1875/4020/lpc-2025-lavd-meta.pdf) | [youtu.be/KFItEHbFEwg](https://www.youtube.com/watch?v=KFItEHbFEwg) | (not linked; production scale-up story) |
| Steps Towards a Gaming-Optimized Scheduler | Changwoo Min (Igalia) | [pdf](https://lpc.events/event/19/contributions/2150/attachments/1951/4162/Steps_Towards_a_Gaming_Optimized_Schedule-lpc2025.pdf) | [youtu.be/5F-vQgv4sI0](https://www.youtube.com/watch?v=5F-vQgv4sI0) | (not linked; gaming workload aside) |

### LPC 2023 and earlier

LPC 2023 did not have a dedicated sched_ext microconference. sched_ext content
was scattered across the general Scheduler MC and the BPF track before the
project's mainline landing. If a citation is needed for that period, prefer the
LWN articles referenced in `research-scx-docs.md` §4 over LPC-2023 videos.

## 5. Cross-link plan

Grouped by hello-ebpf page (target-nav from Spec 1 design §6):

- **`index.md`** (project landing): primary — eBPF Summit 2024 keynote (10 min,
  crisp elevator pitch). Secondary — JCon Europe 2025 hello-ebpf talk (40 min,
  full overview).
- **`getting-started/how-it-works.md`**: primary — LPC 2024 hello-ebpf talk
  (30 min, focuses on the compiler-plugin technology).
- **`architecture/plugin.md`**: primary — LPC 2024 hello-ebpf talk (Q&A dives
  into plugin internals). Secondary — JCon Europe 2025 talk (Aug 2025 recording
  reflects the current shape of the plugin).
- **`sched-ext/index.md`**: primary — David Vernet, LPC 2024 "status and plans"
  (upstream framing); Tech Over Tea #210 (long-form intro). Secondary — eBPF
  Summit 2024 keynote (hello-ebpf's take), Andrea Righi LPC 2025 "current
  status" (2025 update).
- **`sched-ext/kernel-side.md`**: primary — FOSDEM 2025 "Writing a Minimal
  Scheduler with eBPF, sched_ext, and C" (Bechberger, C reference matching
  hello-ebpf's Java tutorial). Secondary — Daniel Hodges LPC 2025 "Fragmentation
  to Integration" (kfunc interop).
- **`sched-ext/userspace.md`**: primary — Andrea Righi LPC 2024 "Design a
  user-space framework" (defines scx_rustland_core; hello-ebpf's userspace
  runtime mirrors it). Secondary — Righi's Refereed Track "Crafting a Linux
  kernel scheduler … using Rust" (longer form); Changwoo Min LPC 2025 LAVD
  status.
- **`sched-ext/cookbook.md`**: primary — FOSDEM 2025 "Concurrency Testing"
  (ChaosScheduler); FooCafe "Sound of Scheduling" (taskclicker); Jake Hillion
  LPC 2025 "scx_chaos" (kernel counterpart to ChaosScheduler); Peter Jung LPC
  2024 "CachyOS deployment"; Barret Rhoden LPC 2024 "Google + pluggable
  scheduling". Secondary — p99conf 2025 "Concurrency Testing" (video pending),
  Changwoo Min LPC 2024 SteamDeck.
- **`arenas.md`**: primary — Emil Tsalapatis LPC 2025 "Scheduler composability
  with arena-based data structures" (`BPFArena`'s conceptual reference).
- **`cookbook.md`** (top-level, firewall-flavoured example): primary — JavaZone
  2024 firewall talk (Vimeo, most stable archival copy). Secondary — Devoxx BE
  2024 for larger-audience framing; NDC Security 2025 for security-audience
  framing; CPH DevFest 2024 for the longest-form version (58 min).
- **`xdp.md`**: secondary link to the JavaZone 2024 firewall talk (XDP portion).
- **`tc.md`**: secondary link to the JavaZone 2024 firewall talk (TC portion).

No talk maps to `maps.md`, `global-variables.md`, `tail-calls.md`,
`tracepoints.md`, `kprobes.md`, `uprobes.md`, `lsm.md`, or `profiling.md`. These
pages should rely on the blog series and reference docs; a `Further watching`
section is not warranted.

## 6. Rejected but worth knowing

- **YouTube shorts `eqJ_cj0qB28`, `EQjhSEHvrOU`, `1G59pi59oc8`, `i741N-R-Ucc`,
  `moibGPgHOD0` (Tech Over Tea, Mar 2024).** All are 8–11 minute clips of #210
  (David Vernet). Excluded: linking a clip when the full 1h55m episode is
  available adds no value.
- **Author's non-eBPF talks (JDK 25 CPU-Time Profiler, Debugging Unveiled,
  Instrument to Remove, DIY Python Debugger, etc.).** Excluded: outside the
  hello-ebpf scope even though they share an author.
- **FOSDEM 2025 "Advancing Java Profiling with JFR, eBPF and user context"
  (Bechberger).** Kept in §2 for completeness but marked "no cross-link
  target" — the talk is primarily about JFR, not the hello-ebpf library.
- **Kernel Recipes talks by David Vernet (2023) and Andrea Righi (2025
  "Schedule Recipes").** Already cataloged in `research-scx-docs.md` §4 as scx
  README references — not duplicated here to avoid drift.
- **eBPF Summit non-sched_ext talks.** The Summit is deliberately excluded by
  the brief unless the talk is by the author or covers sched_ext; only the
  author's 10-min keynote made the cut.
- **Academic paper videos (ghOSt, Shenango, Shinjuku).** Already referenced by
  scx OVERVIEW.md — do not duplicate per the brief.
- **JavaLand / ConFoo / VoxxedDays Zürich / GPN23 / PyConDE non-eBPF sessions
  (`instrument-to-remove-*`, `python-3-dot-12-*`, `debugging-unveiled-*`).**
  Author's other topics; not hello-ebpf.
- **LPC 2024 "Paravirt scheduling with eBPF"** (Joel Fernandes) — video
  missing, VM-specific, outside hello-ebpf scope.
- **LPC 2025 "Can ProxyExec and sched_ext get along?"** (John Stultz) — proxy
  execution edge case; useful reference for advanced users but not for docs
  cross-linking.

## 7. Retrieval provenance

All fetches on 2026-07-01.

Successful:

- https://github.com/SAP/SapMachine/wiki/Presentations (author's canonical talk
  list — via WebFetch)
- https://github.com/parttimenerd (pinned repos — via WebFetch)
- https://speakerdeck.com/parttimenerd (index + 7 individual decks — via
  Playwright)
- https://lpc.events/event/18/ + `page/227-microconferences` +
  `timetable/?view=lpc` + 10 contribution pages (LPC 2024 — via Playwright)
- https://lpc.events/event/19/ + `page/247-microconferences` +
  `timetable/?view=lpc` + 9 contribution pages (LPC 2025 — via Playwright)
- https://archive.fosdem.org/2025/schedule/speaker/johannes_bechberger/ + 2
  event pages (FOSDEM 2025 — via Playwright)
- https://vimeo.com/javazone/videos/search:ebpf (JavaZone 2024 video — via
  Playwright)
- https://www.youtube.com/@TechOverTea/search?query=eBPF and `?query=sched_ext`
  and `?query=Andrea+Righi` and `?query=bpf` (Tech Over Tea — via Playwright)
- https://www.youtube.com/results?search_query=%22Johannes+Bechberger%22+hello-ebpf
  (broader video search — via Playwright)
- 14 individual YouTube watch pages for metadata (title, date, duration,
  channel — via Playwright)

Failed / non-existent:

- https://mostlynerdless.de/speaking/ — HTTP 404. The author's personal blog
  does not host a dedicated speaking page; the SAPMachine wiki is the canonical
  list.
- https://mostlynerdless.de/talks/ — redirects to a soft page with no talk
  inventory; not the authoritative source.
- https://archive.fosdem.org/2024/schedule/speaker/johannes_bechberger/ —
  HTTP 404. The author did not speak at FOSDEM 2024.
- https://lpc.events/event/18/sessions/218/ — redirects to LPC 2025 session
  page. The LPC 2024 sched-ext MC session ID is **192**, not 218 as the
  research brief suggested. Corrected inline in §4.
- `speakerdeck.com` and `lpc.events` WebFetch calls were blocked mid-session
  and completed via Playwright instead — same URLs, no data loss.
