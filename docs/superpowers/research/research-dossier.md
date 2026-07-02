# hello-ebpf strategic dossier

An executive synthesis of the two-session gap-research corpus (13 research documents, cross-referenced below in §9). This is the "one doc to read if you only read one." Every claim traces to a named source doc; no fresh gaps are invented here.

Audience: project lead deciding what the next release cycle looks like. Tone: opinionated. Where two options compete, one wins.

---

## 1. TL;DR

hello-ebpf is the only production-shaped **Java-first** eBPF framework, and it is the only framework in any language whose `@Scheduler` DSL lets a JVM developer write a Linux CPU scheduler as an ordinary Java class. That combination — Java compiler plugin (Java → C) + Panama FFI to libbpf + a working sched_ext surface + real cornerstone samples spanning XDP, TC, LSM, uprobes and schedulers (`research-cornerstone-cross-refs.md`) — is a genuine moat. Nothing in the Rust/Go peer set touches it (`research-gap-catalog-rust-go.md`, `research-aya-deep-dive.md`, `research-cilium-ebpf-deep-dive.md`, `research-libbpf-rs-deep-dive.md`).

But the framework is thin against multi-object realities. The corpus surfaces three structural gaps that individually block most next-tier samples: (a) no feature-probing / graceful degradation surface, so any sample that could run on kernel N-2 fails opaquely (`research-cilium-ebpf-deep-dive.md`); (b) no three-phase open→load→attach lifecycle, so `.rodata` verifier-constants, `set_autoload`, and per-map `max_entries` are unreachable (`research-libbpf-rs-deep-dive.md`); (c) no kprobe.multi/uprobe.multi attach path, so any sample fanning across tens of kernel or libjvm symbols pays N syscalls (`research-gap-catalog-rust-go.md`, `research-gap-designs.md`).

The dossier recommends three strategic bets for the next six months. Bet 1: **@StructOps generalization + arena native data structures** — the biggest ratio of framework delta to samples enabled (unlocks TCP CC, qdisc, in-kernel lists/hashtables/spinlocks) and reuses 90% of the sched_ext machinery (`research-kernel-selftests-deep-dive.md` §1, §5). Bet 2: **the load-time-knobs bundle**: feature-probing + three-phase lifecycle + sleepable `.s` sections + `.rodata` mmap access. Cheap individually, transformative together (`research-cilium-ebpf-deep-dive.md`, `research-libbpf-rs-deep-dive.md`, `research-kernel-selftests-deep-dive.md` §6, §12). Bet 3: **kprobe.multi + uprobe.multi + attach cookies**, per the concrete design in `research-gap-designs.md` §Gap 2 — closes the existing bpf_cookie regression and unlocks fentry.multi.

Three non-goals: no bpftrace-DSL competitor, no AF_XDP userspace stack, no OCI gadget registry. Justifications in §5.

The HotSpot Java unwinder (`research-otel-profiler-deep-dive.md`) is compelling but eleven weeks of work and requires PROG_ARRAY, LPM_TRIE, LRU_HASH, and HASH_OF_MAPS to land first; ship it as a stretch stream, not as one of the top-three bets.

---

## 2. Where hello-ebpf stands today

**What is shipping.** The cornerstone table in `research-cornerstone-cross-refs.md` gives the ground truth: the 10 samples cover the full arc from HelloWorld through XDPPacketFilter, PacketLogger, TailCallDemo, GlobalVariableSample, Firewall, and the sched_ext family (FCFSScheduler, LotteryScheduler). The compiler plugin produces one C file per `@BPF` class and hands it to libbpf. Panama FFI is used throughout — a differentiator noted in `research-blog-series.md` Preamble B and Part 5. Sched_ext support is not a demo; it is a working `@Scheduler`/struct_ops surface with a `UserspaceSchedulerBase` powered by `bpf_for_each_dsq` and `@Lambda` (this is what `research-talks.md` calls the "Sound of Scheduling" body of work at FOSDEM 2025, GPN23, p99conf 2025, JCon Europe 2025).

**What the peers do that we do not.** All four Rust/Go peers converge on the same missing surface: kprobe.multi, uprobe.multi, iterators (`SEC("iter/*")`), sockmap/sockhash, freplace/Extension, ARRAY_OF_MAPS / HASH_OF_MAPS, PERF_EVENT_ARRAY, and feature probing (`research-gap-catalog-rust-go.md`, `research-aya-deep-dive.md`, `research-cilium-ebpf-deep-dive.md`, `research-libbpf-rs-deep-dive.md`). aya alone additionally has aya-log-style structured logging, PerfEventConfig for the full PMU/HW/SW surface, an Extension/freplace concrete API, and richer TC attach with priority/handle/TCX ordering. cilium/ebpf's single largest advantage is its `features` package (`hasProgramType`, `hasHelper`, `hasKprobeMulti`). libbpf-rs's single largest advantage is the three-phase skeleton (SkelBuilder → OpenSkel → Skel) and typed `.rodata`/`.data`/`.bss`/`.kconfig` via mmap.

**Where we lead.** The `@Scheduler` + `UserspaceSchedulerBase` combination is not reproducible in aya, libbpf-rs, cilium/ebpf, or libbpfgo without substantial new machinery. hello-ebpf's JFR emission story (`research-sample-ideas.md` §1–3 and the JavaZone/NDC/FOSDEM firewall talks in `research-talks.md`) has no C or Rust equivalent because only Java can produce a JMC-loadable chunk stream. The compiler plugin's ability to accept ordinary Java control flow and emit correct verifier-friendly C is unique. `research-blog-series.md` Parts 12–14 document the pivot to this model.

**Cornerstone coverage vs the sample-idea backlog.** `research-sample-ideas.md` catalogs 42 sample pitches; roughly two-thirds are shippable today with the existing framework. The other third gates on the same gaps this dossier ranks below — kprobe.multi (samples #16, #29, #30), HASH_OF_MAPS (#33 KatranMiniLb), `bpf_fib_lookup` (#42), LBR / `bpf_get_branch_snapshot` (#40), OCI packaging (#41), USDT (#11, #29), freplace (F3), iterators (F4).

---

## 3. Strategic gaps ranked by impact

Ranking rubric: samples-unlocked × framework-delta-per-unit-work × durability of the moat. Ties broken by whether the gap is on the "load-time knobs" path (multipliers for everything else). Each entry cites the primary source and names cross-refs; content is not re-summarised.

### Gap 1 — @StructOps generalization + arena native data structures  (P0, high impact / small-medium effort)

Primary source: `research-kernel-selftests-deep-dive.md` §1 (arena `bpf_arena_alloc.h` / `_list.h` / `_htab.h` / `_spin_lock.h`) and §5 (struct_ops beyond sched_ext: `bpf_dctcp` TCP CC, `bpf_qdisc_fifo`). Cross-ref: the Emil Tsalapatis LPC 2025 talk in `research-talks.md` §4 anchors the arena data-structure pattern; the existing `@Scheduler` surface is 90% reusable.

The bet: promote `@Scheduler` to a general `@StructOps` annotation family, keep the sched_ext specialisation, and ship the arena list/hashtable/spinlock as ready-to-drop kernel headers plus Java wrappers. This is the single biggest ratio of framework delta to sample surface in the entire corpus, because (a) the plumbing already exists for schedulers, (b) each new struct_ops class (TCP CC, qdisc, HID BPF) is a whole new sample family, and (c) arena data structures are the substrate every non-trivial scheduler will want going forward (`UserspaceScheduler` today rebuilds these Java-side).

Why P0 over Gap 2: this bet doubles hello-ebpf's kernel-side story from "one struct_ops surface" to "the struct_ops surface", and the arena data structures resolve the two arena bugs noted in memory (`project_arena_word_at_bug.md`, `project_arena_prog_association.md`) by giving the framework the same shapes upstream schedulers use.

### Gap 2 — Load-time knobs: feature-probing + three-phase lifecycle + sleepable/.s + rodata mmap  (P0, medium effort, huge multiplier)

Primary sources: `research-cilium-ebpf-deep-dive.md` (feature-probing is the "single most-missing" thing), `research-libbpf-rs-deep-dive.md` §1–2 (three-phase lifecycle and typed rodata/data/bss/kconfig mmap), `research-kernel-selftests-deep-dive.md` §6 (sleepable `.s` sections — trivial addition), §12 (map flags: `NO_PREALLOC`, `NO_COMMON_LRU`).

Bundle these because they share a critical property: **each is small individually, transformative together, and unblocks samples that are otherwise unshippable**. Feature-probing gates any multi-kernel story (right now a sample that uses kprobe.multi silently fails on 5.15). The three-phase lifecycle unlocks `.rodata` verifier constants (dead-code elimination — the whole point), `set_autoload(false)`, and `set_max_entries` bumps at CPU count (`research-libbpf-rs-deep-dive.md` §1 line-by-line). Sleepable `.s` sections open LSM/tracing programs that dereference user memory, which several `research-sample-ideas.md` entries need (HostSslSniffer, JavaHeapDumpTrigger). Map flags matter because `NO_PREALLOC` is required to avoid huge memory allocations on large maps.

Do not split this bundle. Individually each is a "medium" change; together they are the "load-time knobs bundle" and can ship as a single opinionated release theme. Refuses to fit into an M1/M2 split because feature-probing + three-phase share the same open-time entry point.

### Gap 3 — kprobe.multi / uprobe.multi + attach cookies + fentry.multi  (P0, ~3.5 weeks)

Primary source: `research-gap-designs.md` §Gap 2 (concrete design, 3.5 weeks) plus `research-kernel-selftests-deep-dive.md` §11 (fentry.multi/fexit.multi). Cross-ref: `research-gap-catalog-rust-go.md` §"kprobe.multi and uprobe.multi", `research-aya-deep-dive.md` §uprobe symbol resolution + AbsoluteOffset.

This is not "another attach type." The multi variants collapse N syscalls into one, and the accompanying `bpf_cookie` primitive is the standard way to disambiguate which of the N attachments fired. The existing `bpf_cookie` regression noted in the design doc means we already owe this work. Sample-level payoff is immediate: `research-sample-ideas.md` #16 GcRootScanTimings, #18 JavaMallocInspector, #29 ClassLoadTracer, #30 JniCrossingCounter all need it; #6 HotThreadWatcher and every GC-uprobe sample benefits.

Pick this over Gap 4 (perf event array, 4 weeks) because attach cookies are on the critical path for the profiler work anyway.

### Gap 4 — aya-log-style structured logging framework  (P1, small effort, big DX win)

Primary source: `research-aya-deep-dive.md` §aya-log structured logging. Cross-ref: `research-libbpf-rs-deep-dive.md` §5 BPF streams for the kernel-6.16 primitive underneath.

Every sample in `research-sample-ideas.md` and every existing sample today falls back to `bpf_trace_printk` (a global sink, kernel-log spam) or a bespoke ring buffer with hand-rolled event structs. aya-log lifts this to a typed structured-logging framework. Small effort, high visibility, and a Java-idiomatic wrapper (`log.info("read %d bytes from pid %d", n, pid)` with automatic per-arg encoding) makes hello-ebpf feel considerably more finished than any Rust/Go peer. Optionally back it with `bpf_prog_stream_read` on kernel 6.16+ per `research-libbpf-rs-deep-dive.md` §5.

### Gap 5 — Missing map types: SOCKMAP/SOCKHASH, HASH_OF_MAPS/ARRAY_OF_MAPS, PROG_ARRAY tail-call table, LPM_TRIE/LRU_HASH first-class, PERF_EVENT_ARRAY  (P1, together medium)

Primary sources: `research-gap-catalog-rust-go.md` §"Map-type coverage", `research-gap-catalog-otel-awesome.md` §4b.3 gap #1 (HashOfMaps/ArrayOfMaps wrapper) and §4b.2.11 (perf event array), `research-gap-designs.md` §Gap 1 (Socket-plane full design, 5w) and §Gap 5 (perf-event-array, 4w).

The Katran-style, Cilium-style, and OTel-profiler-style samples all bottleneck here. `research-otel-profiler-deep-dive.md` explicitly names PROG_ARRAY, LPM_TRIE, LRU_HASH, HASH_OF_MAPS, and PERF_EVENT_ARRAY as prerequisites for the HotSpot unwinder. Even without the profiler ambition, HASH_OF_MAPS unlocks the KatranMiniLb sample (`research-sample-ideas.md` #33), PROG_ARRAY unlocks any tail-call dispatcher pattern (already used pedagogically in `TailCallDemo` but not exposed as a first-class typed map).

Prefer PROG_ARRAY + HASH_OF_MAPS + PERF_EVENT_ARRAY over full Socket-plane in the six-month window. The socket-plane story (sk_msg / sk_skb / sock_ops / sockmap / sockhash) is a 5-week design (`research-gap-designs.md` §Gap 1) and requires user-facing L7 abstractions to be worth the effort; defer to a subsequent release.

### Also-rans (P2, called out because they appear repeatedly but are not top-five)

- **BPF iterators (`SEC("iter/*")`)** — `research-gap-catalog-rust-go.md`, `research-gap-designs.md` §Gap 3 (5w). Compelling for "top" replacements and container introspection but no cornerstone sample needs it yet.
- **HotSpot Java unwinder** — `research-otel-profiler-deep-dive.md` (956 LOC in `hotspot_tracer.ebpf.c`, plus tracemgmt.h and interpreter offset injection). Eleven weeks minimum; gated on Gap 5. Ship as a stretch stream, not a top bet.
- **DWARF-typed uprobe args (`@Arg("pathname")`)** — `research-bpftrace-deep-dive.md` §3. Big ergonomic win but requires build-time DWARF harvest; sequence after Gap 3.
- **freplace / Extension** — `research-aya-deep-dive.md` §Extension/freplace, `research-gap-catalog-rust-go.md`. Enables the F3 LivePatchMyOwnBpf demo but real production users are rare; defer.

---

## 4. Six-month roadmap

Aggressive but achievable if the team writes off documentation debt in parallel. The compaction principle: bundle related work behind release themes rather than shipping 15 dot-releases.

### Milestone M1 (weeks 1–5): The load-time-knobs release

Ship Gap 2 as a single opinionated theme. Include:

- `Features` class covering `hasProgramType`, `hasHelper`, `hasKprobeMulti`, `hasIsaV3`, `kfuncExists("...")`. Cross-refs `research-cilium-ebpf-deep-dive.md` and `research-bpftrace-deep-dive.md` §Stdlib `kfunc.bt`.
- Three-phase lifecycle: `BPFProgram.openBuilder().open() -> OpenBPFProgram.load() -> BPFProgram`. Expose `programs().<name>().setAutoload(false)`, `maps().<name>().setMaxEntries(n)`, `rodata().<field>().set(v)`. Per `research-libbpf-rs-deep-dive.md` §1–2.
- `.rodata` / `.data` / `.bss` / `.kconfig` typed access with mmap-backed I/O (no syscall per get/set). Per `research-libbpf-rs-deep-dive.md` §2.
- Sleepable `.s` section suffix support. Per `research-kernel-selftests-deep-dive.md` §6 and `research-aya-deep-dive.md` §sleepable.
- `@BPFMapDefinition(flags = NO_PREALLOC | NO_COMMON_LRU)` first-class. Per `research-kernel-selftests-deep-dive.md` §12.

Success criteria: any existing sample can add `.rodata` constants and get dead-code elimination; any sample can query `Features.hasKprobeMulti()` and pick a fallback path.

### Milestone M2 (weeks 6–9): The multi-attach release

Ship Gap 3 per `research-gap-designs.md` §Gap 2. Include:

- `@KProbe.Multi("tcp_*")`, `@UProbe.Multi("libjvm.so:G1CollectedHeap*")` glob attach.
- `@AttachCookie` parameter binding on the probe handler.
- fentry.multi / fexit.multi (`research-kernel-selftests-deep-dive.md` §11).
- Symbol-resolver interface for ksym/usym stack lookup (`research-bpftrace-deep-dive.md` §2). Wire into the existing `StackSymbolizer`.
- Sample: convert `research-sample-ideas.md` #16 GcRootScanTimings to demonstrate multi-attach + cookies.

Success criteria: the ChaosScheduler-adjacent JVM-uprobe samples (#16, #29, #30) shrink from N attach setups to one, and the resulting sample code is 2× shorter.

### Milestone M3 (weeks 10–15): The struct_ops release

Ship Gap 1. Include:

- Promote `@Scheduler` → `@StructOps("<kind>")` with `sched_ext` as the default preset. Keep the existing `@Scheduler` alias for source compatibility.
- Add `@TcpCongestionControl` (targets `bpf_dctcp`-shaped programs) and `@Qdisc` (targets `bpf_qdisc_fifo`-shaped programs) as concrete presets. Per `research-kernel-selftests-deep-dive.md` §5.
- Arena data structures: `BPFArenaList<T>`, `BPFArenaHashMap<K,V>`, `BPFArenaSpinLock`. Ship the kernel headers verbatim from selftests and expose Java wrappers. Per `research-kernel-selftests-deep-dive.md` §1. Fixes the two arena bugs in memory.
- One sample per preset: `LiveTcpCcSample`, `PriorityFifoQdiscSample`.

Success criteria: a JVM developer can write a TCP congestion controller in Java in <200 lines that competes with `bpf_dctcp`. Positioning payoff: hello-ebpf is now "the framework where Java devs write kernel-side pluggable classes", not just "the Java scheduler framework".

### Milestone M4 (weeks 16–20): The map-types + logging release

Ship the P1 half of Gap 5 (PROG_ARRAY typed, HASH_OF_MAPS, PERF_EVENT_ARRAY, LPM_TRIE and LRU_HASH first-class wrappers) plus Gap 4 (structured logging framework). Per `research-gap-catalog-otel-awesome.md` §4b.3 gap #1 and `research-aya-deep-dive.md`.

Samples: KatranMiniLb (`research-sample-ideas.md` #33), NettyLockDeadlockMap (#38), a logging-showcase sample.

Success criteria: hello-ebpf can express the load-balancer pattern (root XDP → tail-call → per-VIP HASH_OF_MAPS) in a compilable ~250-line sample.

### Milestone M5 (weeks 21–26): The stretch stream — HotSpot profiler foundations

Do not attempt the full profiler in six months. Do the enabling work per `research-otel-profiler-deep-dive.md`:

- Interpreter offset injection: build a Java-side helper that walks `gHotSpotVMStructs` (via `/proc/pid/mem`) and emits a `HotSpotVmStructs` record. Per `research-otel-profiler-deep-dive.md` §"interpreter offset injection is the hard part".
- HASH_OF_MAPS bucketed by size (needed for the native DWARF path) — already shipped in M4.
- A minimal `@PerfEventProfiler(freq = 99)` annotation that emits stack traces without user-frame unwinding.
- Off-CPU sampling (~90 LOC in the OTel profiler) — small, self-contained.

Explicitly not shipping M5: full HotSpot unwinder, native DWARF `.eh_frame` reader, tracemgmt.h port, AOT Java support.

### Release cadence

Ship M1 as 0.2 (breaking: three-phase lifecycle). M2 as 0.3. M3 as 0.4 (breaking: `@Scheduler` alias-only). M4 as 0.5. M5 as 0.6-preview.

Documentation runs in parallel: fix the 20-part blog series citation in `docs/index.md` (per `research-blog-series.md` §2), add the "further watching" cross-links to the sched_ext pages per `research-talks.md` §5, and mirror the four hand-drawn diagrams called out as "strong mirror candidates" (`research-blog-series.md` Parts 2, 4, 5).

---

## 5. Deliberate non-goals

Named because they are seductive and would eat the roadmap. Each is grounded in a source doc.

### Non-goal 1: A bpftrace-DSL competitor

`research-bpftrace-deep-dive.md` opens with the correct positioning: bpftrace is a REPL DSL for one-liners, hello-ebpf is a framework. The aggregation classes (count/sum/hist/lhist/avg/stats/tseries) and symbol resolvers documented in §1 and §2 are legitimate Java-side helpers we may want as opt-in surface. What we will not build is a bpftrace-like DSL entry point (`ebpf -e '...'`), a REPL, or a script language. Every hour spent on those is an hour not spent on `@StructOps`. If the aggregation classes are compelling later, ship them as `Aggregation.*` types on `@BPFMap`-backed structs, not as a DSL layer.

### Non-goal 2: AF_XDP userspace stack

`research-gap-catalog-rust-go.md` and `research-gap-catalog-otel-awesome.md` both mention AF_XDP / XSKMAP. Building a proper Java AF_XDP userspace zero-copy socket stack (with UMEM ring management, fill/completion rings, driver-mode packet steering) is a project unto itself and duplicates work Netty and JNR-Unixsocket are better positioned to do. Ship an XSKMAP wrapper only if a sample demands it; do not offer a `BPFSocket` API. Positioning: hello-ebpf lets you write the XDP program that redirects to XSK, and lets Netty do the userspace side.

### Non-goal 3: OCI gadget registry / inspektor-gadget compatibility

`research-sample-ideas.md` #41 GadgetOciPublisher and `research-gap-catalog-otel-awesome.md` §4b.3 gap #6 both propose OCI packaging. The tempting story is "your Java-authored gadget runs anywhere `ig` runs." Reject for now because (a) inspektor-gadget owns that ecosystem and any hello-ebpf work here duplicates their runner, (b) OCI packaging is Maven plugin work with no framework-level payoff, and (c) it distracts from the struct_ops story where we have a real moat. Revisit if `ig` adopts a public gadget-plugin protocol.

### Additional non-goals worth naming

- **AOT (native-image) single-file distribution** — `research-libbpf-rs-deep-dive.md` §Cross-reference §7 marks this "low priority." The pre-compiled BTF-enabled `.o` files already ship in jars.
- **Full JSON output formatter for ring records** — `research-bpftrace-deep-dive.md` §8 marks it low priority. If a user wants JSON, they write it in Java against the ring-buffer wrapper.
- **BPF static linker** — `research-libbpf-rs-deep-dive.md` §6. Nontrivial ergonomics gap but only matters once someone is building a real library of `@BPF` classes. Not yet.
- **Full USDT support** — `research-gap-catalog-rust-go.md` and multiple `research-sample-ideas.md` samples want it, but the JIT-symbol integration problem is unbounded. Ship uprobe.multi first (M2) and revisit USDT if the JdkTlsSniffer speculative sample (`research-sample-ideas.md` F1) becomes a priority.

---

## 6. Ecosystem positioning

One paragraph per peer. Each pair explains what they do that we don't, and what we do that they can't.

**aya** (`research-aya-deep-dive.md`). Rust-native, no C, closest philosophical peer. They have PerfEventConfig covering the full PMU/HW/SW/breakpoint surface, uprobe symbol resolution with AbsoluteOffset+libname, LoadOptions with `override_global`/`max_entries`/`pin_path`, Extension/freplace, aya-log structured logging, XDP mode selection (Skb/Driver/HW), TC attach with priority/handle/TCX ordering, and sleepable/xdp.frags section suffixes. They do not have a Java compiler plugin, JFR integration, or `@Scheduler`. Position hello-ebpf as: "aya for the JVM ecosystem, plus the scheduler surface aya lacks." Copy the aya-log design in M4 verbatim (attribution warranted).

**libbpf-rs** (`research-libbpf-rs-deep-dive.md`). The most feature-complete BPF binding in any language. Three-phase skeleton, typed `.rodata`/`.data`/`.bss`/`.kconfig` via mmap, full Query API with per-link-type info, BPF streams (kernel 6.16), BPF static linker. They do not have a compiler plugin at all (users write `.bpf.c`), no scheduler surface, no logging framework. Position hello-ebpf as: "libbpf-rs for Java, with Java as the source language, not C." Copy the three-phase lifecycle in M1 wholesale.

**cilium/ebpf** (`research-cilium-ebpf-deep-dive.md`). Go-native, best-in-class feature-probing (`features` package), batch map ops with opaque cursor, per-CPU perf reader, Link.Update/Info/Anchor with mprog ordering, ProgramOptions.LogLevel + auto-grow log buffer + KernelTypes + ExtraRelocationTargets. They do not have a scheduler surface. Position hello-ebpf as: "cilium/ebpf for Java, with `@Scheduler` as the differentiator." Copy the feature-probing surface in M1 verbatim.

**libbpfgo** (`research-gap-catalog-rust-go.md`). Go binding to libbpf, less mature than cilium/ebpf. Nothing they do uniquely; deprioritise as a comparison target.

**bpftrace** (`research-bpftrace-deep-dive.md`). A DSL, not a framework. Non-competitive by design. Steal helpful helpers (symbolizer, aggregation classes) opportunistically; do not steal the paradigm. See non-goal 1.

**inspektor-gadget** (`research-gap-catalog-otel-awesome.md` §4b.2.9, `research-sample-ideas.md` #41). Kubernetes-native BPF gadget runner. They own the OCI-packaged-gadget ecosystem. Position hello-ebpf orthogonally: hello-ebpf is where you *author* gadgets in Java; if inspektor-gadget compatibility becomes worth it, publish via their protocol later. See non-goal 3.

**OTel eBPF profiler** (`research-otel-profiler-deep-dive.md`). Not a peer library — a specific application built on libbpf. They have the HotSpot Java unwinder, native DWARF via userspace-parsed `.eh_frame` with HASH_OF_MAPS bucketed by size, tracer dispatch via PROG_ARRAY tail-call table, tracemgmt.h "profiler OS", and off-CPU sampling. Position hello-ebpf as: "the framework in which the Java-side profiler equivalent could be written." Not this cycle; M5 lays foundations only.

**BCC** (`research-blog-series.md` Parts 1–4). Historical. hello-ebpf used libbcc via Panama in the early parts, then pivoted to libbpf in Part 5. Not a strategic target.

---

## 7. Sample-program story arc

The corpus already has the red-line thread: `research-cornerstone-cross-refs.md` maps 10 samples to the arc **Observe → Stream → Filter → Govern → Compose → Decide → Extend**. The 42-idea backlog in `research-sample-ideas.md` should be pruned to samples that (a) reinforce this arc, (b) have a Java-native angle (JFR, JMX, Spring, JavaFX, JVMTI), and (c) exercise a feature we're shipping in the roadmap.

Recommended additions per milestone:

- **M1 companion**: `RodataConstantsSample` — one 50-line sample showing dead-code elimination via `.rodata`. Cornerstone-worthy because it demonstrates the killer feature of Gap 2.
- **M2 companion**: `MultiUprobeGcTracer` — a rewrite of `research-sample-ideas.md` #16 GcRootScanTimings using `@UProbe.Multi` + `@AttachCookie`. Replaces N-attach glue with one line.
- **M3 companion**: `LiveTcpCcSample` — a Java TCP congestion controller. This is the marquee demo for the whole cycle; write the eBPF Summit / LPC 2026 talk around it. Talks catalog (`research-talks.md`) shows the FOSDEM 2025 scheduler-in-C talk pattern is the right template.
- **M3 companion**: `ArenaListSample` — the arena data-structure story with a live visualisation. Ties directly to Emil Tsalapatis's LPC 2025 talk on arena-based data structures.
- **M4 companion**: `KatranMiniLb` (`research-sample-ideas.md` #33). Load-balancer sample with a Spring Boot admin, HASH_OF_MAPS, PROG_ARRAY tail-calls. This is the sample that says "hello-ebpf can carry production data-plane workloads."
- **M4 companion**: The logging-showcase sample — a rewrite of `LogOpenAt2Calls` using the new structured-logging framework, plus a JFR sink so `logger.info(...)` from BPF-side ends up in JMC.

Explicitly defer: JdkTlsSniffer (F1), NoisyNeighbourAutoBalancer (F2), LivePatchMyOwnBpf (F3), BpfIterTaskTable (F4), AiInfraSchedulerReplica (F5). All flagged as "speculative / far-out" in `research-sample-ideas.md` §3.

Delete from the aspirational backlog: nothing yet — the 42 pitches are all defensible, they just don't all fit six months. Revisit the list after M4.

---

## 8. Risks and uncertainties

**Kernel version fragmentation.** Every high-value gap has a kernel-version floor. kprobe.multi ≥ 5.18, iterators ≥ 5.8 (partial), BPF streams ≥ 6.16, arena ≥ 6.9. `research-cilium-ebpf-deep-dive.md`'s feature-probing is the mitigation, but users on RHEL 9-tier kernels will see fewer samples work. Ship M1 first so the "silent failure → probed graceful degradation" story lands before we introduce features that require newer kernels.

**@StructOps ambition scope creep.** `research-kernel-selftests-deep-dive.md` §5 lists TCP CC, qdisc, HID BPF as struct_ops targets, but each has its own kernel-side quirks. Constrain M3 to TCP CC + qdisc; leave HID BPF for a later cycle. Do not commit to a generic "any struct_ops" surface until we have shipped two concrete presets.

**Compiler-plugin cost per feature.** Every new attach type or map type touches the compiler plugin, the annotation processor, and the runtime. Memory notes `feedback_bpf_jar_shadows_compiler_plugin.md`, `feedback_maven_showwarnings.md`, and `feedback_implementer_framework_drift.md` document real friction. Roadmap milestones should budget 25% of time for plugin infrastructure, not just user-visible API.

**HotSpot Java unwinder cost.** `research-otel-profiler-deep-dive.md` puts the unwinder alone at 956 LOC of C plus 2746 LOC of interpreter-offset-injection Go. Attempting this before Gap 5 lands would sink a quarter. Explicitly gate M5 on M4 completion.

**Documentation debt compounds.** `research-blog-series.md` §2 shows the README and `docs/index.md` are already out of sync (18 vs 20 posts, broken Part 1 URL). Every new feature amplifies this if we do not fix documentation in the same PR.

**Talks pipeline is a leading indicator.** `research-talks.md` documents 11 recent talks. If M3 (struct_ops + arena) lands on time, it becomes the natural eBPF Summit 2026 / LPC 2026 story. If it slips, the story regresses to "another scheduler DSL update."

**Feature-probing false confidence.** Shipping `Features.hasKprobeMulti()` in M1 does not guarantee correctness on every kernel. Selftests coverage (`research-kernel-selftests-deep-dive.md`) is the right test-source but requires infra work to run against multiple kernels.

---

## 9. Appendix: source-doc map

Every claim in this dossier is grounded in one or more of the following. Named docs are the authoritative source; consult them for depth.

- `research-cornerstone-cross-refs.md` — the 10 cornerstone samples, red-line arc, feature-coverage matrix.
- `research-gap-catalog-rust-go.md` — 29 gaps vs Rust/Go peers.
- `research-gap-catalog-otel-awesome.md` — 18 OTel gaps plus 18-repo deep-survey with 10 NEW gaps.
- `research-gap-designs.md` — concrete designs for top-5 gaps with effort estimates.
- `research-aya-deep-dive.md` — 10 aya-specific gaps including aya-log.
- `research-cilium-ebpf-deep-dive.md` — feature-probing, batch map ops, perf reader.
- `research-libbpf-rs-deep-dive.md` — three-phase lifecycle, typed rodata/data/bss/kconfig, Query API, BPF streams, static linker.
- `research-bpftrace-deep-dive.md` — aggregation classes, symbolizer, DWARF-typed args.
- `research-kernel-selftests-deep-dive.md` — arena data structures, struct_ops beyond sched_ext, dynptr, sleepable, iterator kfuncs, may_goto, fentry.multi, map flags, bpf_throw, bpf_wq, crypto/xattr kfuncs, RCU.
- `research-otel-profiler-deep-dive.md` — HotSpot unwinder, native DWARF, PROG_ARRAY tail-call, tracemgmt.h, off-CPU sampling.
- `research-sample-ideas.md` — 42 sample pitches with framework-feature exercised and Java-angle.
- `research-talks.md` — 21 talks + podcasts, cross-link plan for docs pages.
- `research-blog-series.md` — 22 blog posts, reconciliation notes, diagram mirror candidates.

Supporting docs (not deep-read for this dossier): `research-docs-ebpf-io.md`, `research-ebpf-io-diagrams.md`, `research-external-attribution.md`, `research-scx-docs.md`.

---

*This dossier is a decision-support document, not a design spec. Every roadmap milestone will need its own design doc (following the pattern of `research-gap-designs.md`) before implementation begins. The dossier's job is to say "these three and not those seven"; the design docs' job is to say "here is exactly how."*
