# hello-ebpf feature ranking: synthesised gap catalogue

Synthesis across 11 research documents under `docs/superpowers/research/`. This document is the authoritative ranked list. Individual research docs remain the sources of truth for detail; this file collapses duplicates, prioritises, and cross-references.

## 0. Method

### Corpus

- `research-gap-catalog-rust-go.md` — 29 gaps distilled from aya, libbpf-rs, cilium-ebpf, libbpfgo.
- `research-gap-catalog-otel-awesome.md` — OTel-profiler gaps, awesome-ebpf sample gaps, §4b deep-dive of 18 repos.
- `research-gap-designs.md` — engineering roadmaps for Gap 1/2/3/4/5.
- `research-aya-deep-dive.md` — 10 fresh gaps from aya-0.13.
- `research-cilium-ebpf-deep-dive.md` — 8 loader-level gaps.
- `research-libbpf-rs-deep-dive.md` — three-phase lifecycle, typed rodata via mmap, streams, static linker.
- `research-bpftrace-deep-dive.md` — DSL ergonomics (aggregation, symbolizer, DWARF args).
- `research-kernel-selftests-deep-dive.md` — kernel primitives (arena, dynptr, kptrs, struct_ops).
- `research-otel-profiler-deep-dive.md` — HotSpot unwinder, DWARF unwinder, off-CPU, tracer dispatch.
- `research-sample-ideas.md` — 42 concrete demo pitches (some gate on unshipped features).
- `research-talks.md` — cross-linking targets, not new features.

### Universe collapsing

The 11 docs raise ~180 distinct atomic gaps; many overlap. Same-feature refinements were folded into a single canonical entry with its cross-refs preserved. Purely per-sample dependencies (e.g. `bpf_fib_lookup` binding needed by XdpFibRouterHeatmap) are only listed if they also surface as gaps in the loader/library catalogs. `research-talks.md` and (for the most part) `research-sample-ideas.md` are consumers of features, not producers of ranked gaps — they inform Section 6 alignment only.

Total ranked entries after collapse: **72**.

### Tier definitions

- **T0 — Foundational (must ship next).** Unblocks ≥3 other T1/T2 items or fixes a live correctness/regression issue. Every T0 has at least one downstream that today has to work around it. Count: **5**.
- **T1 — High-leverage (next 6-12 months).** Directly requested by two or more research docs, each independently useful, each unlocks a discrete category of program/sample. Count: **17**.
- **T2 — Meaningful gap (nice to have).** Wanted by one deep-dive or one sample pitch; adds surface area without unlocking a category. Count: **28**.
- **T3 — Long tail / low priority.** Niche kernel primitive, exotic packaging, or replaceable by a workaround; keep in catalogue but do not staff. Count: **22**.

### Effort scale

- **S** — days. Wrapper class + JNI stub, or annotation-processor tweak.
- **M** — weeks. Compiler-plugin cooperation + verifier-facing C generation + Java API + tests.
- **L** — 1-3 months. New pipeline stage or subsystem (loader phase, userspace state machine).
- **XL** — quarter+. Multi-stage subsystem (profiler, DWARF unwinder, generic struct_ops runtime).

### Ranking rules used

1. Correctness regressions beat features. `attach cookies hard-coded to 0L` (rust-go catalog + gap-designs) is a bug fix, not a feature — T0.
2. When two items are otherwise equal, break by count of downstream unlocks. Example: PROG_ARRAY + `@BPFTailCallTable` (T0) beats HASH_OF_MAPS (T0) beats generic struct_ops (T1) purely by downstream unlock count in the profiler and network gadgets.
3. "Multiple deep-reads independently surface the same feature" is a strong signal — used to promote three-phase lifecycle from T1 to T0.
4. Kernel-primitive support that gates a whole family of programs (iterators, arena data structures) is T1 or T2 based on how many demoable samples it unlocks in `research-sample-ideas.md`.

## 1. Executive top-10

1. **Fix attach-cookie regression + kprobe.multi / uprobe.multi (Gap 2 design).** `BPFProgram.java:711` hardcodes cookie=0L; every documented aya/cilium/libbpf attach-cookie use case (per-attach discrimination, ordering, single-callback fan-in) is broken today. Ship the bug fix alongside `KPROBE.MULTI`/`UPROBE.MULTI` attach types — one call to attach 200 kprobes at 200x lower overhead — because both share the same annotation-processor surface. Sources: `research-gap-catalog-rust-go.md`, `research-gap-designs.md` Gap 2, `research-cilium-ebpf-deep-dive.md`.

2. **Three-phase lifecycle: `SkelBuilder → OpenBPFProgram → BPFProgram`.** Today `BPFProgram.load()` is single-phase; nothing can adjust `max_entries`, disable an unused program via `autoload=false`, rewrite `.rodata`, or set an fentry attach target between open and load. Refactor unlocks four separate T1 features (typed rodata, autoload, dynamic max_entries, attach-target-by-fd). Sources: `research-libbpf-rs-deep-dive.md` §1, `research-aya-deep-dive.md` LoadOptions.

3. **Perf-event-array reader + hotplug-aware attach (Gap 5 design).** No perf sampling profiler works in a container with CPU hotplug today; hello-ebpf's `perf_event` attach uses a static CPU list and lacks a `PerCpuBuffer` reader with Pause/Resume/Deadline/LostSamples semantics. Sources: `research-gap-designs.md` Gap 5, `research-cilium-ebpf-deep-dive.md` §3, `research-gap-catalog-otel-awesome.md` §2.6.

4. **`PROG_ARRAY` + `@BPFTailCallTable`.** OTel profiler needs 8-slot tail-call dispatch (perf → native/HotSpot/interpreter unwinder → send/error); every non-trivial multi-language profiler in the ecosystem uses this pattern. Blocks the entire profiler roadmap (Gap 4). Sources: `research-otel-profiler-deep-dive.md`, `research-gap-designs.md` Gap 4.

5. **Feature-detection API (`Features.has*`).** Every deep-read repeats this: aya, cilium, libbpf-rs, bpftrace, libbpfgo all ship first-class runtime probes (kfunc-exists, program-type support, helper support). hello-ebpf refuses-to-load with a raw verifier error; users have no "is this kernel new enough?" API. Sources: `research-gap-catalog-rust-go.md`, `research-cilium-ebpf-deep-dive.md` §1, `research-bpftrace-deep-dive.md` §9.

6. **Typed `.rodata` / `.bss` / `.kconfig` via mmap.** `GlobalVariable<T>` uses `bpf_map_lookup_elem` (syscall per access) and hardcodes `.data`. No `.rodata` verifier-constants (kills dead-code elimination), no `.kconfig` auto-population from `/proc/config.gz`, no named datasecs. Sources: `research-libbpf-rs-deep-dive.md` §2, `research-aya-deep-dive.md`.

7. **HASH_OF_MAPS / ARRAY_OF_MAPS wrappers.** Blocks OTel-style multi-language native-unwinder (per-exe .eh_frame lookup) and BPFHashOfMaps sample bucket. One of only three "universally listed" gaps across every rust-go tool. Sources: `research-gap-catalog-rust-go.md`, `research-gap-catalog-otel-awesome.md` §4b.3, `research-otel-profiler-deep-dive.md`.

8. **Iterator programs (`iter/task`, `iter/task_vma`, `iter/bpf_map`).** Enables `netstat`/`ps`-in-Java, live map dump without stopping the program, VMA walking for the profiler. Refined by kernel-selftests deep-read: new iter kfuncs (`bpf_iter_task_vma`, `css_task`, `kmem_cache`, `dmabuf`, `num`) further amplify value. Sources: `research-gap-designs.md` Gap 3, `research-gap-catalog-rust-go.md`, `research-kernel-selftests-deep-dive.md` §7.

9. **Socket-plane (sk_msg / sk_skb / sock_ops + SOCKMAP/SOCKHASH).** Cilium's entire dataplane category. hello-ebpf has zero. Gap 1 design covers all four as a coherent subsystem (5 weeks). Sources: `research-gap-designs.md` Gap 1, `research-gap-catalog-rust-go.md`, `research-gap-catalog-otel-awesome.md` §4b.2.5.

10. **Generic `@StructOps` runtime (TCP CC, qdisc, HID-BPF beyond sched_ext).** Compiler plugin already knows how to emit struct_ops layouts for `sched_ext`; kernel selftests show TCP congestion control and qdisc use the same machinery. Small refactor unlocks a large family. Sources: `research-kernel-selftests-deep-dive.md` §3, `research-gap-catalog-rust-go.md`.

## 2. Full ranked catalog

### T0 — Foundational (5)

Each T0 either fixes a live correctness bug or is a prerequisite for ≥3 T1 items.

1. **Attach cookies (fix hard-coded 0L regression + expose `Attach.cookie(long)`).** `BPFProgram.java:711` always passes 0. Blocks every attach-cookie use case listed by aya/cilium/libbpf. Effort **S** (fix) + **M** (surface API). Unlocks: kprobe.multi discrimination, uprobe.multi per-address dispatch, XDP anchor, ordered TCX chains. Sources: `research-gap-catalog-rust-go.md`, `research-gap-designs.md`.

2. **Three-phase lifecycle: `openBuilder() → OpenBPFProgram → BPFProgram.load()`.** Enables set_autoload / set_max_entries / set_pin_path / rewrite `.rodata` before verifier bakes constants. Effort **M**. Unlocks: typed rodata, autoload, dynamic max_entries, attach-target-by-fd for freplace/fentry. Sources: `research-libbpf-rs-deep-dive.md` §1, `research-aya-deep-dive.md`.

3. **`PROG_ARRAY` + `@BPFTailCallTable`.** Kernel-primitive; single map type, ~200 LOC wrapper. Effort **S**. Unlocks: OTel profiler tracer dispatch (Gap 4 whole roadmap), HotSpot unwinder chain, XDP protocol-parser chains. Sources: `research-otel-profiler-deep-dive.md`, `research-gap-designs.md` Gap 4.

4. **HASH_OF_MAPS + ARRAY_OF_MAPS wrappers.** Effort **S-M**. Unlocks: native unwinder (per-exe .eh_frame table), BPFHashOfMaps sample, multi-tenant map partitioning. Sources: `research-gap-catalog-rust-go.md`, `research-gap-catalog-otel-awesome.md` §4b.3, `research-otel-profiler-deep-dive.md`.

5. **Feature-detection API (`Features.hasProgramType(...)`, `Features.hasKfunc(...)`, `Features.hasHelper(...)`).** Effort **M**. Unlocks: graceful degradation everywhere; every deep-read requests this. Sources: `research-gap-catalog-rust-go.md`, `research-cilium-ebpf-deep-dive.md` §1, `research-bpftrace-deep-dive.md` §9 (`kfunc_exist`/`kfunc_allowed` granularity refinement), `research-libbpf-rs-deep-dive.md`.

### T1 — High-leverage (17)

Ordered by unlock count.

6. **`KPROBE.MULTI` / `UPROBE.MULTI` attach.** Effort **M**. Gap 2 design already scoped 3.5w. Sources: `research-gap-designs.md` Gap 2, `research-gap-catalog-rust-go.md`, `research-kernel-selftests-deep-dive.md` §11 (fentry.multi/fexit.multi/kretsyscall extension).

7. **`PerfEventArray` reader** with Pause/Resume/SetDeadline/LostSamples/Overwritable. Effort **M**. Sources: `research-cilium-ebpf-deep-dive.md` §3, `research-gap-designs.md` Gap 5.

8. **Hotplug-aware perf_event_open + `PerfEventConfig` builder.** Effort **M**. Fixes the "extra core appears mid-run, no sampling on it" silent failure. Sources: `research-gap-designs.md` Gap 5, `research-aya-deep-dive.md`, `research-gap-catalog-otel-awesome.md` §2.9.

9. **Iterator programs (`iter/task`, `iter/task_vma`, `iter/bpf_map`, `iter/bpf_prog`, `iter/tcp`, `iter/udp`).** Effort **M-L**. Sources: `research-gap-designs.md` Gap 3, `research-gap-catalog-rust-go.md`, `research-kernel-selftests-deep-dive.md` §7 (new iter types).

10. **Typed `.rodata` / `.bss` / `.kconfig` via mmap + typed `impl.rodata().minUs.set(500)` accessor.** Effort **M**. Requires T0#2 (three-phase). Sources: `research-libbpf-rs-deep-dive.md` §2.

11. **Socket-plane bundle: sk_msg + sk_skb + sock_ops + SOCKMAP + SOCKHASH.** Effort **L** (5w per Gap 1). Sources: `research-gap-designs.md` Gap 1, `research-gap-catalog-rust-go.md`, `research-gap-catalog-otel-awesome.md` §4b.2.5.

12. **Generic `@StructOps` runtime beyond sched_ext (TCP CC, qdisc).** Effort **M**. Sources: `research-kernel-selftests-deep-dive.md` §3, `research-gap-catalog-rust-go.md`.

13. **Aggregation primitives (`Aggregation.Count`/`Sum`/`Hist`/`LHist`/`Avg`/`Stats`/`TSeries` map wrappers).** Effort **M**. Pure Java-side sugar over `BPFPerCpuHashMap`. Sources: `research-bpftrace-deep-dive.md` §1.

14. **Symbolizer (`ksym`/`usym`/`kaddr`/`uaddr`) with `/proc/kallsyms` + per-pid `/proc/PID/maps` caches.** Effort **M**. Sources: `research-bpftrace-deep-dive.md` §2. Prerequisite for readable stack traces.

15. **DWARF-typed uprobe args (`@Arg("pathname")` instead of `Ptr<pt_regs>`).** Effort **L** (build-time DWARF parse + compiler-plugin codegen). Sources: `research-bpftrace-deep-dive.md` §3.

16. **Dynptr full family (`bpf_dynptr_from_mem/skb/xdp/ringbuf`, `read`/`write`/`slice`/`adjust`/`is_null`/`clone`).** Effort **M**. Enables variable-length event marshalling without per-CPU scratch. Sources: `research-kernel-selftests-deep-dive.md` §2.

17. **Batch map ops (`bpf_map_lookup_batch`/`update_batch`/`delete_batch`) with opaque cursor + ENOSPC/ENOENT contract.** Effort **S-M**. Sources: `research-cilium-ebpf-deep-dive.md` §2, `research-gap-catalog-rust-go.md`.

18. **Sleepable `.s` sections + BPF map creation flags (`BPF_F_NO_PREALLOC`, `BPF_F_RDONLY_PROG`, etc.).** Effort **S**. Gates xattr/signature/crypto kfuncs downstream. Sources: `research-aya-deep-dive.md` Gap 8, `research-kernel-selftests-deep-dive.md` §6/§18.

19. **`tp_btf` (BTF-typed tracepoints) attach type.** Effort **S**. Enables typed access to raw-tracepoint args without manual layout knowledge. Sources: `research-gap-catalog-otel-awesome.md` §4b.3 gap #4.

20. **USDT probe support (with libjvm USDT list for HotSpot).** Effort **M**. Sources: `research-gap-catalog-rust-go.md`, `research-sample-ideas.md` sample #15/#31.

21. **BPF streams (`bpf_prog_stream_read`, kernel 6.16 — per-program STDOUT/STDERR).** Effort **S** (50-line JNI). Feature-gate under `Features.hasProgStreams()`. Sources: `research-libbpf-rs-deep-dive.md` §5.

22. **aya-log style structured logging (Level, DisplayHint `{:x}`/`{:i}`/`{:mac}`/`{:p}`).** Effort **L** (three-layer proc-macro-equivalent). Sources: `research-aya-deep-dive.md` Gap 10, `research-gap-catalog-rust-go.md`.

### T2 — Meaningful gap (28)

23. **`freplace` / Extension programs with hot-swap `Link.Update`.** Effort **M**. Sources: `research-aya-deep-dive.md`, `research-cilium-ebpf-deep-dive.md` §5.

24. **TCX attach type + `Anchor` (BeforeLink/AfterLink) for mprog ordering.** Effort **M**. Sources: `research-cilium-ebpf-deep-dive.md` §5, `research-libbpf-rs-deep-dive.md` §7.

25. **netfilter attach with `BPF_F_NETFILTER_IP_DEFRAG`.** Effort **S**. Sources: `research-libbpf-rs-deep-dive.md` §7.

26. **netkit attach.** Effort **S** if TCX shipped. Sources: `research-gap-catalog-rust-go.md`, `research-libbpf-rs-deep-dive.md` §7.

27. **cgroup_sock family (cgroup/sock_create, cgroup/getsockopt, cgroup/setsockopt, sockaddr).** Effort **M**. Sources: `research-gap-catalog-rust-go.md`.

28. **sk_lookup + sk_reuseport (SO_REUSEPORT_SOCKARRAY).** Effort **M**. Sources: `research-gap-catalog-rust-go.md`, `research-gap-catalog-otel-awesome.md` §3.

29. **flow_dissector.** Effort **S**. Sources: `research-gap-catalog-rust-go.md`.

30. **Arena data structures (`bpf_arena_alloc`, `bpf_arena_list`, `bpf_arena_htab`, `bpf_arena_spin_lock`, `bpf_arena_strsearch`, atomics).** Effort **L** (bindings + reference samples). Sources: `research-kernel-selftests-deep-dive.md` §1.

31. **kptrs + `bpf_obj_new`/`bpf_obj_drop`.** Effort **M**. Sources: `research-kernel-selftests-deep-dive.md` §4.

32. **`bpf_list_head` / `bpf_rb_root` kernel-side containers.** Effort **M**. Sources: `research-kernel-selftests-deep-dive.md` §5.

33. **Iterator kfuncs (`bpf_iter_task_vma`, `css_task`, `kmem_cache`, `dmabuf`, `num`).** Effort **S** each. Sources: `research-kernel-selftests-deep-dive.md` §7.

34. **CpuMask kfunc delta (26 more not yet exposed).** Effort **S**. Sources: `research-kernel-selftests-deep-dive.md` §12, plus `feedback_cpumask_reference_leak.md` memory.

35. **Conntrack helpers (`bpf_ct_lookup`, `bpf_ct_insert_entry`, `bpf_skb_ct_set_timeout`, etc.).** Effort **M**. Sources: `research-kernel-selftests-deep-dive.md` §13, `research-gap-catalog-otel-awesome.md` §2.7.

36. **`may_goto` / `can_loop` bounded-loop primitives.** Effort **S**. Sources: `research-kernel-selftests-deep-dive.md` §14.

37. **`bpf_throw` + `bpf_assert_range` (kfunc exceptions).** Effort **S**. Sources: `research-kernel-selftests-deep-dive.md` §15.

38. **DWARF native unwinder (userspace-parsed .eh_frame → per-exe stack-delta HASH_OF_MAPS, 16 size buckets, PC binary search).** Effort **XL**. Depends on T0#4 (HASH_OF_MAPS). Sources: `research-otel-profiler-deep-dive.md`, `research-gap-designs.md` Gap 4 M4.

39. **HotSpot unwinder (gHotSpotVMStructs introspection, hotspot_procs map, CodeBlob segmap).** Effort **XL**. Depends on T0#3 (PROG_ARRAY). Sources: `research-otel-profiler-deep-dive.md`, `research-gap-designs.md` Gap 4 M5.

40. **Off-CPU profiling (sched_switch + finish_task_switch pair).** Effort **L**. Sources: `research-otel-profiler-deep-dive.md`, `research-gap-designs.md` Gap 4 M3, `research-gap-catalog-otel-awesome.md` §2.5.

41. **Build-id keying for binary caches.** Effort **S**. Sources: `research-otel-profiler-deep-dive.md`, `research-gap-catalog-otel-awesome.md` §2.3.

42. **Remote symbolization endpoint (upload build-id → resolved-frames blob).** Effort **M**. Sources: `research-gap-catalog-otel-awesome.md` §2.4, `research-gap-designs.md` Gap 4 M6.

43. **Query API (`bpftool prog/map/link show` in Java) with typed `sealed interface LinkInfo permits KprobeMultiLinkInfo, UprobeMultiLinkInfo, TcxLinkInfo, PerfEventLinkInfo, ...`.** Effort **M**. Sources: `research-libbpf-rs-deep-dive.md` §4, `research-gap-catalog-rust-go.md`.

44. **ProgramInfo `include_xlated_prog_insns` + `include_jited_prog_insns` dumps.** Effort **S**. Sources: `research-libbpf-rs-deep-dive.md` §4, `research-cilium-ebpf-deep-dive.md` §8.

45. **XDP mode (`Skb`/`Driver`/`Hardware`) + `XDP_FLAGS_REPLACE` atomic replace-by-fd.** Effort **S**. Sources: `research-aya-deep-dive.md`, `research-libbpf-rs-deep-dive.md` §7.

46. **TC priority/handle/`TcHook::replace()`/`query()`/`TC_CUSTOM` parent.** Effort **M**. Sources: `research-libbpf-rs-deep-dive.md` §7, `research-aya-deep-dive.md`.

47. **RunOptions richness (Data/DataOut/Context/CPU/Repeat/BatchSize/Benchmark) for `BPF_PROG_TEST_RUN` beyond syscall programs.** Effort **S**. Sources: `research-cilium-ebpf-deep-dive.md` §7, `research-gap-catalog-rust-go.md`.

48. **RCU / preempt guards (`bpf_rcu_read_lock`/`unlock`, `bpf_preempt_disable`/`enable`).** Effort **S**. Sources: `research-kernel-selftests-deep-dive.md` §16.

49. **BPF token (delegated unprivileged loading via `/sys/fs/bpf/*.token`).** Effort **M**. Sources: `research-gap-catalog-rust-go.md`.

50. **Module BTF (attach to non-vmlinux BTF via `ExtraRelocationTargets`).** Effort **S** if `KernelTypes` shipped. Sources: `research-cilium-ebpf-deep-dive.md` §6.

### T3 — Long tail (22)

Brief, one line each. Kept in the catalogue for completeness; do not staff.

51. **LWT (Lightweight Tunnel) programs.** Sources: `research-gap-catalog-rust-go.md`.
52. **`socket_filter` (classic BPF-shaped attach).** Sources: `research-gap-catalog-rust-go.md`.
53. **`lsm_cgroup` per-cgroup LSM.** Sources: `research-gap-catalog-rust-go.md`.
54. **`bpf_get_branch_snapshot` (LBR).** Sources: `research-gap-catalog-otel-awesome.md` §4b.3 gap #9.
55. **`bpf_probe_write_user` (destructive).** Sources: `research-gap-catalog-otel-awesome.md`, `research-bpftrace-deep-dive.md` §9.
56. **`bpf_send_signal`/`bpf_override_return` (destructive).** Sources: `research-gap-catalog-otel-awesome.md` §4b.3, `research-bpftrace-deep-dive.md` §9.
57. **`bpf_wq` deferred-work API.** Sources: `research-kernel-selftests-deep-dive.md` §17.
58. **Crypto kfuncs (`bpf_crypto_ctx_create`, encrypt/decrypt/hash).** Sources: `research-kernel-selftests-deep-dive.md` §19.
59. **xattr / signature kfuncs (`bpf_get_file_xattr`, `bpf_verify_pkcs7_signature`).** Sources: `research-kernel-selftests-deep-dive.md` §19.
60. **BPF static linker (multi-`.o` link with BTF dedup).** Sources: `research-libbpf-rs-deep-dive.md` §6. Explicit non-feature per Section 7 rationale.
61. **OCI-image packaging (`mvn hello-ebpf:publish-gadget` → ORAS artifact).** Sources: `research-gap-catalog-otel-awesome.md` §4b.2.9, `research-sample-ideas.md` #41.
62. **AOT single-file distribution (jlink/native-image bundled runtime).** Sources: `research-bpftrace-deep-dive.md` §7, `research-libbpf-rs-deep-dive.md`.
63. **JSON output formatter for ring-buffer records.** Sources: `research-bpftrace-deep-dive.md` §8.
64. **Spawn-and-trace runner (`BPFRunner.spawnAndTrace(cmd)`).** Sources: `research-bpftrace-deep-dive.md` §6.
65. **Probe glob expansion (`@KProbe("tcp_*")`).** Sources: `research-bpftrace-deep-dive.md` §5.
66. **Verifier log rendering / pretty-printer.** Sources: `research-gap-catalog-otel-awesome.md` §3.
67. **printf directive extensions (`%s`/`%r`/`%p`/`%gr` in trace helper).** Sources: `research-bpftrace-deep-dive.md` §4.
68. **stdlib helpers (`is_err`, `strerror`, `signal_name`, `syscall_name`, `strncmp`, `path`, `join`, `ntop`, `pton`).** Sources: `research-bpftrace-deep-dive.md` §9.
69. **`bpf_fib_lookup` / `bpf_xdp_flow_lookup` kfunc bindings.** Sources: `research-gap-catalog-otel-awesome.md` §4b.3 gap #2, `research-sample-ideas.md` #42.
70. **Utility kfuncs (`bpf_get_kmem_cache`, `bpf_task_from_pid`, `bpf_path_d_path`, `bpf_get_task_exe_file`).** Sources: `research-kernel-selftests-deep-dive.md` §12.
71. **XSKMAP + AF_XDP userspace loop.** Sources: `research-gap-catalog-rust-go.md`, `research-gap-catalog-otel-awesome.md`. Explicit non-feature per Section 7.
72. **Lockdown detection (refuse-to-load with friendly message on integrity/confidentiality mode).** Sources: `research-bpftrace-deep-dive.md` §9.

## 3. Dependency graph

Textual DAG of load-order dependencies. Read left-to-right: `X → Y` means Y depends on X.

```
T0#1 attach-cookies      → T1#6 kprobe.multi/uprobe.multi
                         → T2#24 TCX Anchor
                         → T2#45 XDP replace-by-fd (atomic)

T0#2 three-phase lifecycle → T1#10 typed rodata/kconfig via mmap
                           → T2#23 freplace Link.Update (needs set_attach_target)
                           → T1#8 hotplug-aware perf attach (needs set_ifindex on open)
                           → future set_autoload for optional programs

T0#3 PROG_ARRAY          → T2#39 HotSpot unwinder
                         → T2#38 DWARF native unwinder
                         → T2 profiler chain overall

T0#4 HASH_OF_MAPS         → T2#38 DWARF native unwinder (per-exe .eh_frame table)
                          → sample #42 XdpFibRouterHeatmap (per-interface flow tables)

T0#5 Features.hasX()     → every T1/T2 with a kernel-version gate (T1#21 BPF streams,
                           T2#39 HotSpot unwinder gated on tracepoints, T2#49 BPF token)

T1#7 PerfEventArray reader   → T1#8 hotplug attach (delivers new-CPU add events)
                             → T2#40 off-CPU (sched_switch samples)

T1#9 iterators               → sample "netstat-in-Java", live map dump
                             → T2#42 remote symbolization endpoint (walks task_vma iter)

T1#14 Symbolizer             → T2#38 DWARF native unwinder (needs frame → name)
                             → T2#42 remote symbolization

T1#15 DWARF-typed args       → sample HostSslSniffer, JdkTlsSniffer

T1#20 USDT                    → sample #15 JitCompilationTracer, #29 ClassLoadTracer,
                                #31 JfrLiveTail

T2#40 off-CPU + T2#38 DWARF + T2#39 HotSpot + T1#7 PerfEventArray
                              → OTel-profiler-in-Java (Gap 4 whole roadmap)
```

## 4. Effort-vs-impact matrix

### Big win, small cost (do first)

- **T0#1 attach cookies fix** — S effort, unlocks ordering / discrimination across every attach type. Bug fix.
- **T0#3 PROG_ARRAY** — S effort, unlocks profiler.
- **T0#4 HASH_OF_MAPS** — S-M, unlocks profiler + samples.
- **T1#17 batch map ops** — S-M, huge throughput win.
- **T1#18 sleepable `.s` + map flags** — S, gates crypto/xattr categories.
- **T1#19 tp_btf** — S, cleaner tracepoint code.
- **T1#21 BPF streams** — S, ~50-line JNI stub.
- **T2#44 xlated/jited insns dump** — S, `bpftool prog dump`-in-Java.
- **T2#45 XDP mode + replace-by-fd** — S.
- **T2#48 RCU/preempt guards** — S.

### Big strategic bet (do next)

- **T0#2 three-phase lifecycle** — M, unlocks four T1 features.
- **T0#5 feature-detection** — M, cross-cutting.
- **T1#6 kprobe.multi/uprobe.multi** — M (Gap 2 = 3.5w).
- **T1#7 + T1#8 perf-event-array + hotplug** — M (Gap 5 = 4w).
- **T1#9 iterators** — M-L (Gap 3 = 5w).
- **T1#10 typed rodata** — M.
- **T1#11 socket-plane bundle** — L (Gap 1 = 5w).
- **T1#12 generic StructOps** — M, one bundle unlocks TCP CC + qdisc + HID-BPF.
- **T2#38 + T2#39 + T2#40 profiler triad** — XL (Gap 4 = 11w).

### Cheap polish

- **T1#13 aggregation primitives** — M, pure Java-side sugar; huge DX win per bpftrace deep-read.
- **T1#14 symbolizer** — M, needed anyway for readable stacks.
- **T2#33 iterator kfuncs** — S each, opportunistic.
- **T2#34 cpumask kfunc delta** — S.
- **T2#36 may_goto/can_loop** — S.
- **T2#43 Query API** — M, replaces `bpftool link show`.

### Deferred (T3)

Everything in §2 T3. Keep in the catalogue as a "next-100-issues" backlog, but do not staff. See Section 7 for the explicit non-features.

## 5. What the six deep-reads changed

New entries introduced by the deep-reads beyond the two rust-go / OTel catalogs:

- **libbpf-rs deep-read added:** three-phase lifecycle (T0#2), typed rodata/kconfig via mmap (T1#10), BPF streams (T1#21), Query API with typed LinkInfo variants (T2#43), xlated bytecode dump (T2#44), per-`.bpf.o` BTF struct emission for user-declared C structs, static linker (T3#60).
- **cilium-ebpf deep-read added:** `Features.has*` concrete probe surface refining T0#5, batch map ops opaque cursor semantics (T1#17), `PerfEventArray` Pause/Resume/Deadline/LostSamples (T1#7 refined from Gap 5 scope), `Link.Update`/Info/Iterator + Anchor for mprog ordering (T2#24), ProgramOptions LogSize auto-grow, RunOptions richness (T2#47), MapInfo/ProgramInfo reflection (JitedInsns/LineInfos/Tag/VerifiedInstructions, T2#44 companion).
- **aya deep-read added:** PerfEventConfig/SamplePolicy/PerfEventScope (T1#8 refinement), uprobe AbsoluteOffset/SymbolOffset/libname resolution (feeds T1#20 USDT), LoadOptions builder pieces (feeds T0#2), Extension/freplace with BTF-id lookup (T2#23), XDP mode + atomic swap (T2#45), TC priority/handle/TCX LinkOrder (T2#46), sleepable `.s` and `xdp.frags` attributes (T1#18), allow_unsupported_maps flag, aya-log wire format concrete design (T1#22).
- **bpftrace deep-read added:** aggregation primitives (T1#13 — one of the two biggest new DSL deltas), symbolizer (T1#14), DWARF-typed args (T1#15), printf directive extensions (T3#67), probe glob expansion (T3#65), spawn-and-trace runner (T3#64), `kfunc_exist` fine-grained probe refining T0#5, stdlib helpers (T3#68), lockdown detection (T3#72).
- **kernel-selftests deep-read added:** arena data structures (T2#30), dynptr full family (T1#16), kptrs + bpf_obj_new (T2#31), bpf_list_head/bpf_rb_root (T2#32), fentry.multi/fexit.multi/kretsyscall refining T1#6, generic StructOps beyond sched_ext (T1#12), iterator kfuncs (T2#33), cpumask delta (T2#34), conntrack helpers (T2#35), may_goto/can_loop (T2#36), bpf_throw/bpf_assert_range (T2#37), RCU/preempt guards (T2#48), utility kfuncs (T3#70), bpf_wq (T3#57), crypto/xattr kfuncs (T3#58/#59), map creation flags (T1#18 partial).
- **OTel profiler deep-read added:** PROG_ARRAY + `@BPFTailCallTable` promoted to T0#3, HotSpot unwinder concrete mechanics (T2#39), DWARF native unwinder mechanics (T2#38), off-CPU as sched_switch+finish_task_switch pair (T2#40), tracer dispatch PROG_ARRAY chain, PerCPURecord state machine pattern, error taxonomy, TSD/TLS reading.

Refined / demoted:

- **Skeleton codegen (rust-go catalog)** — libbpf-rs deep-read decomposed this into three concrete features (T0#2, T1#10, T2#43); the raw "typed handles" bullet from rust-go is now covered.
- **BPF static linker** — moved to T3#60 after considering hello-ebpf's one-C-file-per-`@BPF`-class design; `@SharedFrom` handles the real user need at load time.
- **AF_XDP + XSKMAP** — moved to T3#71: no compelling Java-side story (userspace ring loop belongs in a C/Rust process).
- **AOT single-file distribution** — T3#62; jar-with-dependencies is close enough.

## 6. Alignment with existing plans

### Gap-designs top-5 (from `research-gap-designs.md`)

- **Gap 1 socket-plane (5w) → T1#11.** Aligned.
- **Gap 2 kprobe.multi + cookies (3.5w) → T0#1 + T1#6.** Aligned; T0 promotion because cookies are a live regression.
- **Gap 3 iterators (5w) → T1#9.** Aligned.
- **Gap 4 profiler (11w) → T0#3 + T0#4 + T1#7 + T1#8 + T2#38-42.** Aligned; broken across smaller T0/T1/T2 pieces because the design's own milestones are separable.
- **Gap 5 perf-event-array (4w) → T1#7 + T1#8.** Aligned.

### Sample-ideas top-3 by demoability × Java-native angle (from `research-sample-ideas.md`)

- **#20 GcAwareScheduler.** Needs T1#20 USDT (or uprobe-on-JVM), plus already-shipped sched_ext + task_local.
- **#31 JfrLiveTail.** Needs T1#20 USDT + T1#7 PerfEventArray for high-throughput chunk streaming; otherwise pure uprobe.
- **#8 TcpLifeJfr.** Needs T1#11 socket-plane (fentry on `tcp_v4_do_rcv`) — or, if we relax to a kprobe, works today; JFR emission works today.

Additional strong pitches: #6 HotThreadWatcher (needs T1#7 perf-event-array reader), #15 JitCompilationTracer (T1#20 USDT), #40 LbrErrorPathSnap (T3#54 LBR), #41 GadgetOciPublisher (T3#61 OCI packaging).

### Talks alignment (from `research-talks.md`)

- FOSDEM 2025 sched_ext-and-C talk → aligns with T1#12 (generic StructOps beyond sched_ext).
- LPC 2025 Emil Tsalapatis arena data structures → aligns with T2#30 (arena data structures).
- Jake Hillion LPC 2025 scx_chaos → already-shipped ChaosScheduler; no new gap.
- eBPF Summit 2024 keynote → project landing; no gap alignment.

Author's talk pipeline is heavily sched_ext-shaped; T1#12 generic StructOps is the natural "next talk" foundation.

## 7. Non-features (explicit exclusions)

Kept off the ranked list. Each has a stated rationale.

- **Full bpftrace DSL parser / REPL.** Not the paradigm. `research-bpftrace-deep-dive.md` positioning caveat: hello-ebpf is a full Java framework, not a REPL. Individual helpers (§1 aggregation, §2 symbolizer, §3 DWARF args) are ranked; the DSL itself is not.
- **BPF static linker (T3#60, listed but non-goal).** `@SharedFrom` at load time addresses the actual user need; static linking gains are marginal for one-`.c`-per-`@BPF`-class.
- **AF_XDP userspace ring loop (T3#71).** Java is not the right process to sit in an AF_XDP ring drain loop; better handed to a C/Rust sidecar the Java loader spawns.
- **Lockdown detection (T3#72).** A friendly diagnostic, not a feature; ship as part of the error-taxonomy work under T0#5 feature-detection.
- **AOT native-image single binary (T3#62).** hello-ebpf jars already carry BTF-enabled `.o`; the delta to a jlink image is packaging polish, not framework capability.
- **CLI equivalents of bpftrace flags (`-c`, `-p`, `-l`).** hello-ebpf is a library; a `BPFRunner.spawnAndTrace()` helper (T3#64) is enough.

## 8. Open questions

1. **Compiler-plugin cooperation for T1#10 typed rodata.** Does the plugin need to emit a nested `Rodata` record per `@BPF` class, or is a runtime-reflected map from BTF acceptable? libbpf-cargo picks the former; hello-ebpf could pick either.
2. **T0#5 feature-detection semantics: eager vs lazy.** cilium probes at first use; aya probes at load. Which fits hello-ebpf's exception model better?
3. **T2#38/T2#39 profiler DWARF unwinder: JVM-in-tree or as a companion module.** The OTel profiler ships DWARF-unwind + HotSpot-unwind as a coordinated pair. Should hello-ebpf host both, or fork the profiler as a separate `bpf-profiler` maven module?
4. **T1#22 aya-log wire format: leverage JEP 400/UTF-8 log records or invent a binary format.** Aya's format is Rust-serde-shaped; a Java-native format could piggyback on `java.io.ObjectOutput` or JFR chunks.
5. **T1#12 generic StructOps: what registration API.** Current sched_ext code is bespoke annotation surface (`@BPFStructOps` + hardcoded ops); generalising needs a decision on whether users declare a Java interface mirroring the kernel struct or annotate individual methods.
6. **T0#2 three-phase lifecycle: preserving the current `BPFProgram.load()` shorthand.** Most users don't need the open phase. `BPFProgram.load(X.class)` should stay as sugar over `openBuilder(X.class).open().load()` — but who owns the intermediate `OpenBPFProgram`, and how does `try-with-resources` compose?
7. **BPFHashOfMaps kernel-side generic typing.** Kernel `HASH_OF_MAPS` values are `map_fd` (u32). Java-side we want `BPFHashOfMaps<K, InnerMap>` — the `InnerMap` needs a compile-time type-token. Does the annotation processor emit an inner-type constant, or do users pass a `Class<InnerMap>` at runtime?
8. **T3 destructive helpers (T3#55/#56 write_user/send_signal/override_return).** Should there be an `--unsafe`-style opt-in like bpftrace, and how is that surfaced from Java (system property, annotation flag, both)?
