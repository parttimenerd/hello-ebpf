# sched_ext Documentation Anchor Catalog

## Summary

Twenty-plus canonical anchors identified across three tiers: (1) eight top-level markdowns in the `sched-ext/scx` GitHub repo (README, OVERVIEW, DEVELOPER_GUIDE, INSTALL, CARGO_BUILD, BREAKING_CHANGES, RELEASE, DHQ_README) plus a `scheds/README.md` catalog and fifteen per-scheduler Rust READMEs (C schedulers now live in the kernel tree under `tools/sched_ext` or a separate `scx-c-examples` repo, so the previously suggested C READMEs at `scheds/c/scx_simple/README.md` no longer exist in scx main); (2) a small wiki with a "Home" tutorial page plus "Layered Tuning Guide" and "Performance Testing" pages; (3) the upstream kernel doc `Documentation/scheduler/sched-ext.rst` rendered at `kernel.org/doc/html/latest/scheduler/sched-ext.html`. The "start here" anchor for someone landing on scx cold is `OVERVIEW.md` (concept + DSQs + scheduling cycle) followed by the kernel.org rendering for authoritative kfunc/callback reference. The scx repo also curates the canonical set of LWN articles, blog posts (arighi, Changwoo Min), and Kernel Recipes / LPC talks in its README "Additional Resources" section — hello-ebpf can point to these without re-curating.

## In-repo markdown docs

| File | Canonical URL | Scope (what it authoritatively covers) | Length (rough) | Suggested hello-ebpf cross-link target |
| --- | --- | --- | --- | --- |
| `README.md` | https://github.com/sched-ext/scx/blob/main/README.md | Project entry point: philosophy, installation-by-distro pointer, build/install steps, binary locations, env vars, scheduler catalog pointer, kernel feature status, "Additional Resources" (LWN, blogs, talks) | ~230 lines | `sched-ext/index.md` — primary "upstream project" link at the top of the page |
| `OVERVIEW.md` | https://github.com/sched-ext/scx/blob/main/OVERVIEW.md | Concept + motivation, dispatch queues (DSQs), full scheduling cycle (select_cpu → enqueue → dispatch), verifier/callback safety, references to academic prior art (ghOSt, Shenango, Shinjuku, ARINC 653) | ~500 lines | `sched-ext/index.md` (concept intro), `sched-ext/kernel-side.md` (first mention of struct_ops and DSQs) |
| `DEVELOPER_GUIDE.md` | https://github.com/sched-ext/scx/blob/main/DEVELOPER_GUIDE.md | Tooling for scheduler development: systing, scxtop, Perfetto, perf, bpftool, retsnoop, bpftrace, bpftop, stress-ng, veristat, turbostat, schbench; assumes core BPF/scheduling knowledge | ~243 lines | `sched-ext/cookbook.md` ("debugging your scheduler" section), `sched-ext/kernel-side.md` ("digging deeper" appendix) |
| `INSTALL.md` | https://github.com/sched-ext/scx/blob/main/INSTALL.md | Distro-specific install: Ubuntu (25.10 recommended), Arch, Gentoo, Fedora, NixOS, openSUSE Tumbleweed; kernel 6.12+ requirement | ~108 lines | `sched-ext/index.md` (prereqs), `sched-ext/kernel-side.md` (kernel version gate) |
| `CARGO_BUILD.md` | https://github.com/sched-ext/scx/blob/main/CARGO_BUILD.md | Cargo build system: three release profiles, workspace vs individual scheduler builds, tool builds (scxtop, scx_characterize), crates.io installs, cross-compilation | ~245 lines | `sched-ext/userspace.md` (comparison: "how scx builds Rust schedulers vs how hello-ebpf builds Java schedulers") |
| `BREAKING_CHANGES.md` | https://github.com/sched-ext/scx/blob/main/BREAKING_CHANGES.md | API breakage log across scx ↔ kernel commits (currently just prep_enable/cancel_enable rename + scx_bpf_select_cpu_dfl kfunc addition; no kernel-version mapping) | ~23 lines | `sched-ext/kernel-side.md` (footnote on API stability), `sched-ext/cookbook.md` (troubleshooting old kernels) |
| `RELEASE.md` | https://github.com/sched-ext/scx/blob/main/RELEASE.md | Release process for the scx repo itself | short | (not linked from hello-ebpf; internal to scx maintainers) |
| `DHQ_README.md` | https://github.com/sched-ext/scx/blob/main/DHQ_README.md | Documentation for DHQ (a scx sub-component) | short | (not linked unless hello-ebpf grows DHQ coverage) |
| `scheds/README.md` | https://github.com/sched-ext/scx/blob/main/scheds/README.md | Catalog of scheduler subdirectories; notes C schedulers have been moved out of scx to the kernel tree / `scx-c-examples`; points at `scheds/rust/README.md` | ~41 lines | `sched-ext/index.md` ("what schedulers exist in the ecosystem") |
| `scheds/rust/README.md` | https://github.com/sched-ext/scx/blob/main/scheds/rust/README.md | Enumeration of the 15 Rust userspace schedulers | short | `sched-ext/userspace.md` (comparison target list) |
| `scheds/rust/scx_rustland/README.md` | https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_rustland/README.md | scx_rustland scheduler: interactive-workload priority, userspace policy on top of scx_rustland_core BPF component | ~47 lines | `sched-ext/userspace.md` (**primary comparison anchor** — hello-ebpf's userspace runtime mirrors scx_rustland_core) |
| `scheds/rust/scx_rusty/README.md` | https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_rusty/README.md | scx_rusty: multi-domain BPF/userspace hybrid, round-robin per domain with userspace load balancing | ~36 lines | `sched-ext/userspace.md` (secondary example — hybrid approach) |
| `scheds/rust/scx_lavd/README.md` | https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_lavd/README.md | scx_lavd: Latency-criticality Aware Virtual Deadline, gaming/interactive workloads, per-LLC/core-type/NUMA domains | ~31 lines | `sched-ext/cookbook.md` (advanced example — latency-aware scheduling patterns) |
| `scheds/rust/scx_bpfland/README.md` | https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_bpfland/README.md | scx_bpfland: another interactive scheduler by arighi (referenced in scx demo videos) | short | `sched-ext/userspace.md` (referenced but not the primary comparison) |
| `scheds/rust/scx_layered/README.md` | https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_layered/README.md | scx_layered: partitioned scheduling with the "Layered Tuning Guide" wiki page as its companion | short | `sched-ext/cookbook.md` (patterns for partitioning workloads) |
| `scheds/rust/scx_flash/README.md` | https://github.com/sched-ext/scx/blob/main/scheds/rust/scx_flash/README.md | scx_flash scheduler | short | (not linked by default) |
| Other `scheds/rust/scx_*/README.md` | see below | scx_beerland, scx_cake, scx_chaos, scx_cosmos, scx_forge, scx_mitosis, scx_p2dq, scx_pandemonium, scx_tickless | short each | (referenced only in a "further reading" list on `sched-ext/userspace.md`) |

Additional non-`.md` in-repo references worth citing verbatim:
- `kernel.config` — https://github.com/sched-ext/scx/blob/main/kernel.config — canonical set of `CONFIG_SCHED_*` options to enable. Link from `sched-ext/kernel-side.md` when discussing "build a kernel that supports scx".
- `services/README.md` and `services/systemd/` — systemd unit reference. Link from `sched-ext/cookbook.md` if hello-ebpf grows a systemd deployment section.

## Wiki pages

| File | Canonical URL | Scope | Length | Suggested hello-ebpf cross-link target |
| --- | --- | --- | --- | --- |
| Home | https://github.com/sched-ext/scx/wiki | Minimal round-robin scheduler tutorial in C+BPF (sched_init / sched_enqueue / sched_dispatch), plus a curated resources list (LWN, blogs by arighi and Changwoo Min, video talks by David Vernet, LPC 2024 sessions, SRECon EMEA 2024) | medium | `sched-ext/kernel-side.md` (**best "first-real-scheduler" tutorial** — pair it with hello-ebpf's Java equivalent) |
| Layered Tuning Guide | https://github.com/sched-ext/scx/wiki/Layered-Tuning-Guide | Operator-facing tuning guide for scx_layered | medium | `sched-ext/cookbook.md` (deployment-tuning section) |
| Performance Testing | https://github.com/sched-ext/scx/wiki/Performance-Testing | Benchmark methodology for comparing schedulers | medium | `sched-ext/cookbook.md` (benchmarking section) |

The wiki itself warns readers that content may lag the code; treat it as a curated tutorial layer, not a spec.

## Upstream kernel documentation

- Canonical HTML rendering: **https://www.kernel.org/doc/html/latest/scheduler/sched-ext.html**
  - Sections: Extensible Scheduler Class · Switching to and from sched_ext · Dispatch Queues · Scheduling Cycle · Task Lifecycle · Where to Look · Module Parameters · ABI Instability.
  - Documents the full `sched_ext_ops` callback set (`select_cpu`, `enqueue`, `dequeue`, `dispatch`, `init`, `exit`, `init_task`, `enable`, `disable`, `exit_task`, `runnable`, `running`, `stopping`, `quiescent`, `tick`, plus property-change callbacks) and the core kfunc set (`scx_bpf_select_cpu_dfl`, `scx_bpf_dsq_insert`, `scx_bpf_dsq_insert_vtime`, `scx_bpf_dsq_move_to_local`, `scx_bpf_create_dsq`, `scx_bpf_destroy_dsq`, `scx_bpf_kick_cpu`).
  - DSQ types documented: `SCX_DSQ_GLOBAL` (global FIFO), `SCX_DSQ_LOCAL` (per-CPU), and user-created custom DSQs.
  - Arena support: the doc mentions arena only in passing via the `scx_sdt` reference example. Arena support landed in kernel **6.14**; the kernel.org rendering tracks the latest stable kernel branch, so features that landed after the rendered branch's cutoff will not be present. The rendered branch at scrape time was 7.2.0-rc1.
  - The doc explicitly disclaims stability: "The APIs provided by sched_ext to BPF schedulers programs have no stability guarantees … subject to change without warning between kernel versions." Cite this on every hello-ebpf page that mentions kfunc bindings.
- Source (RST): **`Documentation/scheduler/sched-ext.rst`** in `torvalds/linux`. Direct cgit browse at `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/scheduler/sched-ext.rst` returns HTTP 404 for HEAD sometimes — prefer the Bootlin Elixir mirror for permalinks: `https://elixir.bootlin.com/linux/latest/source/Documentation/scheduler/sched-ext.rst` (redirects to the latest kernel version, currently v7.1.2 at scrape time).
- Kernel-version → feature timeline (from the scx README "Kernel Feature Status" section combined with the LWN articles):
  - **6.12** — sched_ext mainlined; core ops set + DSQs + kfuncs stable.
  - **6.13** — additional kfuncs and cpumask helpers.
  - **6.14** — BPF arena support usable from scx schedulers (this is what hello-ebpf's `BPFArena` targets).
  - **6.15+** — ongoing kfunc additions and cpumask/topology helpers; consult `BREAKING_CHANGES.md` and git log.

## External references

The scx `README.md` "Additional Resources" section is the canonical curator of external anchors. hello-ebpf should cite scx's list rather than duplicate curation.

| Type | Title | URL | Date | Suggested hello-ebpf cross-link target |
| --- | --- | --- | --- | --- |
| LWN article | The extensible scheduler class | https://lwn.net/Articles/922405/ | Feb 2023 | `sched-ext/index.md` (history/motivation footnote) |
| Blog (arighi) | Implement your own kernel CPU scheduler in Ubuntu with sched_ext | (linked from scx README; arighi's blog) | Jul 2023 | `sched-ext/kernel-side.md` (getting-started aside) |
| Blog (Changwoo Min) | sched_ext: a BPF-extensible scheduler class (Part 1) | (linked from scx README) | Dec 2023 | `sched-ext/kernel-side.md` (concept deep-dive) |
| Blog (arighi) | Getting started with sched_ext development | (linked from scx README) | Apr 2024 | `sched-ext/cookbook.md` (dev-loop reference) |
| Blog (Changwoo Min) | sched_ext: scheduler architecture and interfaces (Part 2) | (linked from scx README) | Jun 2024 | `sched-ext/kernel-side.md` (architecture deep-dive) |
| Video (playlist) | sched_ext YouTube Playlist | (linked from scx README) | ongoing | `sched-ext/index.md` (further reading) |
| Talk (David Vernet) | sched_ext: pluggable scheduling in the Linux kernel — Kernel Recipes 2023 | (linked from scx README) | 2023 | `sched-ext/index.md` (canonical talk) |
| Talk (David Vernet) | Scheduling with superpowers: Using sched_ext to get big perf gains — Kernel Recipes 2024 | (linked from scx README) | 2024 | `sched-ext/index.md` (production case study) |
| Talk (arighi) | scx_bpfland Linux scheduler demo: topology awareness | (linked from scx README) | Aug 2024 | `sched-ext/userspace.md` (demo) |
| Talk (arighi) | Schedule Recipes — Kernel Recipes 2025 | (linked from scx README) | 2025 | `sched-ext/cookbook.md` (patterns catalog) |
| Micro-conference | LPC 2024 sched_ext micro-conf | (linked from scx wiki) | 2024 | `sched-ext/cookbook.md` (deployment war stories) |
| Micro-conference | LPC 2025 sched_ext micro-conf | (linked from scx README) | 2025 | `sched-ext/cookbook.md` |
| Talk | SRECon EMEA 2024 — scheduling at scale | (linked from scx wiki) | 2024 | `sched-ext/userspace.md` (ops case study) |

Do not crawl LWN or blog article bodies from hello-ebpf's docs; just link out. If hello-ebpf needs a stable citation, prefer the scx README anchor over the primary source (scx README is version-controlled and won't rot as fast).

For per-talk detail on the LPC 2024 and LPC 2025 sched_ext microconferences (session IDs, individual contribution URLs, presenter attribution) and for Johannes Bechberger's own sched_ext / hello-ebpf conference talks, see [`research-talks.md`](research-talks.md) — it is the authoritative catalog and the rows above should be treated as high-level pointers into it.

## Cross-link plan

**`sched-ext/index.md`** — the top of hello-ebpf's sched-ext section. Open with a single sentence pointing to `OVERVIEW.md` as the concept intro, plus a "prereqs" callout linking `INSTALL.md` (for the kernel-version requirement) and the kernel.org HTML rendering (for the authoritative ABI). In the "history and motivation" paragraph, link the Feb 2023 LWN article and David Vernet's Kernel Recipes 2023 talk. Close with "further reading" listing the scx `README.md` "Additional Resources" section by URL so the reader inherits scx's curated blog/talk list without duplication.

**`sched-ext/kernel-side.md`** — the densest cross-linking target. On first mention of `struct_ops`, footnote to `OVERVIEW.md` "How" section. On first mention of a DSQ, footnote to the kernel.org page's "Dispatch Queues" section. Every kfunc name (e.g. `scx_bpf_dsq_insert`) should link to the kernel.org rendering's kfunc section as the authoritative signature source. On the kernel-version requirement, link `INSTALL.md` and the scx `kernel.config`. For a "walk through a minimal scheduler in Java, compare to a minimal one in C" section, link the scx wiki Home page tutorial. In the "digging deeper" appendix at the end, link `DEVELOPER_GUIDE.md`, Changwoo Min's two-part blog, and `BREAKING_CHANGES.md` (for the ABI-instability warning).

**`sched-ext/userspace.md`** — comparison-heavy page. `scx_rustland/README.md` is the **primary anchor** because scx_rustland_core is what hello-ebpf's userspace runtime mirrors; call this out explicitly in the opening paragraph and link the README. `scx_rusty/README.md` as a secondary anchor for hybrid designs. `scx_bpfland/README.md` and the arighi topology-awareness demo as "another interactive scheduler". `scheds/rust/README.md` as the "full catalog" link. `CARGO_BUILD.md` in a "how scx builds Rust schedulers" aside contrasted with hello-ebpf's Maven+Java flow.

**`sched-ext/cookbook.md`** — patterns and troubleshooting. `DEVELOPER_GUIDE.md` for the tooling section (scxtop, bpftool, veristat, retsnoop). arighi's "Getting started with sched_ext development" blog as the canonical dev-loop reference. `scx_lavd/README.md` for latency-aware patterns and `scx_layered/README.md` plus the wiki "Layered Tuning Guide" for partitioning patterns. The wiki "Performance Testing" page for benchmarking. `BREAKING_CHANGES.md` for the "my old scheduler stopped compiling" section. LPC 2024/2025 micro-conference talks and arighi's Kernel Recipes 2025 "Schedule Recipes" as "war stories" further reading.

## Notes and gotchas for hello-ebpf writers

- The `scheds/c/` directory suggested by the original brief no longer exists in scx main. C example schedulers live in `tools/sched_ext/` in the kernel tree (canonical) and in a separate `scx-c-examples` repo (mirror). If hello-ebpf wants to cite `scx_simple.bpf.c` or `scx_qmap.bpf.c`, link the kernel tree copy, e.g. `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/sched_ext/scx_simple.bpf.c`, not the historic scx path.
- The wiki reference to a minimal round-robin scheduler in C is the closest analogue to hello-ebpf's own "hello world" scheduler tutorial — pair the two side-by-side in `kernel-side.md`.
- Kernel.org's HTML rendering tracks the current kernel branch; features documented there may **lag** what scx main supports and hello-ebpf targets. When documenting arena support (6.14), cite both the kernel.org page (for the older stable API) and note that arena-specific coverage is thin — the scx `OVERVIEW.md` and the `scx_sdt` reference sample are better anchors for arena patterns.
- The `BREAKING_CHANGES.md` is very short and out-of-date (only two entries logged). Do not rely on it as a version-mapping table; use the scx README's "Kernel Feature Status" section combined with git log as the source of truth for what landed when.
