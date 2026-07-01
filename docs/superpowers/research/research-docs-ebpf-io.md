# Research: docs.ebpf.io — mapping and cross-link recommendations for hello-ebpf

Status: 2026-07-01. Site enumerated from `https://docs.ebpf.io/sitemap.xml` (1207 URLs, all `<lastmod>2026-06-29`), spot-checks against 8 representative pages.

## 1. Summary

`docs.ebpf.io` is not a BCC site. It is a MkDocs Material reference for the Linux kernel eBPF surface — verifier, program types, map types, helper functions, kfuncs, `bpf()` syscall commands — plus reference docs for `libbpf`, `libxdp`, and `sched_ext` (`scx`) headers. It is actively maintained (built 2026-06-29; individual pages show updates as recent as February 2026) and explicitly scoped in its own FAQ to "the Linux kernel, libraries maintained alongside the Linux kernel as reference implementation (specifically iproute2, libbpf, libxdp), eBPF on Windows (when it matures)". There are no BCC/Python tutorials and no getting-started walkthroughs of the form that would compete with hello-ebpf's tutorial pages, so the concern about tutorial duplication in the brief is stale.

Verdict counts across 21 categorised targets: 15 `link — authoritative`, 3 `link — background`, 0 `avoid — stale`, 3 `avoid — off-topic` (libbpf userspace loader API, `bpf()` syscall command pages, `libxdp` C API — all C-side surfaces hello-ebpf hides), 0 `avoid — duplicates hello-ebpf`.

Headline recommendation: treat `docs.ebpf.io` as the canonical external reference for hello-ebpf and cross-link liberally.
- Every helper mention in `reference/bpfj.md` (and in generated Javadoc where feasible) should link to the matching `linux/helper-function/<name>/` page.
- Every hook page (`xdp.md`, `kprobes.md`, `uprobes.md`, `tracepoints.md`, `lsm.md`, `tc.md`) should carry a "Kernel reference" link to its `linux/program-type/BPF_PROG_TYPE_*/` page.
- `getting-started/how-it-works.md` should link `linux/concepts/verifier/`, `concepts/core/`, and `concepts/btf/` as the three background reads.

## 2. Site structure

Top-level nav derived from the sidebar rendered on every page and confirmed against the sitemap:

| Section | URL | Pages | Purpose |
|---|---|---|---|
| Home | `https://docs.ebpf.io/` | 1 | Landing / TOC |
| Cross-platform concepts | `https://docs.ebpf.io/concepts/` | 5 | BTF, CO-RE, ELF, instruction set, loader — vendor/OS-neutral |
| Linux Reference — Concepts | `https://docs.ebpf.io/linux/concepts/` | 16 | verifier, kfuncs, maps, dynptrs, tail-calls, timers, USDT, trampolines, token, resource-limit, functions, concurrency, loops, pinning, af_xdp |
| Linux Reference — Program types | `https://docs.ebpf.io/linux/program-type/` | 39 | One page per `BPF_PROG_TYPE_*` |
| Linux Reference — Map types | `https://docs.ebpf.io/linux/map-type/` | 35 | One page per `BPF_MAP_TYPE_*` |
| Linux Reference — Helper functions | `https://docs.ebpf.io/linux/helper-function/` | 212 | One page per `bpf_*` helper |
| Linux Reference — Kfuncs | `https://docs.ebpf.io/linux/kfuncs/` | 319 | One page per kfunc |
| Linux Reference — Syscall | `https://docs.ebpf.io/linux/syscall/` | 38 | One page per `bpf()` command (`BPF_MAP_CREATE`, `BPF_PROG_LOAD`, …) |
| libbpf | `https://docs.ebpf.io/ebpf-library/libbpf/` | 445 | userspace loader API (347) + eBPF-side headers (95) + concepts |
| libxdp | `https://docs.ebpf.io/ebpf-library/libxdp/` | 46 | userspace C API for XDP dispatcher |
| sched_ext (scx) | `https://docs.ebpf.io/ebpf-library/scx/` | 37 | in-tree `tools/sched_ext/include/scx/*.h` macros/helpers |
| FAQ | `https://docs.ebpf.io/faq/` | 1 | Scope, audience, contributing |
| Meta | `https://docs.ebpf.io/meta/` | 1 | How the docs site itself is built |

Freshness signal: sitemap `<lastmod>` = 2026-06-29 for every page (rebuilt daily). Content pages themselves show "created / updated" pairs, e.g. `ebpf-library/scx/` shows "February 20, 2026 / March 2, 2025", `ebpf-library/libbpf/` shows "May 6, 2025 / October 13, 2024". The XDP program-type page annotates its intro with `v4.8`, i.e. the kernel version the feature landed in — this "since kernel vN.M" tag is present on every reference page and is one of the most valuable features of the site.

## 3. Page-by-page verdicts

| URL | Title | Section | Scope | Verdict | Target hello-ebpf page | Notes |
|---|---|---|---|---|---|---|
| `https://docs.ebpf.io/` | eBPF Docs (home) | Home | Landing, links to the top-level sections | link — background | `getting-started/how-it-works.md` (once, in a "further reading" block) | Better to link specific concept pages than the home; use only as a "browse the reference" entry point |
| `https://docs.ebpf.io/faq/` | FAQ | Meta | Explains scope of docs.ebpf.io itself | avoid — off-topic | — | Useful to us as researchers, not to hello-ebpf readers |
| `https://docs.ebpf.io/meta/` | Meta docs | Meta | How the docs site is built | avoid — off-topic | — | Contributor doc for docs.ebpf.io itself |
| `https://docs.ebpf.io/concepts/btf/` | BTF | Cross-platform concepts | What BTF is, `/sys/kernel/btf/vmlinux`, `vmlinux.h` generation via bpftool | link — authoritative | `getting-started/how-it-works.md`, `architecture/plugin.md` | Perfect one-page background for hello-ebpf's BTF-driven CO-RE story |
| `https://docs.ebpf.io/concepts/core/` | BPF CO-RE | Cross-platform concepts | Compile Once - Run Everywhere: BTF + libbpf + Clang relocations | link — authoritative | `getting-started/how-it-works.md`, `architecture/plugin.md`, `reference/annotations.md` (on `@CoRe`/`BPF_CORE_READ` mentions) | Cleanest short CO-RE explainer on the public web |
| `https://docs.ebpf.io/concepts/elf/` | ELF | Cross-platform concepts | ELF layout of a BPF object file (sections, relocations) | link — background | `architecture/plugin.md` | Only relevant if the reader is debugging what bpfj emits |
| `https://docs.ebpf.io/concepts/instruction-set/` | Instruction set | Cross-platform concepts | eBPF ISA reference | link — background | `architecture/plugin.md` | For readers curious about what the plugin ultimately produces |
| `https://docs.ebpf.io/concepts/loader/` | Loader | Cross-platform concepts | What an eBPF loader does at a high level | link — background | `getting-started/how-it-works.md` | Good context for hello-ebpf's runtime |
| `https://docs.ebpf.io/linux/concepts/verifier/` | Verifier | Linux concepts | Verifier basics + analyses (dead code, bounded loops, callbacks) | link — authoritative | `getting-started/how-it-works.md`, `feature-matrix.md`, every hook page (in a "why did this fail to load?" note) | The single most-linked page. Every mention of "the verifier" in hello-ebpf docs should link here on first occurrence per page |
| `https://docs.ebpf.io/linux/concepts/kfuncs/` | KFuncs | Linux concepts | What kfuncs are, `__sz`/`__k`/`__nullable`/`__str` annotations, KF_ACQUIRE/RELEASE/RCU flags | link — authoritative | `reference/annotations.md`, `reference/bpfj.md` | Directly explains the kernel-side of what `@BuiltinBPFFunction` wraps |
| `https://docs.ebpf.io/linux/concepts/maps/` | Maps (concept) | Linux concepts | Map primitives, lookup/update/delete semantics | link — authoritative | `reference/annotations.md` (on `@BPFMapDefinition`), map-oriented sections of `reference/bpfj.md` | Preferred single link for "what is a BPF map" |
| `https://docs.ebpf.io/linux/concepts/dynptrs/` | Dynptrs | Linux concepts | Dynamic pointer type, kernel API | link — authoritative | `reference/bpfj.md` (if/when we surface dynptrs) | Reference for any bpfj wrapper over `bpf_dynptr_*` |
| `https://docs.ebpf.io/linux/concepts/tail-calls/` | Tail calls | Linux concepts | Tail-call chains, PROG_ARRAY | link — authoritative | `reference/bpfj.md` (tail-call section) | Kernel-side reference; hello-ebpf should link on any tail-call mention |
| `https://docs.ebpf.io/linux/concepts/timers/` | Timers | Linux concepts | `bpf_timer` API, callbacks | link — authoritative | `reference/bpfj.md` (timers), any tutorial that uses them | — |
| `https://docs.ebpf.io/linux/concepts/usdt/` | USDT | Linux concepts | USDT probes on Linux | link — authoritative | `uprobes.md` (side note on USDT) | — |
| `https://docs.ebpf.io/linux/concepts/loops/` | Loops | Linux concepts | Bounded loops, `bpf_loop`, iterators | link — authoritative | `reference/bpfj.md` (loop-writing guidance) | — |
| `https://docs.ebpf.io/linux/concepts/concurrency/` | Concurrency | Linux concepts | Per-CPU vs shared, spin locks | link — authoritative | `reference/bpfj.md`, `reference/annotations.md` (spinlocks) | — |
| `https://docs.ebpf.io/linux/concepts/pinning/` | Pinning | Linux concepts | Pinning maps/progs into bpffs | link — authoritative | `reference/annotations.md` (on `@SharedFrom` and pin-related annotations) | Directly relevant to how `@SharedFrom` semantics are grounded |
| `https://docs.ebpf.io/linux/concepts/resource-limit/` | Resource limit | Linux concepts | Memlock, memcg accounting | link — background | Troubleshooting section in `getting-started/how-it-works.md` if we have one | — |
| `https://docs.ebpf.io/linux/concepts/af_xdp/` | AF_XDP | Linux concepts | Userspace AF_XDP sockets | link — authoritative | `xdp.md` (see also) | Complements the XDP program-type page |
| `https://docs.ebpf.io/linux/concepts/token/` | BPF token | Linux concepts | Delegation via bpf_token | link — background | `getting-started/how-it-works.md` (permissions) | Newer feature; useful context |
| `https://docs.ebpf.io/linux/concepts/trampolines/` | Trampolines | Linux concepts | fentry/fexit trampolines | link — background | `reference/bpfj.md` if we ever cover fentry/fexit | — |
| `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/` | Program type BPF_PROG_TYPE_XDP | Linux program types | Full XDP reference: return actions, `xdp_md` context, attach modes, frags, since v4.8 | link — authoritative | `xdp.md` (top of page: "Kernel reference: …") | Deep, current; example spot-check shows XDP_ABORTED/DROP/PASS/TX/REDIRECT documented |
| `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/` | Program type BPF_PROG_TYPE_KPROBE | Linux program types | Kprobe & uprobe program contract | link — authoritative | `kprobes.md`, `uprobes.md` | One kernel program type covers both — cross-link from both hello-ebpf pages |
| `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACEPOINT/` | Program type BPF_PROG_TYPE_TRACEPOINT | Linux program types | Tracepoint program contract | link — authoritative | `tracepoints.md` | — |
| `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_RAW_TRACEPOINT/` | Program type BPF_PROG_TYPE_RAW_TRACEPOINT | Linux program types | Raw tracepoint variant | link — authoritative | `tracepoints.md` | Link both variants |
| `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/` | Program type BPF_PROG_TYPE_LSM | Linux program types | LSM hook programs | link — authoritative | `lsm.md` | — |
| `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/` | Program type BPF_PROG_TYPE_SCHED_CLS | Linux program types | tc classifier programs | link — authoritative | `tc.md` | Primary tc program type |
| `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_ACT/` | Program type BPF_PROG_TYPE_SCHED_ACT | Linux program types | tc action programs | link — authoritative | `tc.md` | Cross-link alongside SCHED_CLS |
| `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_STRUCT_OPS/` | Program type BPF_PROG_TYPE_STRUCT_OPS | Linux program types | struct_ops mechanism (parent of sched_ext) | link — authoritative | Any sched_ext-facing hello-ebpf page | Contains 7 sub-pages worth spot-checking if we grow scheduler docs |
| `https://docs.ebpf.io/linux/program-type/` | Program types index | Linux program types | Index of all program types | link — background | `feature-matrix.md` (as "full kernel list") | Useful "compare to hello-ebpf coverage" link |
| `https://docs.ebpf.io/linux/map-type/` | Map types index | Linux map types | Index of all map types | link — background | `feature-matrix.md` | — |
| `https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_HASH/` (and siblings) | Map Type '…' | Linux map types | Semantics, since-kernel, allowed program types, examples | link — authoritative | `reference/annotations.md` (map-type table) | Ideal target for a per-map-type table in the annotations reference |
| `https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_ARENA/` | Map Type 'BPF_MAP_TYPE_ARENA' | Linux map types | Arena map reference | link — authoritative | Any hello-ebpf page covering arena/`BPFArena` | Confirmed to be up-to-date reference for a feature the project already uses |
| `https://docs.ebpf.io/linux/helper-function/` | Helper functions index | Linux helpers | Alphabetical index of 212 helpers | link — authoritative | `reference/bpfj.md` (top of "builtin helpers" section) | Link once as "full index of BPF helper functions" |
| `https://docs.ebpf.io/linux/helper-function/bpf_probe_read_kernel/` (and 211 siblings) | Helper function '…' | Linux helpers | Per-helper: since-kernel, prototype, semantics, allowed program types, example | link — authoritative | `reference/bpfj.md` on every helper mention; generated Javadoc-style `@see` links from `@BuiltinBPFFunction` if feasible | Prototype spot-check confirms high quality (definition + program-type table + working C example) |
| `https://docs.ebpf.io/linux/kfuncs/` | Kfuncs index | Linux kfuncs | Alphabetical index of 319 kfuncs | link — authoritative | `reference/bpfj.md`, `reference/annotations.md` | Primary index; hello-ebpf uses many kfuncs |
| `https://docs.ebpf.io/linux/kfuncs/bpf_dynptr_from_skb/` (and siblings) | KFunc '…' | Linux kfuncs | Per-kfunc reference | link — authoritative | `reference/bpfj.md` on every kfunc mention | Same treatment as helpers |
| `https://docs.ebpf.io/linux/syscall/` (and 38 command sub-pages) | Syscall commands | Linux syscall | Per-`bpf()` command reference (`BPF_MAP_CREATE`, `BPF_PROG_LOAD`, …) | avoid — off-topic | — | hello-ebpf hides the syscall; only relevant if the reader is writing a loader (they're not — bpfj is the loader) |
| `https://docs.ebpf.io/ebpf-library/libbpf/` | Libbpf (root) | libbpf | libbpf overview | link — background | `architecture/plugin.md` | Fine to link once as "what libbpf is"; do not deep-link into userspace API |
| `https://docs.ebpf.io/ebpf-library/libbpf/userspace/*` (347 pages) | libbpf userspace API | libbpf | C loader API reference | avoid — off-topic | — | hello-ebpf replaces this surface with Java; linking would confuse readers |
| `https://docs.ebpf.io/ebpf-library/libbpf/ebpf/*` (95 pages incl. `BPF_CORE_READ`, `SEC`, `__type`) | libbpf eBPF-side headers | libbpf | Reference for macros used inside BPF C source (CO-RE readers, `SEC()`, map defs) | link — authoritative | `reference/annotations.md` (on `BPF_CORE_READ` mentions), `architecture/plugin.md` | These macros are what the plugin emits under the hood — useful for advanced readers |
| `https://docs.ebpf.io/ebpf-library/libbpf/concepts/` | libbpf concepts | libbpf | Small landing under libbpf | link — background | `architecture/plugin.md` | Marginal; only if we need a bridge |
| `https://docs.ebpf.io/ebpf-library/libxdp/*` (46 pages) | libxdp | libxdp | Userspace C API for the XDP dispatcher | avoid — off-topic | — | hello-ebpf's XDP attach path doesn't call libxdp directly |
| `https://docs.ebpf.io/ebpf-library/scx/` (37 pages) | scx headers | scx | `tools/sched_ext/include/scx/*.h` macros and kfunc forward decls | link — authoritative | Any sched_ext / userspace-scheduler page in hello-ebpf | Confirmed active (page updated Feb 2026); directly relevant to the scheduler work already in the tree |

## 4. Recommended cross-link map (per hello-ebpf page)

`getting-started/how-it-works.md` — the eBPF-background page. Add a short "Further reading" panel linking:
- "the verifier" → `https://docs.ebpf.io/linux/concepts/verifier/`
- "BTF" → `https://docs.ebpf.io/concepts/btf/`
- "CO-RE" → `https://docs.ebpf.io/concepts/core/`
- "what a loader does" (once) → `https://docs.ebpf.io/concepts/loader/`
- A single browse-the-reference entry → `https://docs.ebpf.io/`

`reference/annotations.md` — the annotation catalog. Link on first mention of each concept:
- On `@BPFMapDefinition` / `BPF_MAP_TYPE_*` → link the map's page under `https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_*/`; link the overall "what is a map" once to `https://docs.ebpf.io/linux/concepts/maps/`.
- On CO-RE / `@CoRe` / `BPF_CORE_READ` → `https://docs.ebpf.io/concepts/core/` and the `libbpf/ebpf/BPF_CORE_READ/` page.
- On kfuncs and `@BuiltinBPFFunction` → `https://docs.ebpf.io/linux/concepts/kfuncs/`.
- On pinning / `@SharedFrom` → `https://docs.ebpf.io/linux/concepts/pinning/`.
- On spinlocks / per-CPU → `https://docs.ebpf.io/linux/concepts/concurrency/`.

`reference/bpfj.md` — the language reference. This is the single biggest consumer of docs.ebpf.io:
- Top of the "builtin helpers" section, add: "For each helper, see the kernel reference at `https://docs.ebpf.io/linux/helper-function/`."
- Top of the "kfuncs" section: link `https://docs.ebpf.io/linux/kfuncs/` similarly.
- On first mention of any specific `bpf_*` helper (`bpf_probe_read_kernel`, `bpf_ktime_get_ns`, `bpf_map_lookup_elem`, …) link `https://docs.ebpf.io/linux/helper-function/<name>/`.
- On first mention of any kfunc (`bpf_dynptr_from_skb`, `scx_bpf_dsq_insert`, …) link `https://docs.ebpf.io/linux/kfuncs/<name>/`.
- On timers, loops, tail-calls, dynptrs — link the matching `linux/concepts/*` page.
- Ideally, the same convention flows into generated Javadoc/HTML for `@BuiltinBPFFunction` annotations so IDE users get one-click docs.

`architecture/plugin.md` — internals. Link:
- `https://docs.ebpf.io/concepts/core/` on CO-RE
- `https://docs.ebpf.io/concepts/btf/` on BTF ingestion
- `https://docs.ebpf.io/concepts/elf/` and `https://docs.ebpf.io/concepts/instruction-set/` for readers wanting to know what the plugin ultimately emits
- `https://docs.ebpf.io/ebpf-library/libbpf/` (root) on "what libbpf is"
- `https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_CORE_READ/` on the CO-RE read macro the plugin generates around non-trivial roots

`feature-matrix.md` — coverage table. Link:
- Column header for "kernel program types" → `https://docs.ebpf.io/linux/program-type/`
- Column header for "kernel map types" → `https://docs.ebpf.io/linux/map-type/`

Hook pages (`xdp.md`, `tc.md`, `kprobes.md`, `uprobes.md`, `tracepoints.md`, `lsm.md`) — each should carry a `Kernel reference` note near the top:
- `xdp.md` → `https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/` and, for the raw-socket variant, `https://docs.ebpf.io/linux/concepts/af_xdp/`.
- `tc.md` → both `BPF_PROG_TYPE_SCHED_CLS` and `BPF_PROG_TYPE_SCHED_ACT` pages.
- `kprobes.md` → `BPF_PROG_TYPE_KPROBE`.
- `uprobes.md` → `BPF_PROG_TYPE_KPROBE` (same program type in the kernel) plus `linux/concepts/usdt/` as a "see also".
- `tracepoints.md` → both `BPF_PROG_TYPE_TRACEPOINT` and `BPF_PROG_TYPE_RAW_TRACEPOINT`.
- `lsm.md` → `BPF_PROG_TYPE_LSM`.

## 5. What to explicitly not link

- `https://docs.ebpf.io/linux/syscall/BPF_*` (39 pages). Reason: hello-ebpf's entire value proposition is that the reader never touches `bpf()` directly. Linking these pages invites readers to conflate bpfj's runtime with a hand-rolled loader.
- `https://docs.ebpf.io/ebpf-library/libbpf/userspace/*` (347 pages: `bpf_object__open_file`, `bpf_program__attach`, …). Reason: this is the C userspace API bpfj replaces; linking suggests the reader should call it, which they shouldn't.
- `https://docs.ebpf.io/ebpf-library/libxdp/*` (46 pages). Reason: hello-ebpf attaches XDP through its own runtime, not via libxdp; linking is off-topic and confusing.
- `https://docs.ebpf.io/faq/` and `https://docs.ebpf.io/meta/`. Reason: internal to the docs.ebpf.io project, no reader value.
- The `SUMMARY/` pages under each section (`linux/concepts/SUMMARY/`, `linux/helper-function/SUMMARY/`, …). Reason: these are MkDocs internals, not user-facing.

## 6. Cross-check against the brief's assumptions

The brief warns against linking BCC tutorials and "Getting Started" material on docs.ebpf.io. Neither exists on the current site: docs.ebpf.io is a pure reference for Linux kernel eBPF plus `libbpf`/`libxdp`/`scx` reference material. The scope statement on `https://docs.ebpf.io/faq/` and the sidebar (which is identical on every page — Linux Reference → Concepts / Program types / Map types / Helpers / KFuncs / Syscall, then eBPF Library → libbpf / libxdp / scx) both confirm this. The "BCC-oriented tutorial site" description of `docs.ebpf.io` circulated in older discussions is out of date; the site as it stands today is safe to link liberally as a kernel reference.
