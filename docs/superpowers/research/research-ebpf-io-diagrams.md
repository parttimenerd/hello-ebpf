# Research: ebpf.io diagram inventory

Cataloged from ebpf.io (main marketing / project site — **not** docs.ebpf.io, which
is a separate research task) for the purpose of deciding which figures hello-ebpf
should mirror under CC-BY 4.0.

Retrieved: 2026-07-01.

## 1. Summary

- **Total distinct visual assets cataloged:** ~50 (across 8 pages).
- **Actual concept / architecture diagrams** (the interesting subset): **13**, all
  hosted at `/what-is-ebpf/` plus the front-page hero diagram. Everything else is
  logos, base64 hero images, book covers, or SVG placeholder cards.
- **Value tier counts:**
  - `high`: 5 diagrams (front-page hero + hook-overview + kernel-arch +
    map-architecture + loader).
  - `medium`: 5 (syscall-hook, tail-call, helper, clang, overview).
  - `low`: 3 (bcc, bpftrace, libbpf, go, geocities — small tool-specific).
  - `reject`: ~35 (all logos, conference/documentary hero art, book covers, blog
    thumbnails, empty SVG placeholder cards).
- **Top 6 picks for hello-ebpf docs** (see section 4 for prose):
  1. `hook-overview.png` — best canonical "where can eBPF attach?" figure. Anchors
     `getting-started/how-it-works.md`.
  2. `diagram.svg` (front-page hero) — clean domain-agnostic "eBPF = safe kernel
     extensions" picture. Anchors `index.md`.
  3. `kernel-arch.png` — Linux kernel layered view, useful once for readers new to
     kernel programming; belongs in `getting-started/how-it-works.md` or
     `architecture/plugin.md`.
  4. `map-architecture.png` — kernel-side and user-side view of a map with the
     BPF syscall between. Anchors `maps.md`.
  5. `loader.png` — verifier + JIT pipeline. Anchors `architecture/processor.md`
     or `getting-started/how-it-works.md`.
  6. `tailcall.png` — depicts prog-to-prog control transfer with fixed stack.
     Anchors `tail-calls.md`.

Surprise finding: `/applications/`, `/get-started/`, `/case-studies/`, `/blog/`,
`/labs/`, `/summit/`, `/labels/`, `/foundation/` have essentially **no reusable
technical diagrams**. All the value is concentrated in `/what-is-ebpf/`. Two of
the listed URLs (`/summit/`, `/labels/`) actually 404 today; `/foundation/`
redirects off-domain to ebpf.foundation.

## 2. License

**Verbatim license string, from the ebpf.io footer**
(retrieved from `https://ebpf.io/` on 2026-07-01):

> "The content of the ebpf.io website is licensed under a Creative Commons
> Attribution 4.0 International License."

Copyright line adjacent in the same footer:

> "© 2026 eBPF.io authors"

The footer links the license phrase to `https://creativecommons.org/licenses/by/4.0/`.

The identical wording is reproduced on every subpage inspected
(`/what-is-ebpf/`, `/applications/`, `/get-started/`, `/infrastructure/`,
`/case-studies/`, `/blog/`, `/labs/`). No per-image license overrides were
observed, so the CC-BY 4.0 grant applies uniformly to the diagrams cataloged
below.

### Attribution template hello-ebpf should use

Proposed caption template for each mirrored diagram
(place directly under the image in Markdown):

```
*Diagram: [ebpf.io](https://ebpf.io/what-is-ebpf/), © eBPF.io authors,
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
```

For mirrored copies stored under `docs/assets/ebpf-io/`, keep a small
`docs/assets/ebpf-io/CREDITS.md` listing every mirrored filename with its
original URL and retrieval date, so the attribution requirement is auditable
even if the caption template is ever changed.

## 3. Full inventory

Notes on URL columns: the `static/<hash>/<hash>/<name>.png` paths on
gatsby-generated pages are responsive-image derivatives. The stable filename is
the last segment (e.g. `hook-overview.png`); the intermediate hashes will change
whenever ebpf.io rebuilds. When mirroring, always fetch the *original*
`.png` / `.svg` and rename to the terminal filename.

| # | Image URL (from ebpf.io) | Source page | Description | Type | Value | Suggested target page | Notes |
|---|---|---|---|---|---|---|---|
| 1 | `/static/diagram-b6b32006ea52570dc6773f5dbf9ef8dc.svg` | `/` | Hero: "eBPF = programmable kernel with verifier + JIT feeding four use-case pillars (networking / observability / tracing / security)". | concept-diagram | high | `index.md` | Vector, scales cleanly. Use full-width above the fold. |
| 2 | `/static/diagram-mobile-c689f9914d640614f6c9d9fd216cce49.svg` | `/` | Mobile-portrait rearrangement of #1. | concept-diagram | low | none — use #1 with CSS | Only useful if we want responsive art directly; MkDocs handles resizing of #1. |
| 3 | `/static/networking-ab322d4814fa245653f2ca66c069ef92.svg` | `/` | Small pillar icon for "Networking" use case. | logo | reject | none | Decorative only. |
| 4 | `/static/observability-0e7ded4a90e87ea6a804f95a26f0ca71.svg` | `/` | Small pillar icon for "Observability". | logo | reject | none | Decorative only. |
| 5 | `/static/tracing-profiling-3dfcbe700747b291b99f006a5f659ba5.svg` | `/` | Pillar icon: "Tracing & Profiling". | logo | reject | none | Decorative only. |
| 6 | `/static/security-b930894381662f610535209d40a56245.svg` | `/` | Pillar icon: "Security". | logo | reject | none | Decorative only. |
| 7 | `/static/logo-black-98b7a1413b4a74ed961d292cf83da82e.svg` | site-wide | eBPF wordmark, black. | logo | reject | none | Trademark handling — mirror only if we need to reference "the eBPF project" visually. |
| 8 | `/static/logo-white-97b3a3be24b978d5e1dee2f003fa0114.svg` | site-wide | eBPF wordmark, white. | logo | reject | none | Same as #7. |
| 9 | (data:image/webp hero) | `/`, `/get-started/`, `/labs/` | eBPF Documentary hero card. | photo | reject | none | Base64 promotional art, not technical. |
| 10 | (data:image/webp) | `/` | Community Talks card. | photo | reject | none | Marketing. |
| 11 | `/static/azure-*.svg`, `/static/google-*.svg`, `/static/isovalent-*.svg`, `/static/meta-*.svg`, `/static/netflix-*.svg` | `/` | Corporate sponsor / adopter logos. | logo | reject | none | Trademarks belonging to third parties; CC-BY on the *site* does not launder them. Don't mirror. |
| 12 | `/static/e293240ecccb9d506587571007c36739/f2674/overview.png` | `/what-is-ebpf/` | "Overview": text illustration comparing kernel-module world vs eBPF world (safe, dynamic loading, no reboot). | concept-diagram | medium | `getting-started/how-it-works.md` (opening) | Slightly cartoonish; good as an intro. Prefer #14 when space is limited. |
| 13 | `/static/b4f7d64d4d04806a1de60126926d5f3a/12151/syscall-hook.png` | `/what-is-ebpf/` | Syscall path with an eBPF program hooked before/after the handler; user vs kernel space bar. | concept-diagram | medium | `getting-started/how-it-works.md` or `tracepoints.md` | Slightly redundant with #14 hook-overview. |
| 14 | `/static/99c69bbff092c35b9c83f00a80fed240/b5f15/hook-overview.png` | `/what-is-ebpf/` | The canonical eBPF "hook zoo" figure: kprobes / uprobes / tracepoints / XDP / TC / socket / cgroup / LSM around a running kernel. | concept-diagram | high | `getting-started/how-it-works.md` | Single most-cited eBPF diagram on the internet. Must-mirror. |
| 15 | `/static/a7160cd231b062b321f2a479a4d0848f/9180b/clang.png` | `/what-is-ebpf/` | Clang/LLVM: C source -> BPF bytecode. | flowchart | medium | `architecture/plugin.md` | We compile from Java bytecode, not C; use as context. |
| 16 | `/static/1a1bb6f1e64b1ad5597f57dc17cf1350/6515f/go.png` | `/what-is-ebpf/` | The Cilium Go library icon. | logo | reject | none | Ecosystem plug for a specific loader. |
| 17 | `/static/7eec5ccd8f6fbaf055256da4910acd5a/b5f15/loader.png` | `/what-is-ebpf/` | Program loader pipeline: source object -> verifier -> JIT -> attached program. | flowchart | high | `architecture/processor.md` or `getting-started/how-it-works.md` | Mirrors the pipeline we implement in bpf-processor + bpf-runtime; annotate to point at our layer. |
| 18 | `/static/e7909dc59d2b139b77f901fce04f60a1/ad1b4/map-architecture.png` | `/what-is-ebpf/` | eBPF map straddling kernel/user boundary; BPF programs on the left, user-space processes on the right, syscall API in between. | architecture | high | `maps.md` | Perfect anchor image for the maps chapter. |
| 19 | `/static/6e18b76323d8520107fab90c033edaf4/01295/helper.png` | `/what-is-ebpf/` | Helper-call API — set of stable functions callable from BPF programs. | concept-diagram | medium | `reference/annotations.md` (for `@BuiltinBPFFunction`) or `getting-started/how-it-works.md` | Useful for explaining why `@BuiltinBPFFunction` exists. |
| 20 | `/static/106a9d37e6b2b88e24b923d96e852dd5/f39e4/tailcall.png` | `/what-is-ebpf/` | Tail call from one BPF program to another, stack replaced, no return. | flowchart | high | `tail-calls.md` | Only decent canonical diagram of this concept. Anchor image. |
| 21 | `/static/560d57883f7df9beafb47eee1d790247/01295/kernel-arch.png` | `/what-is-ebpf/` | Linux kernel layered architecture (user space, syscalls, subsystems, hardware) with eBPF hook points annotated. | architecture | high | `getting-started/how-it-works.md` or `architecture/plugin.md` | Great for readers new to kernel programming. |
| 22 | `/static/def942c66b8c7565f0cfeab1c1017a80/c5f83/bcc.png` | `/what-is-ebpf/` | BCC toolkit visualization. | logo | low | none — reject | Ecosystem-specific, not analogous to hello-ebpf's model. |
| 23 | `/static/c53dfcbff6ea67a8f00896bd76e4c07c/c5f83/bpftrace.png` | `/what-is-ebpf/` | bpftrace one-liner illustration. | logo | low | none — reject | Different programming model. |
| 24 | `/static/f4991ee40f74df260dbb3e0541855044/b990c/libbpf.png` | `/what-is-ebpf/` | libbpf C-loader icon. | logo | low | none — reject | Ecosystem plug. |
| 25 | `/static/be6480b07c9214966e71cf5181a19070/26963/geocities.png` | `/what-is-ebpf/` | Screenshot of GeoCities used as an analogy for pre-JS web vs post-JS web. | screenshot | reject | none | Cute rhetorical device on ebpf.io; would look out of place in hello-ebpf. |
| 26 | ~60 `data:image/webp;base64,...` blobs across `/applications/` and `/infrastructure/` | `/applications/`, `/infrastructure/` | Cilium, Falco, Katran, Tetragon, Pixie, Calico, bpftool, aya, libbpfgo, PcapPlusPlus, hBPF, bpftime, rbpf, eBPF-for-Windows, etc. project logos. | logo | reject | none | Third-party marks; not covered by ebpf.io CC-BY grant even where technically CC-BY'd on the page. |
| 27 | `/static/linux-c804c72ffe26c5f49c21c092af8d847f.svg`, `/static/llvm-*.svg`, `/static/gcc-*.svg`, `/static/bpftool-*.svg` | `/infrastructure/` | Kernel / LLVM / GCC / bpftool marks. | logo | reject | none | Trademarks of unrelated projects. |
| 28 | `/static/wikipedia-*.svg`, `/static/stackoverflow-*.svg`, `/static/reddit-*.svg`, `/static/cilium-*.svg`, `/static/kernel-*.svg`, `/static/git-kernel-*.svg` | `/get-started/` | Small "learn more" resource icons. | logo | reject | none | Third-party. |
| 29 | Multiple `data:image/svg+xml` empty placeholders | `/get-started/`, `/labs/` | Book covers and lab-card placeholders (LazyLoad artefacts). | screenshot | reject | none | Not real images. |
| 30 | Blog thumbnails (base64 WebP) | `/blog/` | Thumbnails for 8 recent posts (LinkedIn kernel issue, Cloudflare, Lambda, GitHub, Nutanix, Datadog, Summit, file monitoring). | photo | reject | none | Post-specific promo art; per-post license unclear even if the surrounding page is CC-BY. |
| 31 | Not fetched — page 404 | `/summit/` | — | — | — | — | Returns HTTP 404 today; effectively removed from the site. |
| 32 | Not fetched — page 404 | `/labels/` | — | — | — | — | Returns HTTP 404 today. |
| 33 | Not fetched — off-domain redirect | `/foundation/` -> `ebpf.foundation` | — | — | — | — | Redirects to a different host (`ebpf.foundation`) not covered by the ebpf.io CC-BY grant. Do not mirror. |

## 4. Curated picks

Grouped by target hello-ebpf nav page.

### `index.md`

- **#1 — Front-page hero `diagram.svg`.** This is ebpf.io's own one-image
  answer to "what is eBPF?": verifier + JIT feeding four pillars. It's an SVG
  so it scales cleanly at any width, and it matches the tone we want on
  hello-ebpf's landing page ("safe, dynamic kernel extension, four use-case
  families, and hello-ebpf gives you access from Java"). Use it under the
  hero blurb with the standard CC-BY caption.

### `getting-started/how-it-works.md`

- **#14 — `hook-overview.png`.** This is the mental model most new users
  actually need: eBPF is not one thing, it's a set of hook points that share a
  verifier and a loader. Every subsequent chapter (`xdp.md`, `tc.md`,
  `kprobes.md`, `uprobes.md`, `tracepoints.md`, `lsm.md`) is a zoom-in on one
  hook. Placing this diagram once at the top of `how-it-works.md` lets those
  pages assume the reader has seen it.
- **#21 — `kernel-arch.png`.** Optional secondary figure directly under #14 for
  readers who don't yet have a Linux-kernel mental model. If the page gets
  crowded, prefer #14 alone and defer #21 to `architecture/plugin.md`.
- **#17 — `loader.png`.** Third figure, for the "so how does my program get
  from Java source to a running kernel program?" paragraph. Immediately before
  the diagram of hello-ebpf's own pipeline (bpf-compiler-plugin -> bpf-processor
  -> libbpf loader). Callout the correspondence: "ebpf.io's `Loader` box is
  what hello-ebpf builds for you at compile time."

### `maps.md`

- **#18 — `map-architecture.png`.** Kernel-side and user-side view with the
  syscall between them. This is exactly the shape of maps in hello-ebpf
  (`@BPFMapDefinition` on the kernel side, `BPFMap<K,V>` on the Java side, the
  ffm loader crossing between). Anchor at the top of `maps.md` before
  introducing HASH / ARRAY / PERCPU etc.

### `tail-calls.md`

- **#20 — `tailcall.png`.** There is no better public diagram of the "call and
  replace stack, no return" tail-call semantic. Should be the first figure
  on `tail-calls.md`, before the code example.

### `architecture/plugin.md` and `architecture/processor.md`

- **#17 — `loader.png`** (re-use). Show ebpf.io's canonical loader pipeline,
  then follow with a hello-ebpf-specific figure that adds our
  compile-plugin/processor stages at the front. Reader immediately sees how
  hello-ebpf slots into the standard picture.
- **#15 — `clang.png`** (optional). Only if we want to visually contrast
  "conventional flow: C -> Clang -> BPF bytecode" with "hello-ebpf flow:
  Java -> annotation processor -> BPF bytecode." Otherwise skip — it's tool-
  specific and slightly dated.

### `reference/annotations.md`

- **#19 — `helper.png`** (optional). Nice illustration to open the section
  documenting `@BuiltinBPFFunction`: helpers are the stable API surface that
  the kernel exposes to BPF programs, and every `@BuiltinBPFFunction` on the
  Java side corresponds to one entry there. Use as a small side figure, not
  hero size.

## 5. Rejected but worth knowing

Documented so future writers don't rediscover and re-litigate these.

- **All corporate / project logos (Azure, Google, Meta, Netflix, Isovalent,
  Cilium, Falco, Katran, Tetragon, Pixie, Calico, bpftool, aya, libbpfgo,
  bpftime, hBPF, rbpf, eBPF-for-Windows, PcapPlusPlus, Linux, LLVM, GCC).**
  Third-party trademarks. ebpf.io's site-wide CC-BY 4.0 grant covers ebpf.io's
  own content, not marks owned by other projects and companies. Even mirroring
  under CC-BY is legally messy. Reject uniformly. If we ever want to visually
  cite an ecosystem project we should either use its own logo per that
  project's brand guidelines, or link out.

- **`overview.png` (#12) and `syscall-hook.png` (#13).** Both are decent
  concept diagrams but they overlap with `hook-overview.png` (#14). If
  `how-it-works.md` mirrors #14, adding either creates visual clutter without
  new information. Defer.

- **`bcc.png`, `bpftrace.png`, `libbpf.png`, `go.png` (#22, #23, #24, #16).**
  Ecosystem-specific loader / language logos. hello-ebpf offers a *different*
  programming model (Java + annotation processor), so anchoring our docs on
  another loader's visual identity would confuse readers into thinking we
  reuse their stack.

- **`geocities.png` (#25).** GeoCities screenshot used on ebpf.io as a rhetorical
  device ("eBPF is to the kernel what JavaScript was to the browser"). Fun
  in a keynote, out of place in reference documentation.

- **`diagram-mobile.svg` (#2).** Portrait-orientation variant of the front-page
  hero. MkDocs / Material already handles responsive resizing of #1, so
  keeping both is redundant.

- **Documentary and community photos / conference art (#9, #10, and the base64
  hero on `/labs/`).** Marketing content, no technical signal.

- **Book cover placeholder SVGs and blog thumbnails on `/get-started/`,
  `/blog/`, `/labs/`.** Either LazyLoad placeholders (blank) or per-post promo
  art of unclear provenance (individual blog posts may not be under CC-BY the
  same way the site chrome is).

- **Whole pages: `/summit/`, `/labels/`, `/foundation/`.** The first two 404
  today; the third redirects off-domain to `ebpf.foundation`, which is a
  different site with a different (unread) license and no relevant
  technical diagrams anyway.

- **`docs.ebpf.io`.** Explicitly out of scope for this task (there's a
  sibling research doc for that).

## 6. Retrieval provenance

Fetched via WebFetch on 2026-07-01. Pages inspected:

- `https://ebpf.io/` — front page, hero diagram, license footer.
- `https://ebpf.io/what-is-ebpf/` — richest source; all high-value technical
  diagrams live here. Fetched twice with different prompts to confirm the
  image list is complete.
- `https://ebpf.io/applications/` — project cards, no technical diagrams
  beyond ecosystem overview base64 blobs.
- `https://ebpf.io/get-started/` — resource icons and book covers only.
- `https://ebpf.io/infrastructure/` — kernel / tooling / library logos, no
  reusable diagrams.
- `https://ebpf.io/case-studies/` — text-only.
- `https://ebpf.io/blog/` — post thumbnails only.
- `https://ebpf.io/labs/` — placeholder cards only.
- `https://ebpf.io/summit/` — 404.
- `https://ebpf.io/labels/` — 404.
- `https://ebpf.io/foundation/` — 301 redirect to `ebpf.foundation` (off-domain,
  not surveyed).

If we later mirror any of these diagrams, snapshot the source URL and
retrieval date into `docs/assets/ebpf-io/CREDITS.md` so the attribution stays
verifiable even after ebpf.io re-hashes its static paths.
