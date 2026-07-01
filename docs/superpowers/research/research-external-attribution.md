# Research: external-content attribution and licensing

Synthesis doc consolidating the licensing / attribution / audit-trail rules that
hello-ebpf docs must follow when mirroring or citing content from four external
sources: **ebpf.io** (CC-BY 4.0 site-wide), **docs.ebpf.io** (same origin, same
grant), the **sched-ext/scx** project (BSD-2-Clause + BPF-1.0 for code; docs
inherit that), and the maintainer's own **mostlynerdless.de blog series**
(maintainer-authored, treated as first-party but source-attributed).

Companion to:
- [`research-blog-series.md`](research-blog-series.md)
- [`research-ebpf-io-diagrams.md`](research-ebpf-io-diagrams.md)
- [`research-docs-ebpf-io.md`](research-docs-ebpf-io.md)
- [`research-scx-docs.md`](research-scx-docs.md)

## 1. Summary of licenses per source

| Source | License | Applies to | Attribution required? | Modification allowed? |
|---|---|---|---|---|
| ebpf.io (`https://ebpf.io/`) | CC-BY 4.0 (site-wide footer grant) | Site content authored by "eBPF.io authors" | Yes — attribution + license link | Yes, with attribution |
| docs.ebpf.io (`https://docs.ebpf.io/`) | Same CC-BY 4.0 grant (per site footer, per `research-docs-ebpf-io.md`) | Concept and reference pages | Yes | Yes |
| ebpf.io / docs.ebpf.io third-party logos | **Not covered** — trademarks of third parties (Cilium, Falco, Katran, Meta, Google, Azure, Netflix, Isovalent, Linux, LLVM, GCC, etc.) | Any third-party wordmark or logo appearing on the CC-BY sites | Trademark law, not CC-BY | **Do not mirror** |
| sched-ext/scx repo | BSD-2-Clause (code) + BPF-1.0 / GPL-2.0 for kernel-adjacent files | Repo source and docs | Link-out preferred over mirroring | N/A — we don't mirror scx source |
| mostlynerdless.de (blog series) | Maintainer-authored (Johannes Bechberger). Not under a public open license, but reproducible in hello-ebpf docs under a first-party arrangement (same author). | Diagrams and prose from Parts 1–20 + preambles | Source-attribution caption (see §3) | Yes, with edits noted |
| Blog third-party embeds (ebpf.io screenshots inside blog posts, google-slides image, etc.) | Third-party — same problem as ebpf.io logos | Not mirrored via the blog | Follow source's own license | **Do not mirror via blog; go to original if it exists** |

## 2. Attribution templates

### 2.1 ebpf.io and docs.ebpf.io diagrams

**Verbatim license string** from the ebpf.io footer, retrieved 2026-07-01 (see
`research-ebpf-io-diagrams.md` §2):

> "The content of the ebpf.io website is licensed under a Creative Commons
> Attribution 4.0 International License."

Copyright line adjacent:

> "© 2026 eBPF.io authors"

Caption template — one Markdown block, placed directly under the image:

```markdown
*Diagram: [ebpf.io](https://ebpf.io/what-is-ebpf/), © eBPF.io authors,
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
```

For docs.ebpf.io diagrams specifically, swap the URL to the source page:

```markdown
*Diagram: [docs.ebpf.io](https://docs.ebpf.io/linux/concepts/verifier/),
© eBPF.io authors, [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
```

### 2.2 Maintainer's own blog diagrams

The maintainer authored these; no CC-BY grant is on record, but they are
reused in first-party docs by the same author. Use a **source-note caption**
that makes provenance visible without pretending it's an open license:

```markdown
*Diagram from Johannes Bechberger,
["Hello eBPF: <Post Title> (<N>)"](https://mostlynerdless.de/blog/YYYY/MM/DD/<slug>-<N>/).*
```

If the diagram was redrawn or lightly edited for the docs, add `Redrawn`:

```markdown
*Diagram redrawn from Johannes Bechberger,
["Hello eBPF: <Post Title> (<N>)"](https://mostlynerdless.de/blog/YYYY/MM/DD/<slug>-<N>/).*
```

Never hotlink to `mostlynerdless.de/wp-content/uploads/...` — the site's
media paths are not a stable CDN and images get rehashed on WordPress updates.
Always mirror into `docs/assets/blog/` (see §4).

### 2.3 sched-ext/scx and kernel.org

We do not mirror scx source or diagrams. All references are link-outs:

```markdown
See [scx `OVERVIEW.md`](https://github.com/sched-ext/scx/blob/main/OVERVIEW.md)
for the DSQ concept and full scheduling cycle.
```

For kernel.org kfunc/ABI references:

```markdown
The authoritative kfunc signatures live in the kernel's
[`sched-ext.html`](https://www.kernel.org/doc/html/latest/scheduler/sched-ext.html).
Note the doc's own stability disclaimer: "The APIs provided by sched_ext to
BPF schedulers programs have no stability guarantees."
```

## 3. Audit files

Each set of mirrored external assets gets its own `CREDITS.md` file. This is
the paper trail an external reader (or copyright complainant) can point at to
verify each image's license and provenance.

### 3.1 `docs/assets/ebpf-io/CREDITS.md`

One row per mirrored file. Columns: local filename, upstream URL at time of
mirroring (the `.png` / `.svg` terminal filename, not the gatsby-hashed path),
retrieval date, target doc page.

```markdown
# Credits — ebpf.io mirrored diagrams

All files in this directory are © eBPF.io authors and licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) per the ebpf.io
site-wide footer grant (verified 2026-07-01).

| Local file | Upstream URL (terminal filename) | Retrieved | Used on |
|---|---|---|---|
| `diagram.svg` | https://ebpf.io/static/diagram.svg | 2026-07-01 | `index.md` |
| `hook-overview.png` | https://ebpf.io/static/hook-overview.png | 2026-07-01 | `getting-started/how-it-works.md` |
| `kernel-arch.png` | https://ebpf.io/static/kernel-arch.png | 2026-07-01 | `getting-started/how-it-works.md` |
| `loader.png` | https://ebpf.io/static/loader.png | 2026-07-01 | `architecture/processor.md` |
| `map-architecture.png` | https://ebpf.io/static/map-architecture.png | 2026-07-01 | `maps.md` |
| `tailcall.png` | https://ebpf.io/static/tailcall.png | 2026-07-01 | `tail-calls.md` |
| `helper.png` | https://ebpf.io/static/helper.png | 2026-07-01 | `reference/annotations.md` |
```

Note: the actual gatsby-hashed paths on ebpf.io (`static/<hash>/<hash>/<name>.png`)
are unstable derivatives. Always fetch the plain terminal filename and record
that in `CREDITS.md`.

### 3.2 `docs/assets/blog/CREDITS.md`

For maintainer-blog diagrams, the audit file captures which blog post each
image came from so a future writer can re-download if a diagram is updated
upstream.

```markdown
# Credits — mostlynerdless.de blog diagrams

All files in this directory are © Johannes Bechberger, mirrored from the
"Hello eBPF" blog series at https://mostlynerdless.de/. Reproduced in
hello-ebpf documentation as first-party content by the same author.

| Local file | Blog post | Original URL | Retrieved |
|---|---|---|---|
| `map-bridge.png` | Part 2 | https://mostlynerdless.de/wp-content/uploads/2024/01/ebpf_maps-2000x425.png | 2026-07-01 |
| `tail-call-stack.png` | Part 4 | https://mostlynerdless.de/wp-content/uploads/2024/02/tail_call-2000x599.png | 2026-07-01 |
| `bcc-vs-libbpf.png` | Part 5 | https://mostlynerdless.de/wp-content/uploads/2024/02/bcc_vs_bpf-1-2000x1125.png | 2026-07-01 |
| `struct-layout.png` | Part 7 | https://mostlynerdless.de/wp-content/uploads/2024/03/struct_layout-2000x760.png | 2026-07-01 |
| `xdp-filter.png` | Part 9 | https://mostlynerdless.de/wp-content/uploads/2024/04/xdp_filter-1-2000x1005.png | 2026-07-01 |
| `memory-segments.png` | Part 10 | https://mostlynerdless.de/wp-content/uploads/2024/05/memory_segments.png | 2026-07-01 |
| `ethhdr-tree.png` | Part 11 | https://mostlynerdless.de/wp-content/uploads/2024/07/ethhdr-2000x1111.png | 2026-07-01 |
| `compiler-pipeline.png` | Part 12 | https://mostlynerdless.de/wp-content/uploads/2024/07/compiler_pipeline-2000x1125.png | 2026-07-01 |
| `network-stack-xdp-tc.png` | Part 13 | https://mostlynerdless.de/wp-content/uploads/2024/08/network_stack-1.png | 2026-07-01 |
| `time-slice-two-tasks.png` | Part 15 | https://mostlynerdless.de/wp-content/uploads/2024/09/Slide12-2000x1125.png | 2026-07-01 |
| `scheduler-dance-dsqs.png` | Part 15 | https://mostlynerdless.de/wp-content/uploads/2024/09/scheduler_dance-2000x1847.png | 2026-07-01 |
| `task-control-diagram.png` | Part 16 | https://mostlynerdless.de/wp-content/uploads/2024/12/task_control_diagram-2000x1680.png | 2026-07-01 |
| `lottery-bowl.png` | Part 17 | https://mostlynerdless.de/wp-content/uploads/2024/12/lottery_bowl.png | 2026-07-01 |
| `chaos-state-machine.png` | Part 19 | https://mostlynerdless.de/wp-content/uploads/2025/02/image-3.png | 2026-07-01 |
```

(This exact list is a starting point drawn from
[`research-blog-series.md`](research-blog-series.md); §4 of that doc has the
full inventory including screenshots and photos that we deliberately skip.)

### 3.3 `docs/LICENSE-CC-BY-4.0.md`

One file, one canonical copy of the license text, referenced from every
caption template's link and from each `CREDITS.md`. Contents: the full plain-
text CC-BY 4.0 legal code from
[`creativecommons.org/licenses/by/4.0/legalcode.txt`](https://creativecommons.org/licenses/by/4.0/legalcode.txt).

Rationale: CC-BY doesn't require redistributing the full text, but keeping it
in-tree means we can point at a stable local anchor even if
`creativecommons.org` restructures its URLs.

## 4. Directory layout for mirrored assets

```
docs/
├── assets/
│   ├── ebpf-io/
│   │   ├── CREDITS.md
│   │   ├── diagram.svg
│   │   ├── hook-overview.png
│   │   ├── kernel-arch.png
│   │   ├── loader.png
│   │   ├── map-architecture.png
│   │   ├── tailcall.png
│   │   └── helper.png
│   └── blog/
│       ├── CREDITS.md
│       ├── map-bridge.png
│       ├── tail-call-stack.png
│       ├── ...
└── LICENSE-CC-BY-4.0.md
```

Two rules for filenames in `assets/`:

1. **Rename on mirror.** Upstream URLs have hashed segments (ebpf.io) or WordPress
   size suffixes (`-2000x981`); local filenames should be short, semantic, and
   stable. Record the upstream URL in `CREDITS.md` instead of encoding it in the
   filename.
2. **No spaces, no capitals, no size suffixes.** `map-architecture.png`, not
   `Map Architecture (2000x1000).png`.

## 5. What we deliberately do not mirror

Restatement from [`research-ebpf-io-diagrams.md`](research-ebpf-io-diagrams.md)
§5 and [`research-blog-series.md`](research-blog-series.md) §3 photographs:

- **All corporate / project logos.** Azure, Google, Meta, Netflix, Isovalent,
  Cilium, Falco, Katran, Tetragon, Pixie, Calico, bpftool, aya, libbpfgo,
  bpftime, hBPF, rbpf, eBPF-for-Windows, PcapPlusPlus, Linux, LLVM, GCC. Third-
  party trademarks; the CC-BY grant on the *site* does not cover them.
- **eBPF wordmark (black/white).** Trademark of the eBPF project. Only mirror
  if hello-ebpf docs need to visually cite "the eBPF project" and even then
  prefer a link-out to a mirrored logo.
- **Third-party embeds inside blog posts** — screenshots of ebpf.io graphics,
  Google Slides images, terminal outputs from unrelated tools. If we want the
  ebpf.io graphic, we fetch it from ebpf.io directly (§3.1), not through the
  blog.
- **Photographs of the author, cats, museums, conferences.** No documentation
  value. Skip.
- **Blog thumbnails and book covers on ebpf.io.** Post-specific promo art of
  unclear license — even if the surrounding page is CC-BY, individual
  thumbnails may not be.
- **`docs.ebpf.io` bpf() syscall / libbpf userspace API / libxdp pages.** Not a
  licensing issue — a scope issue — but flagging alongside the other "don't
  link" cases for a single reference point. See
  [`research-docs-ebpf-io.md`](research-docs-ebpf-io.md).

## 6. Provenance discipline

When mirroring a diagram:

1. Fetch the terminal filename URL (not the hashed derivative). For ebpf.io
   that means `https://ebpf.io/static/<name>.png`. For blog images it means
   `https://mostlynerdless.de/wp-content/uploads/YYYY/MM/<slug>.png`.
2. Rename locally per §4 rule 1.
3. Add a row to the appropriate `CREDITS.md` with the exact upstream URL and
   today's date.
4. Add the caption (§2) directly under the image in the Markdown file that
   uses it.
5. Commit all four changes (image, CREDITS row, doc reference, license file if
   first time) in a single commit.

When a mirrored diagram is later updated upstream:

1. Fetch again to the same local filename (overwrite).
2. Update the `Retrieved` column in `CREDITS.md`.
3. Commit.

Do not delete old versions from git history — git already preserves them and
the historical rows in `CREDITS.md` serve as a change log.

## 7. Non-goals for Spec 1

Spec 1 (infrastructure) does **not** need to mirror any diagrams. It only
needs to:

- Create the empty directories `docs/assets/ebpf-io/` and `docs/assets/blog/`
  with stub `CREDITS.md` files (headers only, no rows).
- Add `docs/LICENSE-CC-BY-4.0.md` with the full CC-BY 4.0 legalcode.
- Reference this doc from the style guide's "external content" rule.

Actual diagram mirroring happens in Spec 2 as each page is rewritten. Each
Spec 2 page-authoring task does the mirror + caption + CREDITS row for its
own page's diagrams.

## 8. Legal-safety checklist for reviewers

Before Spec 2 merges a page that mirrors external content:

- [ ] Caption present directly under image (§2).
- [ ] Local filename in `assets/*/` matches CREDITS row exactly.
- [ ] Upstream URL in CREDITS row resolves (verify by curl or browser).
- [ ] License is CC-BY 4.0 or same-author first-party — no ambiguous or
      unmarked third-party content.
- [ ] Image is a diagram/illustration, not a corporate logo or photograph.
- [ ] For blog images: URL preserves any known typos (e.g. Part 19's
      `helle-ebpf` slug, per `research-blog-series.md` §2).
