# Spec 1 Implementation Brief — Docs Restructure Infrastructure

Handoff for the plan writer. The full design is in
[`2026-07-01-docs-restructure-spec1-design.md`](2026-07-01-docs-restructure-spec1-design.md);
this brief captures scope, constraints, and non-obvious traps so the plan
does not need to rediscover them.

Background research the plan writer can also consult (produced 2026-07-01
under `docs/superpowers/research/`):

- `research-blog-series.md` — 22-post "Hello eBPF" blog inventory.
- `research-ebpf-io-diagrams.md` — CC-BY 4.0 diagram audit of ebpf.io.
- `research-docs-ebpf-io.md` — docs.ebpf.io further-reading map.
- `research-scx-docs.md` — sched-ext/scx anchor catalog.
- `research-external-attribution.md` — CC-BY 4.0 attribution rules.
- `research-cornerstone-cross-refs.md` — 10-sample "red line" arc.

None of the research docs are Spec 1 deliverables; they exist so Spec 2's
page-authoring tasks can cross-reference external content without re-doing
the survey. Spec 1 only needs to land the *scaffolding* those docs assume
(§5a of the design).

## What Spec 1 delivers

Infrastructure and inventory, not prose. Nine deliverables:

1. `docs/superpowers/style-guide.md` — the ten-plus-one-rule guide.
2. Six audit tables under `docs/superpowers/audit/` covering annotations,
   BPFJ helpers, runtime API, hooks, samples, and plugin extension points.
3. A working `pymdownx.snippets` pipeline with one proof-of-life migration.
4. External-content scaffolding: `docs/assets/{ebpf-io,blog}/CREDITS.md`
   stubs, `docs/LICENSE-CC-BY-4.0.md`, and the two `docs/index.md`
   corrections (blog count 18→20; broken Part 1 URL).
5. Stubs for every new page named in the target nav.
6. `mkdocs.yml` flipped to the new nav, with shim files at the old URLs.
7. A `mkdocs build --strict` step wired into the `docs` CI job.

Everything else — page rewrites, Javadoc fixes, feature-matrix refresh,
generated-C reference, actual diagram mirroring — is Spec 2 or later.

## What Spec 1 does NOT touch

- No Java source. No sample edits. No compiler-plugin changes.
- No archetype changes.
- No new mkdocs plugins beyond `pymdownx.snippets` (already transitive via
  `mkdocs-material`).
- No Javadoc build or publish pipeline.
- No `README.md` edits.

If the plan writer feels the itch to rewrite prose or fix a sample, that's
Spec 2 signal. Note it in the audit's `Gap` column and move on.

## Non-obvious constraints the plan must respect

**Ordering is load-bearing.** The design's §12 spells out six commits in
sequence. Commit 4 (stubs + carves) leaves files unlinked; commit 5 flips
the nav; commit 6 tightens CI. Any deviation risks an intermediate state
where `mkdocs build --strict` fails. The plan should preserve this order
and call out commit boundaries explicitly.

**Audits are parallel-safe.** The six audit tables touch disjoint files
and can be produced by different subagents concurrently. The plan should
exploit this — one implementer subagent per audit is a clean fit.

**Nav flip is atomic.** Commit 5 must update `mkdocs.yml`, create the
shim files at old paths, and register everything in `not_in_nav:` in a
single commit. Splitting this commit breaks the site mid-way.

**Preconditions before Task 1.** The plan's first task should verify
`mkdocs build --strict` is green on `main` — either locally
(`pip install -r docs-requirements.txt` first) or by pointing at the
most recent green CI `docs` job. Skipping this hides a pre-existing
break inside Spec 1's diff.

**No mac builds.** hello-ebpf builds/tests run only on thinkstation.
Spec 1 has no Java builds, but `mkdocs build --strict` locally is fine on
the mac (pure Python, no repo build dependencies).

**Snippet marker discipline.** Style-guide rule 10 says comments inside
`--8<--` regions must read like documentation. The proof-of-life
migration task must exemplify this — pick a sample where the region's
comments already read cleanly, or delete/relocate scratch comments before
adding the region markers.

**Audit row source > illustrative list.** Every audit's row set is
derived from a grep sweep, not from the design's illustrative examples.
If grep finds an annotation not listed in the design, it gets a row.
If a listed annotation is not in grep output, no row. The plan should
frame audit tasks around grep, not around the design's lists.

**Blog-series count is 20, not 18.** The user's earlier answer of "18 is
correct" predates the research pass that fetched Parts 17–20 directly.
`docs/index.md` line 101 says "18-part blog series"; the correct count is
20 numbered posts + Part 14.5 + 2 preambles. This is one of the two
`docs/index.md` corrections in commit 3.

**Part 1 URL in `docs/index.md` is a hard 404.** The linked slug
`writing-ebpf-programs-in-java-with-hello-ebpf-1-hello-world` does not exist.
Fix to `hello-ebpf-developing-ebpf-apps-in-java-1`. (Part 19 has a URL typo
`helle-ebpf` that must be preserved verbatim in any Spec 2 cross-link —
"correcting" it will 404. Not a Spec 1 concern, but flagged so nobody fixes
it in commit 3 by accident.)

**docs.ebpf.io is a current Linux kernel reference.** Treat it as an
authoritative link target — Spec 2 links to it liberally per
`research-docs-ebpf-io.md` (sitemap lastmod 2026-06-29, MkDocs-Material
site scoped to kernel + libbpf/libxdp/scx reference material). Not a
Spec 1 concern in terms of files touched, but flagged so the plan
writer does not treat it as a cautious link target.

**sched-ext `scheds/c/scx_simple/README.md` no longer exists.** Any earlier
brief suggesting that path is stale — C example schedulers moved to the
kernel tree at `tools/sched_ext/` and to a separate `scx-c-examples` repo.
The primary comparison anchor for hello-ebpf's userspace runtime is
`scheds/rust/scx_rustland/README.md`. See `research-scx-docs.md` for the
full anchor catalog. Again, not a Spec 1 concern in terms of files touched,
but flagged so audit and stub tasks don't silently cite dead paths.

## Suggested task shape (for the plan writer to refine)

Roughly one commit per section below; each is a plan task. Audits can be
sub-tasked further if parallelization is worth the coordination cost.

1. **Preconditions + style guide.** Verify `mkdocs build --strict` green,
   write `docs/superpowers/style-guide.md`, commit.
2. **Six audits** (may parallelize). Each audit is: grep the module, walk
   `docs/*.md` for symbol mentions, produce the table, commit. Landing
   order does not matter as long as all six land before commit 5.
3. **Snippets pipeline + proof of life + external scaffolding.** Add
   `pymdownx.snippets` to `mkdocs.yml`, add `[start:x]/[end:x]` markers to
   one sample under `bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/`,
   switch one existing doc block to use the include. In the same commit,
   land the external-content scaffolding: create `docs/assets/ebpf-io/CREDITS.md`
   and `docs/assets/blog/CREDITS.md` as stubs (headers only), create
   `docs/LICENSE-CC-BY-4.0.md` with the full CC-BY 4.0 legalcode, and correct
   `docs/index.md`'s "18-part" → "20-part" and the broken Part 1 URL. Commit.
4. **Stubs + carves.** Create every new stub file, split `sched_ext.md`
   along the 16-row mapping in §6.1, move `helpers.md` → `reference/bpfj.md`,
   move `userspace-scheduler.md` → `sched-ext/userspace.md` (fix the
   relative link), move `scheduler-article.md` → `sched-ext/cookbook.md`.
   Nav still points at old paths at this commit. Commit.
5. **Nav flip + shims.** Update `mkdocs.yml` nav, add shim files at old
   paths, list them in `not_in_nav:`. Site now lives at new URLs. Commit.
6. **CI gate.** Add explicit `mkdocs build --strict` step to the `docs`
   job before `mkdocs gh-deploy --force`. Commit.

## Review gates the plan must include

Every task ends with one or both of these:

- **Build gate.** `mkdocs build --strict` passes locally (or via a
  scratch CI run) after every commit that touches doc files.
- **Reader-test gate.** Not required in Spec 1 — Spec 1 produces no prose.
  It applies in Spec 2.

## Open questions the plan writer can defer

These belong to Spec 2, but the plan should note them so nobody
accidentally addresses them here:

- Verifier-features matrix refresh against 6.17.
- Whether generated-C gets its own reference page.
- CO-RE / BTF coverage placement.
- Javadoc HTML publishing pipeline.
- Actual mirroring of ebpf.io / blog diagrams (per-page, in Spec 2). Spec 1
  lands only the empty `CREDITS.md` stubs and the license file.
- Sample-drift footnote convention for Parts 2, 3, 8, 14, 20 (per
  `research-cornerstone-cross-refs.md` §7). Spec 2 decides the exact form
  when the affected pages are authored.
- Part 19 URL typo preservation (`helle-ebpf`). Only surfaces when Spec 2
  cross-links Part 19 — flagged so no Spec 2 author "corrects" it by reflex.

## Success criteria

Spec 1 is done when the design's §10 deliverables checklist is all boxes
ticked, both local and CI `mkdocs build --strict` are green, and every
nav entry resolves in a manual click-through.

## Handoff

Plan writer: read the full design first, then produce
`docs/superpowers/plans/2026-07-01-docs-restructure-spec1.md` following
the writing-plans skill. Use this brief for scope and constraints; use
the design for details.
