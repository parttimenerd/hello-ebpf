# Docs Restructure — Spec 1: Infrastructure, Audit, and Nav

## 1. Goal

Produce a complete inventory of hello-ebpf's user-visible surface, restructure
the mkdocs nav to fit four audiences, and stand up an includes-based examples
pipeline so future doc snippets cannot drift. This spec is infrastructure only.
No page rewrites happen here. The follow-up **Spec 2** consumes the inventory
produced here and drives per-page content authoring.

Audiences the docs must serve, in order of expected traffic:

1. Java developers new to eBPF.
2. eBPF-fluent evaluators (from C / libbpf / bpftrace) sizing up the framework.
3. sched_ext scheduler authors.
4. Contributors and maintainers.

## 2. Non-goals

- No new prose on individual features. Adding pages, moving pages, and cutting
  section headers within existing pages is fine; rewriting sentences is not.
- No changes to any Java source, samples, or the compiler plugin.
- No archetype changes. `bpf-archetype/` stays as it is.
- No new mkdocs plugins beyond `pymdownx.snippets` (needed for `--8<--` includes).

## 3. Style guide (`docs/superpowers/style-guide.md`)

Codified from the writing patterns already visible in `docs/diagnostics.md`,
`docs/shared-maps.md`, `docs/userspace-scheduler.md`, and `docs/cookbook.md`.
Every task in Spec 2 checks its output against this guide during review.

Nine rules, one paragraph each, each rule paired with a good and a bad example
lifted from existing pages (or fabricated when no natural bad example exists).

1. **Problem → cause → fix.** Never a fix without stating the cause. The
   cookbook and diagnostics use this shape uniformly; new pages must too.
2. **Terse, declarative.** No hedging ("usually", "in some cases", "you might
   want to"). Kernel realities are stated; framework guarantees are stated.
3. **Every claim carries an artifact.** A code block, a shell command, a file
   path, a kernel-config line, a link to the source, or a link to a sample.
   Prose without an artifact is a smell.
4. **Code blocks under ~15 lines by default; up to ~30 lines when the example
   genuinely needs the extra lines.** Anything past 30 lines lives in a real
   sample file and is included via `--8<--` (see §5).
5. **Cross-link to source.** Use relative paths (`../bpf-samples/…`). The
   mkdocs build resolves these to GitHub via `repo_url`.
6. **Sectioned by numbered progression on process pages
   (Getting Started, Userspace Scheduler); symbol-per-heading on reference
   pages (Diagnostics, Annotations catalog, BPFJ catalog).** Do not mix
   modes in one page.
7. **Motivation before mechanics** on any page that introduces a new concept.
   Shared-maps opens with "Why split a program at all?" before `@SharedFrom`;
   Userspace Scheduler explains when/why before showing `policy()`.
8. **Kernel realities framed concretely.** Not "recent kernels support X" but
   "kernel ≥ 6.11 with CONFIG_SCHED_CLASS_EXT=y". Include the verification
   command when non-obvious.
9. **No emoji. No exclamation marks. Admonitions (`!!! warning`, `!!! note`)
   only for hazards, kernel gates, or "this doc lags the code" warnings —
   never for filler emphasis.**

The style guide also documents the **reader test** review gate borrowed from
the `doc-coauthoring` skill: for every new page in Spec 2, a fresh subagent
with no prior context reads the page cold and reports what it did not
understand. That gate is defined here so Spec 2 tasks can reference it by
name.

## 4. Audit (`docs/superpowers/audit/`)

Six audit tables, one Markdown file each, all excluded from mkdocs nav (they
render if visited directly but do not appear in navigation). Excluded via a
top-level `not_in_nav:` list in `mkdocs.yml`.

Common table schema for all six audits:

```
| Symbol | Source path | Purpose (≤ 12 words) | Documented in | Gap | Target page |
```

- **Symbol.** Exact identifier (`@BPFFunction`, `BPFJ.bpfArenaAllocPages`, `SEC("xdp")`, `RustlandFifoSample`, etc.).
- **Source path.** Repo-relative path to the definition file, with `:line` where useful.
- **Purpose.** One-line summary, lifted from javadoc when present; empty and marked `TODO:javadoc` when the source has no doc comment (Spec 2 will fix the code-side gap).
- **Documented in.** Grep result across `docs/*.md`. Format: `page.md#anchor` or blank.
- **Gap.** One of `OK` / `Partial` / `Missing` / `Rewrite`. Definitions:
  - `OK` — symbol is named on its target page, with a working example.
  - `Partial` — symbol is named or shown in a table but has no dedicated coverage.
  - `Missing` — symbol is not mentioned in any page.
  - `Rewrite` — coverage exists but violates the style guide (e.g. no cause section, dead example).
- **Target page.** The page in the new nav (§5) where the symbol should end up. May be shared across many rows (e.g. all `@BPF*` annotations land on `reference/annotations.md`).

The six audits, in dependency order so downstream tables can reference upstream anchors:

1. **`audit-annotations.md`** — every `@` annotation shipped for user code, including non-BPF-prefixed ones (`@Unsigned`, `@Size`, `@InArena`, `@Kptr`, `@TrustedPtr`, `@BPFNullable`, `@BoundedBy`, `@Includes`, `@KernelBTF`, `@AllowDirectVal`, `@JavaOnly`, `@SharedFrom`, `@Requires`, `@Properties/@Property`, `@InlineUnion`, `@PassByRef`, `@Offset`, `@Sizes`, `@CustomType`, `@KFunc`, `@BuiltinBPFFunction`, `@BPFAbstraction`, `@BPFJavaInline`, `@BPFFunction`, `@BPFFunctionAlternative`, `@BPFInline`, `@BPFTimer`, `@BPFMapDefinition`, `@BPFMapClass`, `@BPFImpl`, `@BPFInterface`, `@Kprobe/@Kretprobe`, `@Uprobe/@Uretprobe`, `@LSM`, `@Tracepoint/@RawTracepoint`, `@Ksyscall`, `@Fentry/@Fexit`, `@ProgramType`, `@InternalBody`, `@InternalMethodDefinition`, `@MethodIsBPFRelatedFunction`, `@SuppressBPFWarning`, `@NotUsableInJava`, `@OriginalName/@OriginalNames`, `@EnumMember`).
2. **`audit-bpfj.md`** — every `public static` in `BPFJ.java` (~52 methods).
3. **`audit-runtime-api.md`** — `BPFProgram`, `BPFHashMap`, `BPFArray`, `BPFRingBuffer`, `BPFArena`, `BPFPerCpuArray`, `BPFPerCpuHashMap`, `BPFLruHashMap`, `BPFLruPerCpuHashMap`, `BPFQueue`, `BPFStack`, `BPFBloomFilter`, `BPFArrayOfMaps`, `BPFHashOfMaps`, `BPFProgArray` (tail calls), `GlobalVariable`, `BPFTimer` Java API, `StackSymbolizer`, JFR event types, `TailCall*` API, `SchedulerExtension` test infra, `Opts`, `QueuedTask` (userspace scheduler), `Scheduler` abstract class callbacks, error classifier public API. One row per public class or per public method where the method is the primary surface.
4. **`audit-hooks.md`** — one row per `SEC(...)` shape the plugin can emit. Columns adapted: **Section string**, **Java annotation**, **Min kernel**, **Source (plugin file:line where the section string is chosen)**, **Documented in**, **Gap**, **Target page**. Covers: xdp, xdp/{devmap,cpumap}, tc/*, kprobe, kretprobe, uprobe, uretprobe, fentry, fexit, tracepoint/*, raw_tracepoint/*, ksyscall, lsm/*, cgroup/*, perf_event, sched_ext (struct_ops entries — one row per operation), sockops, sk_msg, sk_skb, cgroup_skb, cgroup_sock.
5. **`audit-samples.md`** — every `.java` under `bpf-samples/src/main/java/me/bechberger/ebpf/samples/`. Columns adapted: **Sample**, **Hook types used**, **What it demonstrates (≤ 15 words)**, **Reference-quality? (Y/N)**, **Documented in**, **Target page**. `Reference-quality? = Y` means the sample is small, self-contained, and idiomatic enough that Spec 2 may include it via `--8<--`. Everything else is demo-only.
6. **`audit-plugin.md`** — user-visible extension points of the compiler plugin, marked `[audience: contributor]`: plugin flags (`-Xplugin:BPFCompilerPlugin ...`), error catalog (every enum value in `VerifierFixSuggester`'s classes and every diagnostic key in the annotation processor), code-gen behaviours worth knowing (e.g. `@InArena` deref → `addr_space_cast`, `@Trusted` handling, `@BPFAbstraction` lowering, `.rodata` for `final` globals). One row per user-observable behaviour.

Discovery method: **module-by-module**. Concretely, each audit task uses one
Explore subagent to enumerate symbols by grepping the module for the shape
it cares about (`grep -rn '^public.*@interface' annotations/`, etc.), and a
second sweep across `docs/*.md` for each symbol name to fill the
"Documented in" column. Table rows can be assembled from any convenient
intermediate format the audit subagent produces.

The audit files are checked into `docs/superpowers/audit/`. They are living
documents: Spec 2's per-page tasks tick rows to `OK` as they land content,
and the audit becomes the completion record for Spec 2.

## 5. Includes-based examples pipeline

Every code snippet in the docs that runs — every one, no exceptions — lives
in a real source file that CI already compiles. Docs pull those snippets in
via `pymdownx.snippets`. Two consequences:

- Zero drift. When a snippet's underlying sample stops compiling, the doc
  build shows the old snippet, but CI has already caught the compile break.
- No new module needed for tiny examples. Small snippets that do not warrant
  a full sample class go into a new package:
  `bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/` (which already
  exists — reuse it). Larger examples reuse existing samples.

Mechanics:

1. Add `pymdownx.snippets` to `mkdocs.yml` under `markdown_extensions`, with
   `base_path: ["."]` (repo root only — every include uses a full repo-relative path, so there is no ambiguity between overlapping base paths), `check_paths: true` so missing files fail the build, and `dedent_subsections: true` so extracted regions render cleanly.
2. Convention for marking a region in a `.java` file: pairs of line comments name the region. In Markdown, an include line inside a fenced code block references the file path (relative to the repo root) and the region name after a colon. Both the start/end comment shape and the include shape are documented as reference in the style guide (§3); the spec avoids embedding a rendered example here to sidestep nested-fence quoting.
3. Snippet names are `snake_case`, prefixed with the sample's short name to
   avoid collisions across files. Enforced by review, not by tooling.

4. **Legacy handling.** Existing pages that contain freestanding code blocks
   are not touched in this spec. Spec 2 replaces them one page at a time,
   which is when reader-test gate applies. If a Spec 2 page rewrite finds
   that an existing sample needs a `[start:x]/[end:x]` marker added, the
   sample file is edited in the same task (samples already ship
   `SPDX-License-Identifier` headers, so the comment is idiomatic).

5. **CI gate.** The existing `docs` job in `.github/workflows/ci.yml` runs
   `mkdocs gh-deploy --force` on push to main. `mkdocs build --strict` is
   already effectively enabled via `--force`, but we add an explicit
   `mkdocs build --strict` step before the deploy in the `docs` job, so
   broken snippets or dead links break the build. This is the only workflow
   change in Spec 1.

## 6. Target nav

Applied wholesale in one commit at the end of Spec 1. Existing page files
either stay in place (path unchanged) or move as noted. No file is deleted;
where a page is split, both halves are new files and the original is deleted
in the same commit. **Redirects:** we add an `_redirects`-style shim only
for pages whose URL changes (see §7).

```
Home                                          index.md
Getting Started
  Install & prerequisites                     getting-started/install.md          [new, stub]
  Your first BPF program                      getting-started/hello.md            [new, stub]
  How the plugin works                        getting-started/how-it-works.md     [new, stub]
Guides
  Maps                                        maps.md
  Global variables & types                    global-variables.md
  Shared maps (@SharedFrom)                   shared-maps.md
  BPF arenas (@InArena)                       arenas.md                           [new, stub]
  XDP                                         xdp.md
  TC                                          tc.md
  Tracepoints                                 tracepoints.md
  Kprobes                                     kprobes.md
  Uprobes                                     uprobes.md
  LSM & Cgroup                                lsm.md
  Tail calls                                  tail-calls.md                       [new, stub]
  Timers                                      timers.md                           [new, stub]
  Profiling (CPU / stack)                     profiling.md
sched_ext
  Overview                                    sched-ext/index.md                  [split from sched_ext.md]
  Kernel-side (@BPF Scheduler)                sched-ext/kernel-side.md            [split from sched_ext.md]
  Userspace Scheduler                         sched-ext/userspace.md              [moved from userspace-scheduler.md]
  Callbacks reference                         sched-ext/callbacks.md              [split from sched_ext.md]
  Cookbook (scheduling patterns)              sched-ext/cookbook.md               [moved from scheduler-article.md]
Reference
  Cheat Sheet                                 cheatsheet.md
  Feature matrix                              feature-matrix.md
  Annotations catalog                         reference/annotations.md            [new, stub]
  BPFJ helpers catalog                        reference/bpfj.md                   [moved from helpers.md; renamed]
  Diagnostics                                 diagnostics.md
  Cookbook                                    cookbook.md
Samples
  Index & selection guide                     samples/index.md                    [new, stub]
Architecture (contributor)
  Compiler-plugin overview                    architecture/plugin.md              [new, stub]
  Annotation processor                        architecture/processor.md           [new, stub]
  Error classifier                            architecture/errors.md              [new, stub]
  Contributing                                architecture/contributing.md        [new, stub]
Changelog                                     changelog.md
```

**"Stub" definition.** A stub is a valid Markdown file that:

- has an H1 matching the nav entry,
- contains one `!!! note` admonition: *"This page is a placeholder for content coming in Spec 2. See the [audit table](../superpowers/audit/&lt;file&gt;.md) for the symbols it will cover."*,
- lists (as a plain bullet list) the audit rows targeting this page, so a reader landing on a stub immediately sees the intended scope.

Stubs exist so the new nav is fully wired the moment Spec 1 ships. Spec 2 replaces each stub with real content, one at a time.

### 6.1 Notes on splits

- `sched_ext.md` (703 lines) is carved into `sched-ext/{index,kernel-side,callbacks}.md`. Content is moved verbatim; no sentence is rewritten. The split task begins by proposing the exact H2-to-file carve for review (this cannot be encoded in the spec because the current H2 structure of `sched_ext.md` has not been re-verified against the head of the file at plan time). Section anchors inside the moved content are preserved so external deep-links do not rot.
- `scheduler-article.md` (magazine-style tutorial, currently orphaned from nav) moves to `sched-ext/cookbook.md` unchanged.
- `helpers.md` is renamed to `reference/bpfj.md`. The file content is unchanged in Spec 1; Spec 2 rewrites it into a catalog against the BPFJ audit.
- `userspace-scheduler.md` moves to `sched-ext/userspace.md`. Content unchanged except for one relative link: the original page links to `superpowers/specs/2026-06-29-userspace-scheduler-design.md` (one level up from `docs/`). At the new location, `docs/sched-ext/userspace.md`, the same target is reached via `../superpowers/specs/2026-06-29-userspace-scheduler-design.md` (two levels up). Update that link as part of the move task.

## 7. Redirect / broken-link policy

Anyone who bookmarked `helpers.md` or `userspace-scheduler.md` on the published site will 404 after this spec ships. Two mitigations:

1. **In-repo shim.** For each moved or renamed page, the original path is replaced by a one-line placeholder pointing at the new location. That is, the old file is not deleted — its content becomes a redirect notice:

   ```markdown
   # Moved

   This page moved to [`reference/bpfj.md`](reference/bpfj.md).
   ```

   These placeholder files are listed in `mkdocs.yml`'s `not_in_nav:` so they render at the old URL but do not clutter the sidebar. They exist for exactly one release cycle (0.1.5 → 0.1.6). Their removal is a follow-up chore in the 0.1.6 changelog task and is not in scope for either Spec 1 or Spec 2.

2. **Changelog entry.** The `Releasing 0.1.5` changelog entry (already in `changelog.md`) gets a line noting the doc-nav restructure and pointing at the redirect list.

Sites that link to `#anchor` within a moved page: anchors are preserved because content is moved verbatim; the shim links land on the new page's top; readers scroll. Acceptable trade-off for one release cycle.

## 8. What Spec 2 will do (context only, not scope here)

- Fill every `Missing` row in the six audit tables.
- Rewrite every `Rewrite` and `Partial` row.
- Every new / rewritten page passes the style guide (§3) and the reader-test gate.
- Every runnable code snippet is an `--8<--` include from a real source file.
- The `_.md` audit tables are ticked to `OK` as content lands; the audit is the completion record.

Spec 2 sequences work by audience priority: Getting Started + hero Guides (audience 1) → sched_ext (audience 3) → Reference (audience 2) → Architecture (audience 4). Samples index straddles audiences 1 and 2 and lands mid-sequence.

## 9. Testing

Spec 1 is infrastructure. Test surface:

1. **`mkdocs build --strict` locally on the mac** — passes. Broken links, missing snippets, or invalid frontmatter fail the build.
2. **`mkdocs build --strict` in CI** — same, but on ubuntu-latest via the `docs` job. This is the load-bearing gate.
3. **Manual click-through** of every nav entry post-build to verify: (a) all stubs render, (b) all moved pages resolve, (c) all shims redirect visibly.
4. **Audit sanity check** — for each of the six audit tables, spot-check five rows: run the grep the audit claims and confirm the row's "Documented in" column matches. Catches copy-paste errors.

No new Java code, no new tests in the JUnit sense.

## 10. Deliverables checklist

At the end of Spec 1:

- [ ] `docs/superpowers/style-guide.md` exists and covers all 9 rules with examples.
- [ ] `docs/superpowers/audit/audit-annotations.md` — every annotation from §4.1 has a row.
- [ ] `docs/superpowers/audit/audit-bpfj.md` — every public static in `BPFJ.java` has a row.
- [ ] `docs/superpowers/audit/audit-runtime-api.md` — every symbol from §4.3 has a row.
- [ ] `docs/superpowers/audit/audit-hooks.md` — every hook section from §4.4 has a row.
- [ ] `docs/superpowers/audit/audit-samples.md` — every sample class has a row.
- [ ] `docs/superpowers/audit/audit-plugin.md` — plugin extension points from §4.6 covered.
- [ ] `mkdocs.yml` updated with new nav, snippets extension, `not_in_nav` list, and shim entries.
- [ ] Stubs created for all new pages.
- [ ] Split pages carved out; `sched_ext.md`, `helpers.md`, `userspace-scheduler.md`, `scheduler-article.md` replaced by shim files at their original paths (§7).
- [ ] `pymdownx.snippets` wired; one existing snippet migrated end-to-end as a proof (candidate: the XDP example in `index.md` — the smallest, safest migration).
- [ ] CI `docs` job runs `mkdocs build --strict` before deploy.
- [ ] Local + CI `mkdocs build --strict` both green.

## 11. Out of scope (explicit)

- Rewriting `cookbook.md` (Spec 2).
- Rewriting `diagnostics.md` (Spec 2).
- Adding any new BPF-side or Java-side code beyond snippet markers on existing samples.
- Migrating any snippet other than the one proof-of-life snippet named in §10.
- The archetype (`bpf-archetype/`) — its own README stays authoritative.
- Javadoc rewrites (the audit will flag `TODO:javadoc` rows; fixing them is Spec 2 work).
- Any changes to `README.md`.
