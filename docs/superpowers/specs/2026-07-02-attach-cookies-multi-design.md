# Design: BPF attach cookies + `KPROBE.MULTI` / `UPROBE.MULTI`

Fix the hardcoded `bpf_cookie = 0L` in `BPFProgram.attachUprobe*` /
`attachKProbe*` so users can discriminate between attachments of the
same program, and add first-class `@KProbe.Multi` / `@UProbe.Multi`
annotations that attach one program to N functions in a single
syscall.

Parent roadmap: `docs/superpowers/specs/2026-07-02-roadmap-t0-plus.md`
§4. This spec assumes hello-ebpf's existing single-shot
`BPFProgram.load(cls)` lifecycle (no three-phase open/load split).

## 1. Problem

### 1.1 Cookies

`bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java:711` (and the
corresponding kprobe attach path) hardcodes the attach cookie:

```java
opts.set(JAVA_LONG, 16, 0L);  // bpf_cookie
```

The kernel exposes `bpf_get_attach_cookie(ctx)` from every k/uprobe
program, returning whatever `u64` the userspace attach call supplied.
Hardcoding `0L` kills the intended use cases:

- **Per-attach discrimination.** One BPF program attached to 10
  functions — the program asks the kernel "which of the 10 fired?"
  by reading its cookie. Without cookies, users need 10 separate
  programs.
- **Ordering / prioritisation.** For TCX, cgroup, and struct_ops
  attach types, the cookie can carry a priority tag.
- **Fan-in with metadata.** A generic tracer that fans in from many
  probes, distinguished only by cookie.

Every peer library — aya, cilium-ebpf, libbpf-rs, libbpfgo — exposes
attach cookies as a first-class parameter.

### 1.2 KPROBE.MULTI / UPROBE.MULTI

Kernel 6.6+ ships `BPF_LINK_TYPE_KPROBE_MULTI` and 6.7+ ships
`BPF_LINK_TYPE_UPROBE_MULTI`. A single `bpf_link_create` call attaches
one BPF program to N kernel functions (or N user-space symbols)
selected by a glob pattern or an explicit list. Advantages over N
individual kprobes:

- **~200× lower attach overhead** (measured against libbpf's kprobe
  attach path).
- **Atomic attach.** Either all N points get the probe, or none does.
- **Cookies per attachment point.** The `link_create.kprobe_multi`
  descriptor carries a `cookies[]` array, one per attach point.

Without these, common tracers (attach one program to every kernel
function matching `tcp_*`, or to every symbol matching a wildcard) are
either impossible or require N attach syscalls.

hello-ebpf targets 6.14+ so both kernel features are always available.

## 2. Goals

- `AttachOptions` record with a `cookie` field passed through every
  `BPFProgram.attach*` overload.
- `@KProbe.Multi(pattern = ..., functions = ..., cookies = ...)` and
  `@UProbe.Multi(binary = ..., symbols = ..., cookies = ...)` nested
  annotations that lower to a single `bpf_link_create` call.
- `BPFJ.getAttachCookie(ctx)` builtin lowering to
  `bpf_get_attach_cookie(ctx)`.
- Backward compatibility: existing `@Kprobe`, `@Uprobe`, `@Kretprobe`,
  `@Uretprobe` annotations, and every existing `attachKProbe(...)` /
  `attachUprobe(...)` call site keep compiling and behaving identically.

## 3. Non-goals

- **Cookie update after attach.** Cookies are fixed at
  `bpf_link_create` time; no `updateCookie` API.
- **Cookies for attach types beyond k/uprobe.** TCX, cgroup,
  struct_ops, LSM etc. do accept cookies but their integration is
  separate.
- **Per-instance-in-a-multi-attach cookie mutation.** The `cookies[]`
  array is fixed at attach time.
- **Glob-expanding on the Java side.** For `@KProbe.Multi(pattern =
  "tcp_*")`, the kernel resolves the glob; the plugin does not
  enumerate matching functions.
- **A `@BPFFunction.Multi` mega-annotation.** The multi variants live
  on `@KProbe`/`@UProbe` as nested types, not on `@BPFFunction`.
- **Runtime cookie assignment for pattern-based multi-attach.** The
  user provides either a flat `cookies[]` (attach order) or accepts
  cookie = 0 for all matched functions. There is no per-symbol callback
  hook in v1 (the roadmap noted this would want the three-phase open
  phase; without it, we drop the feature).

## 4. Architecture

Three additions:

**`AttachOptions` record.** A small immutable carrier passed to
`BPFProgram.attach*` overloads.

**Nested `@KProbe.Multi` / `@UProbe.Multi` annotations.** Sit alongside
the existing `@Kprobe` / `@Uprobe` annotations; the annotation
processor discovers them and emits a `kprobe.multi/...` /
`uprobe.multi/...` SEC prefix; the runtime attach path calls
`bpf_link_create` with the multi descriptor.

**`BPFJ.getAttachCookie(ctx)` builtin.** A single-method addition
lowering via the existing `@BuiltinBPFFunction` template mechanism.

The compiler plugin already knows how to route annotations to
sections. All three additions are additive; nothing existing changes
semantics.

## 5. Java API

### 5.1 `AttachOptions`

```java
package me.bechberger.ebpf.bpf.attach;

/** Per-attach options for kprobe/uprobe attachments. */
public record AttachOptions(long cookie) {
    public static final AttachOptions DEFAULT = new AttachOptions(0L);

    public AttachOptions withCookie(long c) { return new AttachOptions(c); }
}
```

### 5.2 New attach overloads on `BPFProgram`

Every existing `attachKProbe(...)` / `attachUprobe(...)` overload gets
a companion that takes `AttachOptions`. The existing signature stays
as sugar over `..., AttachOptions.DEFAULT`.

```java
public abstract class BPFProgram {
    // -- kprobe -----------------------------------------------------
    public BPFLink attachKProbe(ProgramHandle prog, String symbol,
                                boolean retprobe, AttachOptions opts);
    public BPFLink attachKProbe(ProgramHandle prog, String symbol, boolean retprobe) {
        return attachKProbe(prog, symbol, retprobe, AttachOptions.DEFAULT);
    }
    public BPFLink attachKProbe(ProgramHandle prog, String symbol) {
        return attachKProbe(prog, symbol, false);
    }

    // -- uprobe -----------------------------------------------------
    public BPFLink attachUprobe(ProgramHandle prog, boolean retprobe, int pid,
                                String binaryPath, String funcName,
                                AttachOptions opts);
    public BPFLink attachUprobe(ProgramHandle prog, boolean retprobe, int pid,
                                String binaryPath, String funcName) {
        return attachUprobe(prog, retprobe, pid, binaryPath, funcName,
                            AttachOptions.DEFAULT);
    }
    // ... plus the offset-based overloads with the same pattern.

    // -- multi ------------------------------------------------------
    /** Attach one program to N kprobes atomically. See @KProbe.Multi. */
    public BPFLink attachKProbeMulti(ProgramHandle prog, KProbeMultiSpec spec);

    /** Attach one program to N uprobes atomically. See @UProbe.Multi. */
    public BPFLink attachUProbeMulti(ProgramHandle prog, UProbeMultiSpec spec);
}
```

### 5.3 Multi-attach specs

```java
package me.bechberger.ebpf.bpf.attach;

/** Spec for a single kprobe-multi attach. Either pattern XOR functions is set. */
public record KProbeMultiSpec(
        @Nullable String pattern,          // glob, e.g. "tcp_v4_*"
        String[] functions,                // fixed list; used when pattern == null
        long[] cookies,                    // parallel to functions; empty ⇒ all zero
        boolean retprobe
) {
    /** Attach at every kernel function matching the given glob. All cookies default to 0. */
    public static KProbeMultiSpec pattern(String pattern) {
        return new KProbeMultiSpec(pattern, new String[0], new long[0], false);
    }

    /** Attach at each named function, with per-attachment cookies. */
    public static KProbeMultiSpec functions(String[] functions, long[] cookies) {
        // ... validate cookies.length == functions.length
    }
}

public record UProbeMultiSpec(
        String binaryPath,
        @Nullable String pattern,          // symbol glob within the binary
        String[] symbols,                  // or explicit symbol list
        long[] offsets,                    // or explicit offset list (parallel to symbols if both)
        long[] cookies,
        int pid,                           // -1 for all processes
        boolean retprobe
) { /* similar builder pattern */ }
```

### 5.4 `@KProbe.Multi` / `@UProbe.Multi` annotations

```java
package me.bechberger.ebpf.annotations.bpf;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Kprobe {
    String value();

    /** Nested variant: attach to N functions in one syscall.
     *  Use exactly one of pattern or functions.
     *
     *  If cookies is empty, all attachments get cookie = 0. Otherwise
     *  cookies.length must equal functions.length. */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Documented
    @interface Multi {
        /** Kernel-function glob, e.g. "tcp_v4_*". Mutually exclusive with functions. */
        String pattern() default "";

        /** Explicit function list. Mutually exclusive with pattern. */
        String[] functions() default {};

        /** Cookies parallel to functions[]. Empty ⇒ all zero.
         *  Not applicable to pattern-based multi (all cookies are 0). */
        long[] cookies() default {};

        /** True for kretprobe.multi. */
        boolean retprobe() default false;
    }
}
```

`@Uprobe.Multi` mirrors this shape with `binary`, `symbols`, `offsets`,
`pid`.

### 5.5 `BPFJ.getAttachCookie`

New `@BuiltinBPFFunction` in `BPFJ.java`:

```java
/** Return the cookie associated with the current attachment.
 *  For k/uprobes: whatever was passed in AttachOptions.cookie().
 *  For pattern-based multi-attach: 0.
 *  For explicit multi-attach: the corresponding element of cookies[]. */
@BuiltinBPFFunction("bpf_get_attach_cookie($arg1)")
@NotUsableInJava
public static long getAttachCookie(Object ctx) {
    throw new MethodIsBPFRelatedFunction();
}
```

## 6. Usage examples

### 6.1 Simple cookie via `AttachOptions`

```java
@Kprobe("tcp_v4_rcv")
int onRcv(Ptr<PtDefinitions.pt_regs> ctx) {
    long which = BPFJ.getAttachCookie(ctx);  // whatever we passed at attach time
    // ...
    return 0;
}

// In main():
try (MyTracer prog = BPFProgram.load(MyTracer.class)) {
    prog.attachKProbe(prog.getProgramByName("onRcv"), "tcp_v4_rcv",
                      false, new AttachOptions(42L));
    // ...
}
```

### 6.2 Explicit multi-attach with per-symbol cookies

```java
@Kprobe.Multi(functions = { "tcp_v4_rcv", "tcp_v6_rcv" },
              cookies   = { 4L, 6L })
int onAnyTcpRcv(Ptr<PtDefinitions.pt_regs> ctx) {
    long ipVersion = BPFJ.getAttachCookie(ctx);   // 4 or 6
    if (ipVersion == 4) { /* ... */ } else { /* ... */ }
    return 0;
}
```

Auto-attach fires from `prog.autoAttachPrograms()` — the plugin
generates the attach code from the annotation.

### 6.3 Pattern-based multi-attach

```java
@Kprobe.Multi(pattern = "tcp_v4_*")
int onAnyTcpV4(Ptr<PtDefinitions.pt_regs> ctx) {
    // cookie is always 0 for pattern-based multi
    // ...
    return 0;
}
```

### 6.4 Uprobe multi-attach

```java
@Uprobe.Multi(binary  = "/usr/lib/x86_64-linux-gnu/libjvm.so",
              symbols = { "SafepointSynchronize::begin",
                          "SafepointSynchronize::end" },
              cookies = { 1L, 2L })
int onSafepoint(Ptr<PtDefinitions.pt_regs> ctx) {
    long which = BPFJ.getAttachCookie(ctx);   // 1 or 2
    return 0;
}
```

### 6.5 Manual multi-attach without annotations

```java
try (MyProfiler prog = BPFProgram.load(MyProfiler.class)) {
    var spec = KProbeMultiSpec.functions(
            new String[] { "sys_read", "sys_write" },
            new long[]   { 1L, 2L });
    prog.attachKProbeMulti(prog.getProgramByName("onIo"), spec);
    // ...
}
```

## 7. Implementation

### 7.1 Cookie plumbing (small fix)

In `BPFProgram.attachUprobe(...)` at line 711:

```java
opts.set(JAVA_LONG, 16, opts_attach.cookie());  // was 0L
```

The kprobe attach path (around `attachKProbe` at ~line 606) needs the
same treatment — `bpf_program__attach_kprobe_opts` takes a
`bpf_kprobe_opts` with a `bpf_cookie` field. Wrap the varargs form
today by allocating the opts struct in-line.

### 7.2 Multi-attach FFI

Two new libbpf entry points to wrap:

- `bpf_program__attach_kprobe_multi_opts(prog, pattern_or_null,
   bpf_kprobe_multi_opts *opts)` — where `opts` is:
  ```c
  struct bpf_kprobe_multi_opts {
      size_t sz;
      const char **syms;      // or NULL to use addrs
      const unsigned long *addrs;
      const __u64 *cookies;
      size_t cnt;
      bool retprobe;
      bool session;
      bool unique_match;
  };
  ```
- `bpf_program__attach_uprobe_multi(prog, pid, path, func_pattern,
   opts)` — similar shape with `syms`/`offsets`/`ref_ctr_offsets`/
   `cookies`.

Both live in libbpf 1.3+. hello-ebpf already depends on 1.4+.

Wrap each via `HandlerWithErrno<MemorySegment>` following the pattern
of `BPF_PROGRAM__ATTACH_UPROBE_OPTS` at
`BPFProgram.java:681`. Layout for `bpf_kprobe_multi_opts` is:

```
offset 0:  size_t sz
offset 8:  const char **syms
offset 16: const unsigned long *addrs
offset 24: const __u64 *cookies
offset 32: size_t cnt
offset 40: bool retprobe (padded to 8)
offset 48: bool session (padded to 8)
offset 56: bool unique_match (padded to 8)
                                                = 64 bytes total
```

Verify offsets against libbpf's `libbpf.h` at build time (the plugin
already vendors kernel headers; a small compile-check confirms).

### 7.3 Annotation processor changes

`TypeProcessor.java` currently discovers `@Kprobe` / `@Uprobe`. Two new
paths:

- On `@Kprobe.Multi` / `@Uprobe.Multi`, generate a `@BPFFunction` with
  `section = "kprobe.multi/<something>"` (the SEC string doesn't matter
  for multi; libbpf routes by section prefix). Store the annotation
  values (pattern / functions / cookies / retprobe) in the generated
  `BPFImpl` as a static field.
- Generate an `autoAttach()` hook that calls
  `attachKProbeMulti(prog, spec)` with the stored spec.

Existing `@BPFFunction` machinery handles the C emission (kprobe-multi
uses the same C context as kprobe: `struct pt_regs *ctx`).

### 7.4 `BPFJ.getAttachCookie` template

Add to `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFJ.java`:

```java
@BuiltinBPFFunction("bpf_get_attach_cookie($arg1)")
@NotUsableInJava
public static long getAttachCookie(Object ctx) {
    throw new MethodIsBPFRelatedFunction();
}
```

The `$arg1` placeholder is already supported by the existing template
language (`reference_method_template_language.md` in the memory notes).

### 7.5 Validation

At annotation-processor time:

- `@KProbe.Multi(pattern = ..., functions = ...)` with both set: compile
  error.
- `@KProbe.Multi()` with neither: compile error.
- `cookies.length != functions.length` when both are set: compile error.
- `pattern != ""` and `cookies.length > 0`: compile error.

At attach time:

- `KProbeMultiSpec.functions.length == 0` when `pattern == null`:
  `IllegalArgumentException`.
- Any element of `cookies` outside signed-long range: N/A (it's a
  `long`).

## 8. Compatibility

**Existing samples.** `@Kprobe`, `@Uprobe`, `@Kretprobe`, `@Uretprobe`
still work. `attachKProbe(prog, symbol)` still works. Cookie is 0
unless explicitly set — matching today's behaviour.

**Kernel floor.** 6.14+ unchanged. Kprobe-multi requires 6.6+, uprobe-
multi requires 6.7+; both are ≤ 6.14.

**libbpf floor.** 1.3+ for multi attach; 1.4+ is already the project
floor.

## 9. Testing

### 9.1 Unit tests (mac — annotation processor)

`bpf-compiler-plugin-test/src/test/java/.../KProbeMultiAnnotationTest.java`:

- `patternXorFunctionsRequired` — both set → compile error.
- `neitherSetRejected` — neither set → compile error.
- `cookieCountMismatchRejected` — `cookies.length != functions.length`
  → compile error.
- `generatedSpecCarriesValues` — for a valid annotation, the generated
  `BPFImpl` static field contains the expected `KProbeMultiSpec`.

### 9.2 Real-kernel smoke tests (thinkstation vng)

`bpf-samples/src/test/java/.../AttachCookiesSmokeTest.java`:

- **Cookie discrimination.** Attach the same program twice via
  `attachKProbe` with cookies 1 and 2, at two different symbols.
  Fire both, read a `BPF_MAP_TYPE_HASH<u64, u64>` that counts by
  cookie. Assert both counters are non-zero.
- **Kprobe multi with explicit functions.** `@Kprobe.Multi(functions
  = { "tcp_v4_rcv", "tcp_v6_rcv" }, cookies = { 4L, 6L })`. Load; ping
  localhost over both IPv4 and IPv6; assert per-cookie counters both
  non-zero.
- **Kprobe multi with pattern.** `@Kprobe.Multi(pattern = "tcp_v4_*")`.
  Load; expect attach to succeed against >5 functions (check via
  `bpf_link` fd introspection or count of trace events fired).
- **Uprobe multi.** `@Uprobe.Multi(binary = "libc.so.6",
  symbols = { "malloc", "free" }, cookies = { 1L, 2L })`. Load;
  trigger a tiny helper binary; assert cookie 1 and cookie 2 both
  observed.
- **Regression.** All existing samples still pass — they never
  request a cookie, so behaviour matches today.

### 9.3 Test scaffolding

Reuse the `SchedulerExtension` / vng pattern from
`RustlandFifoSampleSmokeTest.java`. Cookie observation is via a
per-cookie HASH map read from userspace after triggering.

## 10. Sample

`bpf-samples/src/main/java/me/bechberger/ebpf/samples/BpfCookieSample.java`:

- Loads a program that traces `tcp_v4_rcv` and `tcp_v6_rcv` via a
  `@Kprobe.Multi` with cookies `4L` and `6L`.
- Prints per-IP-version RX counts once a second for 5 seconds.
- Doubles as the smoke test's target.

## 11. Interactions with other roadmap features

- **§8 `Features.hasX(...)`.** `Features.hasAttachType(
  TRACE_KPROBE_MULTI)` and `hasAttachType(TRACE_UPROBE_MULTI)` gate
  the multi paths; if the probe fails, the annotation processor
  can still generate the code but the runtime attach will throw. On
  6.14+, both always return true; this is a defensive check.
- **§3 `@StructOps`.** No interaction. Struct_ops attach doesn't use
  the `attach_cookie` FFI path.
- **§6 `@BPFTailCallTable`.** No interaction. Tail-call programs are
  never directly attached.

## 12. Risks

- **`bpf_kprobe_multi_opts` layout drift.** libbpf occasionally adds
  fields at the end; the `sz` prefix protects against silent
  incompatibility. Compile-check via `#ifdef LIBBPF_VERSION_MINOR` in
  the FFI wrapper.
- **Pattern attach at large scope.** `@Kprobe.Multi(pattern = "*")`
  would attach to every kernel function — hundreds of thousands of
  probes. The kernel accepts it; users pay the resulting overhead.
  Documented, not enforced.
- **Cookie collisions when using pattern-based multi.** Pattern
  attach cannot give per-symbol cookies, so a user who wants
  discrimination must switch to explicit functions. Documented in
  the annotation Javadoc.
- **Two attach paths for the "same" annotation.** `@Kprobe` and
  `@Kprobe.Multi` are related but distinct; users need to pick. The
  nested-annotation naming (`@Kprobe.Multi`) makes the relationship
  visible in the source.

## 13. Success criteria

- The one-line fix at `BPFProgram.java:711` (and the equivalent kprobe
  path) is in place; a cookie set via `AttachOptions` is observable
  from `BPFJ.getAttachCookie(ctx)` in a real-kernel test.
- `BpfCookieSample` loads and prints per-cookie counts.
- Multi-attach smoke tests pass on thinkstation.
- Every existing sample using `@Kprobe`, `@Uprobe`, `@Kretprobe`,
  `@Uretprobe` continues to load and behave identically.
- Annotation-processor error messages are cited verbatim in the tests.

## 14. Handoff

Plan writer: implementation plan at
`docs/superpowers/plans/2026-07-02-attach-cookies-multi.md`. Task
sequencing:

1. Wrap `bpf_kprobe_multi_opts` / `bpf_uprobe_multi_opts` layouts and
   add `HandlerWithErrno` entries.
2. Add `AttachOptions` record + `getAttachCookie` builtin.
3. Fix the hardcoded `0L` — write the "cookie survives attach"
   smoke test first, then the fix, then watch the test pass.
4. Add `@KProbe.Multi` / `@UProbe.Multi` annotations + processor
   wiring + auto-attach codegen.
5. Write the sample + smoke tests.

Each task ends with a green build gate. Plan reads the actual
`BPFProgram.attachKProbe(...)` and `attachUprobe(...)` code before
committing to the exact ordering — the current understanding is from
grep, not a full read.
