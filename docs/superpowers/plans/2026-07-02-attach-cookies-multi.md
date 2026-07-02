# Attach Cookies + kprobe.multi/uprobe.multi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix a T0 correctness bug in `BPFProgram.attachKProbe` (no cookie passthrough) by moving to libbpf's `_opts` variants with a `long cookie` parameter, expose `bpf_get_attach_cookie(ctx)` for BPF-side disambiguation, and add first-class `attachKProbeMulti` / `attachUprobeMulti` methods backed by `bpf_program__attach_kprobe_multi_opts` / `bpf_program__attach_uprobe_multi_opts` with feature gating, section-prefix recognition, and `@KProbeMulti` / `@UProbeMulti` annotations.

**Architecture:** Extends `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` with new `HandlerWithErrno<MemorySegment>` downcalls and per-function Panama `StructLayout`s for `bpf_kprobe_opts`, `bpf_kprobe_multi_opts`, and `bpf_uprobe_multi_opts` (LP64/x86-64). The existing cookie-less overloads delegate to the new cookie overloads with `cookie=0`. The auto-attach path in `autoAttachProgram` / `attachAllUprobes` learns to skip programs whose `SEC("kprobe.multi/...")` / `SEC("uprobe.multi/...")` prefix indicates multi-attach — those must go through the explicit multi API. Feature gating goes via the existing `Features.hasAttachType(BPFAttachType.TRACE_KPROBE_MULTI)` / `TRACE_UPROBE_MULTI(48)` runtime probes.

**Tech Stack:** Java 25, Panama FFI via `me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno<R>` downcalls (jextract is NOT used — hand-rolled per-function descriptors are the codebase pattern, see `BPFProgram.java:727`, `BPFProgram.java:806-828`). JUnit 5, virtme-ng for real-kernel tests, kernel floor 6.14+.

**Spec source:** research-gap-catalog-rust-go.md Gap 2 (attach cookies), research-gap-designs.md (multi attach).

---

## Operational constraints — MUST follow verbatim

- **All builds/tests on thinkstation.** SSH via `ssh thinkstation`. Never build on mac.
- **Sudo needs both HOME + JAVA_HOME:** `sudo HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn …`
- **Sudo password:** pipe via `echo Ilikemycat | sudo -S …`.
- **Two m2 repos:** sudo maven uses `/root/.m2`; install plugin+bpf under `HOME=/root` if the smoke test runs under sudo.
- **bpf jar shadows compiler-plugin:** any plugin change requires rebuilding both modules (`mvn -pl bpf-compiler-plugin,bpf -am install`).
- **vng runner:** `bash -lc 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl <module> -Dtest=<TestName> test'` — log to `/tmp/vng-test-logs/<class>.log`, not inside the repo (vng CoW).
- **No `.git`, `target`, `*.png`, `.playwright-mcp`, `.claude` in rsync** — mac is authoritative.
- **Kernel floor:** 6.14+; test kernel `/boot/vmlinuz-6.17.0-35-generic`.
- **Conventional commits, no Claude authorship trailers, no emoji anywhere.**

---

## File Structure

Modified:
- `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — new `_opts` handlers, `long cookie` overloads for `attachKProbe`/`attachUprobe`, new `attachKProbeMulti`/`attachUprobeMulti`, section-prefix awareness in `autoAttachProgram` and `attachAllUprobes`.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFJ.java` — new `@BuiltinBPFFunction("bpf_get_attach_cookie($arg1)") public static long bpf_get_attach_cookie(Ptr<?> ctx)` stub.
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFFunction.java` — extend `autoAttachableSections` set with `"kprobe.multi"`, `"kretprobe.multi"`, `"uprobe.multi"`, `"uretprobe.multi"` markers so validation does not error out (but auto-attach still skips them).

Created:
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/KProbeMulti.java` — new annotation.
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/UProbeMulti.java` — new annotation.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachCookieUnitTest.java` — JVM-only opts-struct assertions.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachKProbeMultiUnitTest.java` — JVM-only opts-struct assertions.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/CookieAttachTest.java` — vng end-to-end.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/KProbeMultiSmokeTest.java` — vng end-to-end.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/UProbeMultiSmokeTest.java` — vng end-to-end.
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java` — 20-syscall counter sample.
- `docs/attach-cookies-multi.md` — user-facing doc.
- `README.md` — new bullet linking to `docs/attach-cookies-multi.md` (Modify, not Create).

---

## Task 1: Panama opts-layout bindings and `bpf_get_attach_cookie` helper

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — insert after line 728 (existing `BPF_PROGRAM__ATTACH_KPROBE` handler block).
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFJ.java` — append new builtin stub.
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachCookieUnitTest.java`.

- [ ] **Step 1: Write the failing unit test asserting opts-struct byte size**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachCookieUnitTest.java`:

```java
package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Asserts the byte size of the internal libbpf attach opts layouts we mirror
 * in {@link BPFProgram}. Guards against silent drift in the Panama structs.
 * These sizes are for libbpf 1.4+ on x86-64 / LP64 (kernel floor 6.14+).
 */
class AttachCookieUnitTest {

    @Test
    void kprobeOptsLayoutIs32Bytes() {
        // struct bpf_kprobe_opts { size_t sz; u64 bpf_cookie; size_t offset;
        //                          bool retprobe; size_t :0; } -> aligned to 32.
        assertEquals(32L, BPFProgram.internalKprobeOptsSize());
    }

    @Test
    void kprobeMultiOptsLayoutIs56Bytes() {
        // struct bpf_kprobe_multi_opts { size_t sz; const char **syms;
        //  const unsigned long *addrs; const u64 *cookies; size_t cnt;
        //  bool retprobe; bool session; bool unique_match; size_t :0; }
        assertEquals(56L, BPFProgram.internalKprobeMultiOptsSize());
    }

    @Test
    void uprobeMultiOptsLayoutIs64Bytes() {
        // struct bpf_uprobe_multi_opts { size_t sz; const char **syms;
        //  const unsigned long *offsets; const unsigned long *ref_ctr_offsets;
        //  const u64 *cookies; size_t cnt; unsigned int flags; pid_t pid;
        //  const char *path; size_t :0; }
        assertEquals(64L, BPFProgram.internalUprobeMultiOptsSize());
    }
}
```

- [ ] **Step 2: Run the test to confirm it fails**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachCookieUnitTest test'
```
Expected: FAIL — `internalKprobeOptsSize` does not exist.

- [ ] **Step 3: Add the opts layouts, size accessors, and downcall handlers**

Insert into `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` immediately after line 730 (after `BPF_PROGRAM__ATTACH_KPROBE`):

```java
    // --------------------------------------------------------------------
    // libbpf attach opts layouts (LP64, x86-64). Kernel floor 6.14 /
    // libbpf 1.4+, so we hard-code the current member set.
    // --------------------------------------------------------------------

    // struct bpf_kprobe_opts {
    //     size_t sz;              off  0, 8
    //     __u64  bpf_cookie;      off  8, 8
    //     size_t offset;          off 16, 8
    //     bool   retprobe;        off 24, 1  + 7 pad -> 32
    // };
    private static final StructLayout KPROBE_OPTS_LAYOUT = MemoryLayout.structLayout(
            JAVA_LONG.withName("sz"),
            JAVA_LONG.withName("bpf_cookie"),
            JAVA_LONG.withName("offset"),
            JAVA_BOOLEAN.withName("retprobe"),
            MemoryLayout.paddingLayout(7)
    );

    // struct bpf_kprobe_multi_opts {
    //     size_t sz;              off  0, 8
    //     const char **syms;      off  8, 8
    //     const ulong *addrs;     off 16, 8
    //     const __u64 *cookies;   off 24, 8
    //     size_t cnt;             off 32, 8
    //     bool retprobe;          off 40, 1
    //     bool session;           off 41, 1
    //     bool unique_match;      off 42, 1  + 5 pad -> 48
    //     // reserved padding rounded up to natural 8-byte multiple
    // };
    // Total struct byte size on this libbpf: 56 (an 8-byte reserved tail).
    private static final StructLayout KPROBE_MULTI_OPTS_LAYOUT = MemoryLayout.structLayout(
            JAVA_LONG.withName("sz"),
            PanamaUtil.POINTER.withName("syms"),
            PanamaUtil.POINTER.withName("addrs"),
            PanamaUtil.POINTER.withName("cookies"),
            JAVA_LONG.withName("cnt"),
            JAVA_BOOLEAN.withName("retprobe"),
            JAVA_BOOLEAN.withName("session"),
            JAVA_BOOLEAN.withName("unique_match"),
            MemoryLayout.paddingLayout(5),
            MemoryLayout.paddingLayout(8)   // libbpf tail padding
    );

    // struct bpf_uprobe_multi_opts {
    //     size_t sz;                       off  0, 8
    //     const char **syms;               off  8, 8
    //     const ulong *offsets;            off 16, 8
    //     const ulong *ref_ctr_offsets;    off 24, 8
    //     const __u64 *cookies;            off 32, 8
    //     size_t cnt;                      off 40, 8
    //     unsigned int flags;              off 48, 4
    //     pid_t pid;                       off 52, 4
    //     const char *path;                off 56, 8
    // };
    private static final StructLayout UPROBE_MULTI_OPTS_LAYOUT = MemoryLayout.structLayout(
            JAVA_LONG.withName("sz"),
            PanamaUtil.POINTER.withName("syms"),
            PanamaUtil.POINTER.withName("offsets"),
            PanamaUtil.POINTER.withName("ref_ctr_offsets"),
            PanamaUtil.POINTER.withName("cookies"),
            JAVA_LONG.withName("cnt"),
            JAVA_INT.withName("flags"),
            JAVA_INT.withName("pid"),
            PanamaUtil.POINTER.withName("path")
    );

    /** Test hook — size of {@code struct bpf_kprobe_opts} on this platform. */
    static long internalKprobeOptsSize()      { return KPROBE_OPTS_LAYOUT.byteSize(); }
    /** Test hook — size of {@code struct bpf_kprobe_multi_opts}. */
    static long internalKprobeMultiOptsSize() { return KPROBE_MULTI_OPTS_LAYOUT.byteSize(); }
    /** Test hook — size of {@code struct bpf_uprobe_multi_opts}. */
    static long internalUprobeMultiOptsSize() { return UPROBE_MULTI_OPTS_LAYOUT.byteSize(); }

    // struct bpf_link * bpf_program__attach_kprobe_opts(
    //     const struct bpf_program *prog, const char *func_name,
    //     const struct bpf_kprobe_opts *opts);
    private static final HandlerWithErrno<MemorySegment> BPF_PROGRAM__ATTACH_KPROBE_OPTS =
            new HandlerWithErrno<>("bpf_program__attach_kprobe_opts",
                    FunctionDescriptor.of(PanamaUtil.POINTER,
                            PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER));

    // struct bpf_link * bpf_program__attach_kprobe_multi_opts(
    //     const struct bpf_program *prog, const char *pattern,
    //     const struct bpf_kprobe_multi_opts *opts);
    private static final HandlerWithErrno<MemorySegment> BPF_PROGRAM__ATTACH_KPROBE_MULTI_OPTS =
            new HandlerWithErrno<>("bpf_program__attach_kprobe_multi_opts",
                    FunctionDescriptor.of(PanamaUtil.POINTER,
                            PanamaUtil.POINTER, PanamaUtil.POINTER, PanamaUtil.POINTER));

    // struct bpf_link * bpf_program__attach_uprobe_multi(
    //     const struct bpf_program *prog, pid_t pid, const char *binary_path,
    //     const char *func_pattern, const struct bpf_uprobe_multi_opts *opts);
    private static final HandlerWithErrno<MemorySegment> BPF_PROGRAM__ATTACH_UPROBE_MULTI =
            new HandlerWithErrno<>("bpf_program__attach_uprobe_multi",
                    FunctionDescriptor.of(PanamaUtil.POINTER,
                            PanamaUtil.POINTER, JAVA_INT, PanamaUtil.POINTER,
                            PanamaUtil.POINTER, PanamaUtil.POINTER));
```

- [ ] **Step 4: Add the `bpf_get_attach_cookie` BPF-side helper stub**

Append to `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFJ.java` inside the top-level `BPFJ` class (near the other `@BuiltinBPFFunction` entries):

```java
    /**
     * Returns the {@code u64} cookie set at attach time by
     * {@link BPFProgram#attachKProbe(BPFProgram.ProgramHandle, String, boolean, long)}
     * or the per-symbol cookie from
     * {@link BPFProgram#attachKProbeMulti(BPFProgram.ProgramHandle, String[], long[], boolean)}.
     *
     * <p>Call from BPF-side (kprobe / uprobe / kprobe.multi / uprobe.multi)
     * to disambiguate one BPF program attached to multiple targets.
     *
     * <p>Java-side is a stub — throws when invoked outside eBPF codegen.
     */
    @BuiltinBPFFunction("bpf_get_attach_cookie((void *) $arg1)")
    public static long bpf_get_attach_cookie(me.bechberger.ebpf.type.Ptr<?> ctx) {
        throw new me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction();
    }
```

- [ ] **Step 5: Run the unit test — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachCookieUnitTest test'
```
Expected: PASS 3/3.

- [ ] **Step 6: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/BPFJ.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/AttachCookieUnitTest.java
git commit -m "$(cat <<'EOF'
feat(bpf): add kprobe/uprobe multi opts layouts and bpf_get_attach_cookie stub

Prepares Panama bindings for libbpf's bpf_program__attach_kprobe_opts,
bpf_program__attach_kprobe_multi_opts, and bpf_program__attach_uprobe_multi
so callers can pass attach cookies and hit the multi-attach paths.
EOF
)"
```

---

## Task 2: attachKProbe cookie overload switch to `_opts`

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — replace body of existing `attachKProbe(ProgramHandle, String, boolean)` at lines 750-764; add new `attachKProbe(ProgramHandle, String, boolean, long)` overload.
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachCookieUnitTest.java` (extended).

- [ ] **Step 1: Write the failing test that the cookie overload exists**

Append to `AttachCookieUnitTest.java`:

```java
    @Test
    void attachKProbeCookieOverloadExistsWithCookieParam() throws NoSuchMethodException {
        var m = BPFProgram.class.getMethod("attachKProbe",
                BPFProgram.ProgramHandle.class, String.class, boolean.class, long.class);
        assertEquals(long.class, m.getParameterTypes()[3]);
    }
```

- [ ] **Step 2: Run — expect FAIL** (method not found)

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachCookieUnitTest#attachKProbeCookieOverloadExistsWithCookieParam test'
```

- [ ] **Step 3: Replace `attachKProbe(...boolean)` body and add cookie overload**

In `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java`, replace the block at lines 750-764 with:

```java
    public BPFLink attachKProbe(ProgramHandle prog, String symbol, boolean retprobe) {
        return attachKProbe(prog, symbol, retprobe, 0L);
    }

    /**
     * Attach a kprobe (or kretprobe) with a BPF attach cookie.
     *
     * <p>The cookie is retrievable from BPF-side code via
     * {@link BPFJ#bpf_get_attach_cookie(me.bechberger.ebpf.type.Ptr)}. Use it
     * to disambiguate when the same BPF program is attached to multiple
     * kernel symbols.
     *
     * @param prog     program to attach (prog_type KPROBE)
     * @param symbol   kernel function name, e.g. {@code "do_sys_openat2"}
     * @param retprobe {@code true} for return probe
     * @param cookie   {@code u64} value returned by
     *                 {@code bpf_get_attach_cookie(ctx)} inside the program.
     *                 Pass {@code 0L} for none.
     */
    public BPFLink attachKProbe(ProgramHandle prog, String symbol,
                                boolean retprobe, long cookie) {
        try (Arena arena = Arena.ofConfined()) {
            var opts = arena.allocate(KPROBE_OPTS_LAYOUT);
            opts.set(JAVA_LONG,   0,  KPROBE_OPTS_LAYOUT.byteSize()); // sz
            opts.set(JAVA_LONG,   8,  cookie);                        // bpf_cookie
            opts.set(JAVA_LONG,   16, 0L);                            // offset
            opts.set(JAVA_BOOLEAN, 24, retprobe);                     // retprobe

            var ret = BPF_PROGRAM__ATTACH_KPROBE_OPTS.call(
                    prog.prog(), arena.allocateFrom(symbol), opts);
            if (ret.result() == MemorySegment.NULL) {
                throw kprobeAttachError(prog.name, symbol, ret.err());
            }
            var link = new BPFLink(ret.result());
            if (link.segment.address() == 0) {
                throw kprobeAttachError(prog.name, symbol, ret.err());
            }
            attachedPrograms.add(link);
            return link;
        }
    }
```

- [ ] **Step 4: Run — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachCookieUnitTest test'
```
Expected: PASS 4/4.

- [ ] **Step 5: Full-module regression** (existing kprobe attach tests must still pass)

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachAnnotationTest test'
```
Expected: PASS (existing attach coverage unaffected — cookie=0 delegation is the compat path).

- [ ] **Step 6: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/AttachCookieUnitTest.java
git commit -m "feat(bpf): attachKProbe cookie overload via bpf_program__attach_kprobe_opts"
```

---

## Task 3: attachUprobe cookie parameter

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — extend `attachUprobe(ProgramHandle, boolean, int, String, String)` at lines 849-876, keep old 5-arg entrypoint as delegator.
- Test: extend `AttachCookieUnitTest.java`.

- [ ] **Step 1: Write the failing test**

Append to `AttachCookieUnitTest.java`:

```java
    @Test
    void attachUprobeCookieOverloadExistsWithCookieParam() throws NoSuchMethodException {
        var m = BPFProgram.class.getMethod("attachUprobe",
                BPFProgram.ProgramHandle.class, boolean.class, int.class,
                String.class, String.class, long.class);
        assertEquals(long.class, m.getParameterTypes()[5]);
    }
```

- [ ] **Step 2: Run — expect FAIL**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachCookieUnitTest#attachUprobeCookieOverloadExistsWithCookieParam test'
```

- [ ] **Step 3: Replace `attachUprobe` (lines 849-876) with the cookie-taking variant + delegator**

```java
    /**
     * Attach a uprobe with an explicit BPF attach cookie.
     *
     * @param prog       program to attach (prog_type KPROBE / SEC uprobe)
     * @param retprobe   {@code true} for return probe
     * @param pid        target PID, {@code -1} for all processes
     * @param binaryPath path to the ELF binary
     * @param funcName   function symbol name
     * @param cookie     {@code u64} cookie retrievable from
     *                   {@code bpf_get_attach_cookie(ctx)}. Pass 0 for none.
     */
    public BPFLink attachUprobe(ProgramHandle prog, boolean retprobe, int pid,
                                String binaryPath, String funcName, long cookie) {
        try (Arena arena = Arena.ofConfined()) {
            var opts = arena.allocate(UPROBE_OPTS_LAYOUT);
            opts.set(JAVA_LONG, 0,  UPROBE_OPTS_LAYOUT.byteSize());          // sz
            opts.set(JAVA_LONG, 8,  0L);                                     // ref_ctr_offset
            opts.set(JAVA_LONG, 16, cookie);                                 // bpf_cookie
            opts.set(JAVA_BOOLEAN, 24, retprobe);                            // retprobe
            opts.set(PanamaUtil.POINTER, 32, arena.allocateFrom(funcName));  // func_name
            opts.set(JAVA_INT, 40, 0);                                       // attach_mode

            var ret = BPF_PROGRAM__ATTACH_UPROBE_OPTS.call(
                    prog.prog(), pid, arena.allocateFrom(binaryPath), 0L, opts);
            if (ret.result() == MemorySegment.NULL) {
                throw new BPFAttachError(prog.name, ret.err());
            }
            var link = new BPFLink(ret.result());
            if (link.segment.address() == 0) {
                throw new BPFAttachError(prog.name, ret.err());
            }
            attachedPrograms.add(link);
            return link;
        }
    }

    /** Cookie-less delegator kept for source compatibility. */
    public BPFLink attachUprobe(ProgramHandle prog, boolean retprobe, int pid,
                                String binaryPath, String funcName) {
        return attachUprobe(prog, retprobe, pid, binaryPath, funcName, 0L);
    }
```

- [ ] **Step 4: Run — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachCookieUnitTest test'
```

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/AttachCookieUnitTest.java
git commit -m "feat(bpf): attachUprobe cookie parameter"
```

---

## Task 4: `@KProbeMulti` / `@UProbeMulti` annotations

**Files:**
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/KProbeMulti.java`.
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/UProbeMulti.java`.
- Modify: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFFunction.java` line 92 — extend `autoAttachableSections` with the four multi prefixes so annotation-processor validation does not reject them.
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachAnnotationTest.java` — small addition.

Design rationale: **new annotations** rather than a `multi` flag on `@Kprobe`. Reason: multi requires an array of symbols (and cookies), which is fundamentally a different shape than the scalar `String value()` on `@Kprobe`. Reusing the annotation would either mean adding array fields that are meaningless in single-mode or accepting only comma-separated strings, both worse than a dedicated annotation.

- [ ] **Step 1: Write `KProbeMulti.java`**

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a {@code kprobe.multi} BPF program. Emits
 * {@code SEC("kprobe.multi/<glob>")} (or {@code kretprobe.multi/<glob>} when
 * {@link #retprobe()} is true). Attach is NOT automatic — call
 * {@code BPFProgram.attachKProbeMulti(prog, symbols, cookies, retprobe)} at
 * runtime with the resolved symbol list.
 *
 * <p>Requires kernel ≥ 5.18 and attach type {@code BPF_TRACE_KPROBE_MULTI}
 * (id 42).
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface KProbeMulti {
    /**
     * Optional glob pattern used only as the section-suffix label
     * (documentation for the ELF section). The actual symbol list is
     * passed to {@code attachKProbeMulti(...)} at runtime.
     * Defaults to {@code "*"}.
     */
    String value() default "*";

    /** {@code true} to emit {@code kretprobe.multi} (return probe). */
    boolean retprobe() default false;
}
```

- [ ] **Step 2: Write `UProbeMulti.java`**

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a {@code uprobe.multi} BPF program. Emits
 * {@code SEC("uprobe.multi/<glob>")} (or {@code uretprobe.multi/<glob>} when
 * {@link #retprobe()} is true). Attach is NOT automatic — call
 * {@code BPFProgram.attachUprobeMulti(prog, binaryPath, funcs, cookies, retprobe)}
 * at runtime.
 *
 * <p>Requires kernel ≥ 6.6 and attach type {@code BPF_TRACE_UPROBE_MULTI}
 * (id 48).
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface UProbeMulti {
    /** Section-suffix glob label (documentation only). Defaults to {@code "*"}. */
    String value() default "*";

    /** {@code true} to emit {@code uretprobe.multi} (return probe). */
    boolean retprobe() default false;
}
```

- [ ] **Step 3: Extend `BPFFunction.autoAttachableSections`**

Replace line 92 of `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFFunction.java`:

```java
    Set<String> autoAttachableSections = Set.of(
            "fentry", "fexit",
            "kprobe", "kretprobe", "ksyscall", "tp", "lsm",
            "kprobe.multi", "kretprobe.multi",
            "uprobe.multi", "uretprobe.multi");
```

Rationale: these are recognized as valid section markers so annotation-processor validation accepts them, but the runtime `autoAttachPrograms()` skip logic (Task 7) prevents libbpf's `bpf_program__attach` from being invoked on them (which would fail — multi requires the multi API).

- [ ] **Step 4: Add validation test — annotation resolves to expected section prefix**

Append to `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachAnnotationTest.java` (create a new nested test method — file already exists):

```java
    @Test
    void kprobeMultiAndUprobeMultiSectionsAreAutoAttachable() {
        var s = me.bechberger.ebpf.annotations.bpf.BPFFunction.autoAttachableSections;
        org.junit.jupiter.api.Assertions.assertTrue(s.contains("kprobe.multi"));
        org.junit.jupiter.api.Assertions.assertTrue(s.contains("kretprobe.multi"));
        org.junit.jupiter.api.Assertions.assertTrue(s.contains("uprobe.multi"));
        org.junit.jupiter.api.Assertions.assertTrue(s.contains("uretprobe.multi"));
    }
```

- [ ] **Step 5: Run — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl annotations,bpf -am -Dtest=AttachAnnotationTest test'
```

- [ ] **Step 6: Commit**

```bash
git add annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/KProbeMulti.java \
        annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/UProbeMulti.java \
        annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFFunction.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/AttachAnnotationTest.java
git commit -m "feat(annotations): @KProbeMulti and @UProbeMulti section markers"
```

---

## Task 5: `attachKProbeMulti` runtime method

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — insert after existing `attachKProbe` block (around line 800).
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachKProbeMultiUnitTest.java`.

- [ ] **Step 1: Write the failing method-signature unit test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachKProbeMultiUnitTest.java`:

```java
package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

class AttachKProbeMultiUnitTest {

    @Test
    void attachKProbeMultiIsPublicWithExpectedSignature() throws NoSuchMethodException {
        Method m = BPFProgram.class.getMethod("attachKProbeMulti",
                BPFProgram.ProgramHandle.class, String[].class, long[].class, boolean.class);
        assertEquals(BPFProgram.BPFLink.class, m.getReturnType());
        assertTrue(java.lang.reflect.Modifier.isPublic(m.getModifiers()));
    }

    @Test
    void attachKProbeMultiRejectsLengthMismatch() throws Exception {
        // Reflectively construct a stub BPFProgram? No — this is JVM-only:
        // instead invoke via a subclass we synthesize inline (Task-1 pattern).
        // For a length check we can call the static validator we extract.
        assertThrows(IllegalArgumentException.class,
                () -> BPFProgram.validateMultiArrays(
                        new String[]{"a","b"}, new long[]{1L}));
    }
}
```

- [ ] **Step 2: Run — expect FAIL** (`attachKProbeMulti` and `validateMultiArrays` missing).

- [ ] **Step 3: Add `attachKProbeMulti` and the shared validator**

Insert into `BPFProgram.java` immediately after the closing brace of `attachKProbe(...)` at line 800 (before the uprobe section header comment):

```java
    /**
     * Package-visible validator shared by {@link #attachKProbeMulti} and
     * {@link #attachUprobeMulti}. Extracted so unit tests can drive it without
     * loading a real BPF program.
     */
    static void validateMultiArrays(String[] symbols, long[] cookies) {
        if (symbols == null || symbols.length == 0) {
            throw new IllegalArgumentException("multi attach requires at least one symbol");
        }
        if (cookies != null && cookies.length != symbols.length) {
            throw new IllegalArgumentException(
                    "cookies.length (" + cookies.length +
                    ") must equal symbols.length (" + symbols.length + ")");
        }
    }

    /**
     * Attach a single BPF program to many kernel symbols in one syscall via
     * libbpf's {@code bpf_program__attach_kprobe_multi_opts}.
     *
     * <p>The BPF program must be compiled with a {@code SEC("kprobe.multi/…")}
     * or {@code SEC("kretprobe.multi/…")} section (see {@link me.bechberger.ebpf.annotations.bpf.KProbeMulti}).
     *
     * <p>Per-symbol {@code cookies} let one BPF program disambiguate which
     * symbol fired; retrieve inside the program via
     * {@link BPFJ#bpf_get_attach_cookie(me.bechberger.ebpf.type.Ptr)}.
     *
     * <p>Requires kernel ≥ 5.18. On older kernels this method throws
     * {@link BPFLoadError.UnsupportedKernel} before touching libbpf.
     *
     * @param prog     the program to attach
     * @param symbols  kernel symbols to trace (at least one)
     * @param cookies  per-symbol cookies. Must be either {@code null} (no
     *                 cookies) or the same length as {@code symbols}.
     * @param retprobe {@code true} to attach on function return
     * @return the single {@link BPFLink} covering all attachments
     * @throws BPFAttachError if libbpf rejects the attach
     */
    public BPFLink attachKProbeMulti(ProgramHandle prog, String[] symbols,
                                     long[] cookies, boolean retprobe) {
        validateMultiArrays(symbols, cookies);
        if (!me.bechberger.ebpf.bpf.features.Features.hasAttachType(
                me.bechberger.ebpf.bpf.features.BPFAttachType.TRACE_KPROBE_MULTI)) {
            throw new BPFLoadError.UnsupportedKernel(
                    "attach_type TRACE_KPROBE_MULTI", "5.18");
        }
        try (Arena arena = Arena.ofConfined()) {
            // Allocate array of C strings
            var symsArr = arena.allocate(PanamaUtil.POINTER, symbols.length);
            for (int i = 0; i < symbols.length; i++) {
                symsArr.setAtIndex(PanamaUtil.POINTER, i, arena.allocateFrom(symbols[i]));
            }
            MemorySegment cookiesArr = MemorySegment.NULL;
            if (cookies != null) {
                cookiesArr = arena.allocate(JAVA_LONG, cookies.length);
                for (int i = 0; i < cookies.length; i++) {
                    cookiesArr.setAtIndex(JAVA_LONG, i, cookies[i]);
                }
            }

            var opts = arena.allocate(KPROBE_MULTI_OPTS_LAYOUT);
            opts.set(JAVA_LONG,    0,  KPROBE_MULTI_OPTS_LAYOUT.byteSize()); // sz
            opts.set(PanamaUtil.POINTER, 8,  symsArr);                       // syms
            opts.set(PanamaUtil.POINTER, 16, MemorySegment.NULL);            // addrs
            opts.set(PanamaUtil.POINTER, 24, cookiesArr);                    // cookies
            opts.set(JAVA_LONG,    32, (long) symbols.length);               // cnt
            opts.set(JAVA_BOOLEAN, 40, retprobe);                            // retprobe
            opts.set(JAVA_BOOLEAN, 41, false);                               // session
            opts.set(JAVA_BOOLEAN, 42, false);                               // unique_match

            var ret = BPF_PROGRAM__ATTACH_KPROBE_MULTI_OPTS.call(
                    prog.prog(), MemorySegment.NULL /* pattern; syms takes precedence */, opts);
            if (ret.result() == MemorySegment.NULL) {
                throw new BPFAttachError(prog.name +
                        " (kprobe.multi over " + symbols.length + " symbols)",
                        ret.err());
            }
            var link = new BPFLink(ret.result());
            if (link.segment.address() == 0) {
                throw new BPFAttachError(prog.name, ret.err());
            }
            attachedPrograms.add(link);
            return link;
        }
    }
```

- [ ] **Step 4: Run — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachKProbeMultiUnitTest test'
```

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/AttachKProbeMultiUnitTest.java
git commit -m "feat(bpf): attachKProbeMulti backed by bpf_program__attach_kprobe_multi_opts"
```

---

## Task 6: `attachUprobeMulti` runtime method

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — insert after `attachAllUprobes` at line 945.
- Test: extend `AttachKProbeMultiUnitTest.java`.

- [ ] **Step 1: Add failing signature test**

Append to `AttachKProbeMultiUnitTest.java`:

```java
    @Test
    void attachUprobeMultiIsPublicWithExpectedSignature() throws NoSuchMethodException {
        Method m = BPFProgram.class.getMethod("attachUprobeMulti",
                BPFProgram.ProgramHandle.class, String.class,
                String[].class, long[].class, boolean.class);
        assertEquals(BPFProgram.BPFLink.class, m.getReturnType());
    }
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Add `attachUprobeMulti` after `attachAllUprobes` (line 945)**

```java
    /**
     * Attach a single BPF program to many user-space functions in one syscall
     * via libbpf's {@code bpf_program__attach_uprobe_multi}.
     *
     * <p>The BPF program must be compiled with {@code SEC("uprobe.multi/…")}
     * or {@code SEC("uretprobe.multi/…")} (see
     * {@link me.bechberger.ebpf.annotations.bpf.UProbeMulti}).
     *
     * <p>Requires kernel ≥ 6.6. On older kernels this method throws
     * {@link BPFLoadError.UnsupportedKernel} before touching libbpf.
     *
     * @param prog       program to attach
     * @param binaryPath path to the ELF binary containing the target symbols
     * @param funcNames  function symbols to trace (at least one)
     * @param cookies    per-symbol cookies, or {@code null} for none. If
     *                   non-null, must have the same length as {@code funcNames}.
     * @param retprobe   {@code true} to attach on function return
     */
    public BPFLink attachUprobeMulti(ProgramHandle prog, String binaryPath,
                                     String[] funcNames, long[] cookies,
                                     boolean retprobe) {
        validateMultiArrays(funcNames, cookies);
        if (!me.bechberger.ebpf.bpf.features.Features.hasAttachType(
                me.bechberger.ebpf.bpf.features.BPFAttachType.TRACE_UPROBE_MULTI)) {
            throw new BPFLoadError.UnsupportedKernel(
                    "attach_type TRACE_UPROBE_MULTI", "6.6");
        }
        try (Arena arena = Arena.ofConfined()) {
            var symsArr = arena.allocate(PanamaUtil.POINTER, funcNames.length);
            for (int i = 0; i < funcNames.length; i++) {
                symsArr.setAtIndex(PanamaUtil.POINTER, i, arena.allocateFrom(funcNames[i]));
            }
            MemorySegment cookiesArr = MemorySegment.NULL;
            if (cookies != null) {
                cookiesArr = arena.allocate(JAVA_LONG, cookies.length);
                for (int i = 0; i < cookies.length; i++) {
                    cookiesArr.setAtIndex(JAVA_LONG, i, cookies[i]);
                }
            }

            final int BPF_F_UPROBE_MULTI_RETURN = 1;

            var opts = arena.allocate(UPROBE_MULTI_OPTS_LAYOUT);
            opts.set(JAVA_LONG,    0,  UPROBE_MULTI_OPTS_LAYOUT.byteSize()); // sz
            opts.set(PanamaUtil.POINTER, 8,  symsArr);                       // syms
            opts.set(PanamaUtil.POINTER, 16, MemorySegment.NULL);            // offsets
            opts.set(PanamaUtil.POINTER, 24, MemorySegment.NULL);            // ref_ctr_offsets
            opts.set(PanamaUtil.POINTER, 32, cookiesArr);                    // cookies
            opts.set(JAVA_LONG,    40, (long) funcNames.length);             // cnt
            opts.set(JAVA_INT,     48, retprobe ? BPF_F_UPROBE_MULTI_RETURN : 0); // flags
            opts.set(JAVA_INT,     52, -1);                                  // pid = all
            opts.set(PanamaUtil.POINTER, 56, MemorySegment.NULL);            // path (via arg)

            var ret = BPF_PROGRAM__ATTACH_UPROBE_MULTI.call(
                    prog.prog(),
                    -1,                                       // pid
                    arena.allocateFrom(binaryPath),           // binary_path
                    MemorySegment.NULL,                       // func_pattern
                    opts);
            if (ret.result() == MemorySegment.NULL) {
                throw new BPFAttachError(prog.name +
                        " (uprobe.multi over " + funcNames.length +
                        " symbols in " + binaryPath + ")", ret.err());
            }
            var link = new BPFLink(ret.result());
            if (link.segment.address() == 0) {
                throw new BPFAttachError(prog.name, ret.err());
            }
            attachedPrograms.add(link);
            return link;
        }
    }
```

- [ ] **Step 4: Run — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachKProbeMultiUnitTest test'
```

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/AttachKProbeMultiUnitTest.java
git commit -m "feat(bpf): attachUprobeMulti backed by bpf_program__attach_uprobe_multi"
```

---

## Task 7: Auto-attach section-prefix wiring

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — extend `autoAttachPrograms()` (line 1219) and `attachAllUprobes(int, String)` (lines 930-945).
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/AttachAnnotationTest.java` (append).

Behavior: `autoAttachProgram(name)` cannot succeed for `kprobe.multi/*` sections (libbpf's `bpf_program__attach` returns EINVAL — no symbol list). The auto-attach loop must SKIP those with a clear log message pointing users to `attachKProbeMulti`. Same for uprobe.multi in `attachAllUprobes`.

- [ ] **Step 1: Write the failing test**

Append to `AttachAnnotationTest.java`:

```java
    @Test
    void isMultiSectionRecognized() {
        assertTrue(BPFProgram.isMultiAttachSection("kprobe.multi/foo"));
        assertTrue(BPFProgram.isMultiAttachSection("kretprobe.multi/foo"));
        assertTrue(BPFProgram.isMultiAttachSection("uprobe.multi/foo"));
        assertTrue(BPFProgram.isMultiAttachSection("uretprobe.multi/foo"));
        assertFalse(BPFProgram.isMultiAttachSection("kprobe/foo"));
        assertFalse(BPFProgram.isMultiAttachSection("uprobe/foo"));
    }
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Add `isMultiAttachSection` helper**

Insert into `BPFProgram.java` near the top of the class (just after the `attachedPrograms` field declaration, or before `attachKProbe` at line 727):

```java
    /** Returns {@code true} if a section string names a multi-attach probe. */
    public static boolean isMultiAttachSection(String section) {
        if (section == null) return false;
        return section.startsWith("kprobe.multi/")
                || section.startsWith("kretprobe.multi/")
                || section.startsWith("uprobe.multi/")
                || section.startsWith("uretprobe.multi/");
    }
```

- [ ] **Step 4: Wire skip into `autoAttachPrograms()` (line 1219)**

Replace the body of `autoAttachPrograms()`:

```java
    public BPFProgram autoAttachPrograms() {
        var lsmNames = getLSMProgramNames();
        var multiNames = getMultiAttachProgramNames();
        for (var name : getAllAutoAttachablePrograms()) {
            if (multiNames.contains(name)) {
                // Multi-attach programs cannot be attached via bpf_program__attach.
                // The user MUST call attachKProbeMulti / attachUprobeMulti explicitly
                // with the symbol list and cookies. Skipping silently would mask a
                // configuration mistake; emit a JFR event so it shows up in tracing.
                var evt = new BPFEvents.ProgramAttach();
                if (evt.isEnabled()) {
                    evt.programName = name;
                    evt.section = "SKIPPED_MULTI";
                    evt.commit();
                }
                continue;
            }
            if (lsmNames.contains(name)) {
                attachLSMHook(getProgramByName(name));
            } else {
                autoAttachProgram(name);
            }
        }
        return this;
    }

    /** Names of programs whose section marks them as multi-attach. */
    private java.util.Set<String> getMultiAttachProgramNames() {
        var names = new java.util.HashSet<String>();
        var programClass = getClass().getSuperclass();
        for (var method : programClass.getDeclaredMethods()) {
            var annotation = findParentAnnotation(programClass, method, BPFFunction.class);
            if (annotation != null && isMultiAttachSection(annotation.section())) {
                names.add(getBPFFunctionName(method));
            }
        }
        return names;
    }
```

- [ ] **Step 5: Wire skip into `attachAllUprobes` (line 930-945)**

Replace the body of `attachAllUprobes(int pid, String binaryPath)`:

```java
    public List<BPFLink> attachAllUprobes(int pid, String binaryPath) {
        List<BPFLink> links = new ArrayList<>();
        for (Method method : getClass().getMethods()) {
            BPFFunction ann = getAnnotationOfSelfOrOverriden(method, BPFFunction.class);
            if (ann == null) continue;
            String section = ann.section();
            boolean isUprobe    = section.startsWith("uprobe/");
            boolean isUretprobe = section.startsWith("uretprobe/");
            if (isMultiAttachSection(section)) {
                // Multi-attach is not iterable per-symbol from an annotation; the caller
                // must invoke attachUprobeMulti(...) explicitly.
                continue;
            }
            if (!isUprobe && !isUretprobe) continue;
            String symbol  = section.substring(section.indexOf('/') + 1);
            String progName = ann.name().isEmpty() ? method.getName() : ann.name();
            ProgramHandle handle = getProgramByName(progName);
            links.add(attachUprobe(handle, isUretprobe, pid, binaryPath, symbol));
        }
        return links;
    }
```

- [ ] **Step 6: Run — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachAnnotationTest test'
```

- [ ] **Step 7: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/AttachAnnotationTest.java
git commit -m "feat(bpf): auto-attach loops skip kprobe.multi/uprobe.multi sections"
```

---

## Task 8: vng end-to-end — CookieAttachTest

**Files:**
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/CookieAttachTest.java`.

Verifies that two attachments of the same BPF program with different cookies produce distinct per-cookie counters.

- [ ] **Step 1: Write the test**

```java
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CookieAttachTest {

    @BPF(license = "GPL")
    public static abstract class CookieProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include <vmlinux.h>
                #include <bpf/bpf_helpers.h>
                #include <bpf/bpf_tracing.h>
                """;

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Long, Long> perCookieCount;

        @BPFFunction(section = "kprobe/__x64_sys_getuid", autoAttach = false)
        int onGetuid(Ptr<?> ctx) {
            long cookie = BPFJ.bpf_get_attach_cookie(ctx);
            Long cur = perCookieCount.get(cookie);
            long next = (cur == null ? 0 : cur) + 1;
            perCookieCount.put(cookie, next);
            return 0;
        }
    }

    @Test
    void twoAttachmentsWithDistinctCookiesAreDisambiguated() throws Exception {
        try (var prog = BPFProgram.load(CookieProg.class)) {
            var handle = prog.getProgramByName("onGetuid");
            // Attach the SAME program twice: once on __x64_sys_getuid, once on
            // __x64_sys_geteuid, with different cookies.
            prog.attachKProbe(handle, "__x64_sys_getuid",  false, 0xAAAAL);
            prog.attachKProbe(handle, "__x64_sys_geteuid", false, 0xBBBBL);

            // Trigger both syscalls a handful of times.
            for (int i = 0; i < 5; i++) {
                Thread.currentThread();
                // getuid / geteuid via JNI-less path:
                Runtime.getRuntime().exec(new String[]{"/bin/id"}).waitFor();
            }

            Long a = prog.perCookieCount.get(0xAAAAL);
            Long b = prog.perCookieCount.get(0xBBBBL);
            assertNotNull(a, "cookie 0xAAAA should have counted at least one call");
            assertNotNull(b, "cookie 0xBBBB should have counted at least one call");
            assertTrue(a > 0);
            assertTrue(b > 0);
        }
    }
}
```

- [ ] **Step 2: rsync to thinkstation and run under vng**

```
ssh thinkstation 'mkdir -p /tmp/vng-test-logs && cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- bash -lc "HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=CookieAttachTest test" 2>&1 | tee /tmp/vng-test-logs/CookieAttachTest.log'
```
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/CookieAttachTest.java
git commit -m "test(bpf): CookieAttachTest verifies bpf_get_attach_cookie disambiguation"
```

---

## Task 9: vng end-to-end — KProbeMultiSmokeTest and UProbeMultiSmokeTest

**Files:**
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/KProbeMultiSmokeTest.java`.
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/UProbeMultiSmokeTest.java`.

- [ ] **Step 1: Write `KProbeMultiSmokeTest.java`**

```java
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.KProbeMulti;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KProbeMultiSmokeTest {

    @BPF(license = "GPL")
    public static abstract class MultiProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include <vmlinux.h>
                #include <bpf/bpf_helpers.h>
                """;

        @BPFMapDefinition(maxEntries = 64)
        BPFHashMap<Long, Long> hits;

        @BPFFunction(section = "kprobe.multi/dummy", autoAttach = false)
        @KProbeMulti("*")
        int onMany(Ptr<?> ctx) {
            long cookie = BPFJ.bpf_get_attach_cookie(ctx);
            Long cur = hits.get(cookie);
            hits.put(cookie, (cur == null ? 0 : cur) + 1);
            return 0;
        }
    }

    @Test
    void multiAttachTenSymbolsAndReadPerCookieCounters() throws Exception {
        String[] syms = {
                "__x64_sys_getuid", "__x64_sys_geteuid", "__x64_sys_getgid",
                "__x64_sys_getegid", "__x64_sys_getpid", "__x64_sys_gettid",
                "__x64_sys_getppid", "__x64_sys_umask", "__x64_sys_setsid",
                "__x64_sys_setuid"
        };
        long[] cookies = new long[syms.length];
        for (int i = 0; i < syms.length; i++) cookies[i] = 0x1000L + i;

        try (var prog = BPFProgram.load(MultiProg.class)) {
            prog.attachKProbeMulti(prog.getProgramByName("onMany"), syms, cookies, false);
            for (int i = 0; i < 5; i++) {
                Runtime.getRuntime().exec(new String[]{"/bin/id"}).waitFor();
            }
            int matched = 0;
            for (long c : cookies) {
                Long v = prog.hits.get(c);
                if (v != null && v > 0) matched++;
            }
            assertTrue(matched >= 5,
                    "expected ≥5 of 10 symbol cookies to fire, got " + matched);
        }
    }
}
```

- [ ] **Step 2: Write `UProbeMultiSmokeTest.java`**

```java
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.UProbeMulti;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UProbeMultiSmokeTest {

    @BPF(license = "GPL")
    public static abstract class UProg extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include <vmlinux.h>
                #include <bpf/bpf_helpers.h>
                """;

        @BPFMapDefinition(maxEntries = 32)
        BPFHashMap<Long, Long> hits;

        @BPFFunction(section = "uprobe.multi/dummy", autoAttach = false)
        @UProbeMulti("*")
        int onMany(Ptr<?> ctx) {
            long cookie = BPFJ.bpf_get_attach_cookie(ctx);
            Long cur = hits.get(cookie);
            hits.put(cookie, (cur == null ? 0 : cur) + 1);
            return 0;
        }
    }

    @Test
    void multiAttachThreeLibcFuncsAndTriggerFromChild() throws Exception {
        String binaryPath = "/usr/lib/x86_64-linux-gnu/libc.so.6";
        String[] funcs   = { "malloc", "free", "getenv" };
        long[]   cookies = { 0x11L, 0x22L, 0x33L };

        try (var prog = BPFProgram.load(UProg.class)) {
            prog.attachUprobeMulti(prog.getProgramByName("onMany"),
                    binaryPath, funcs, cookies, false);
            // /bin/ls hits all three of malloc/free/getenv.
            Runtime.getRuntime().exec(new String[]{"/bin/ls", "/"}).waitFor();

            int matched = 0;
            for (long c : cookies) {
                Long v = prog.hits.get(c);
                if (v != null && v > 0) matched++;
            }
            assertEquals(3, matched,
                    "all three libc functions should have fired at least once");
        }
    }
}
```

- [ ] **Step 3: Run under vng**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- bash -lc "HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=KProbeMultiSmokeTest,UProbeMultiSmokeTest test" 2>&1 | tee /tmp/vng-test-logs/multi-smoke.log'
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/KProbeMultiSmokeTest.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/UProbeMultiSmokeTest.java
git commit -m "test(bpf): kprobe.multi and uprobe.multi vng smoke tests"
```

---

## Task 10: `KProbeMultiCounter` sample

**Files:**
- Create: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java`.

- [ ] **Step 1: Write the sample**

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.KProbeMulti;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;

import java.util.ArrayList;
import java.util.Comparator;

/**
 * Attaches one BPF program to 20 x86_64 syscall entries via
 * {@link BPFProgram#attachKProbeMulti} and prints the top-10 by call count.
 */
@BPF(license = "GPL")
public abstract class KProbeMultiCounter extends BPFProgram {
    static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_helpers.h>
            """;

    @BPFMapDefinition(maxEntries = 64)
    BPFHashMap<Long, Long> counts;

    @BPFFunction(section = "kprobe.multi/all", autoAttach = false)
    @KProbeMulti("*")
    int onSyscall(Ptr<?> ctx) {
        long cookie = BPFJ.bpf_get_attach_cookie(ctx);
        Long cur = counts.get(cookie);
        counts.put(cookie, (cur == null ? 0 : cur) + 1);
        return 0;
    }

    public static void main(String[] args) throws Exception {
        String[] syms = {
                "__x64_sys_read",  "__x64_sys_write",  "__x64_sys_open",
                "__x64_sys_close", "__x64_sys_stat",   "__x64_sys_fstat",
                "__x64_sys_lstat", "__x64_sys_poll",   "__x64_sys_lseek",
                "__x64_sys_mmap",  "__x64_sys_mprotect","__x64_sys_munmap",
                "__x64_sys_brk",   "__x64_sys_rt_sigaction",
                "__x64_sys_rt_sigprocmask","__x64_sys_ioctl",
                "__x64_sys_pread64","__x64_sys_pwrite64","__x64_sys_readv",
                "__x64_sys_writev"
        };
        long[] cookies = new long[syms.length];
        for (int i = 0; i < syms.length; i++) cookies[i] = i;

        try (var prog = BPFProgram.load(KProbeMultiCounter.class)) {
            prog.attachKProbeMulti(prog.getProgramByName("onSyscall"),
                    syms, cookies, false);
            System.out.println("Sampling for 5s...");
            Thread.sleep(5000);

            record Row(String sym, long count) {}
            var rows = new ArrayList<Row>();
            for (int i = 0; i < syms.length; i++) {
                Long v = prog.counts.get((long) i);
                rows.add(new Row(syms[i], v == null ? 0 : v));
            }
            rows.sort(Comparator.comparingLong(Row::count).reversed());
            System.out.println("Top 10:");
            rows.stream().limit(10).forEach(r ->
                    System.out.printf("  %-32s %d%n", r.sym(), r.count()));
        }
    }
}
```

- [ ] **Step 2: Build (compile only) on thinkstation**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf-samples -am -DskipTests compile'
```
Expected: BUILD SUCCESS.

- [ ] **Step 3: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java
git commit -m "feat(samples): KProbeMultiCounter — top-10 syscalls via attachKProbeMulti"
```

---

## Task 11: Documentation

**Files:**
- Create: `docs/attach-cookies-multi.md`.
- Modify: `README.md` — append one bullet under the existing "Documentation" list.

- [ ] **Step 1: Write `docs/attach-cookies-multi.md`**

```markdown
# Attach cookies and multi-attach (kprobe.multi / uprobe.multi)

Two related capabilities landed in `BPFProgram`:

- Attach cookies — a `u64` value bound to each attachment. Retrievable from
  BPF-side code via `BPFJ.bpf_get_attach_cookie(ctx)`. Lets one BPF program
  disambiguate multiple attachments of itself.
- Multi-attach — a single syscall attaches one BPF program to N kernel
  symbols (`kprobe.multi`, kernel ≥ 5.18) or N user-space functions
  (`uprobe.multi`, kernel ≥ 6.6). Each attachment gets its own cookie.

## Cookie-only

```java
prog.attachKProbe(handle, "__x64_sys_openat",  false, 0xAAAAL);
prog.attachKProbe(handle, "__x64_sys_openat2", false, 0xBBBBL);
```

Inside the BPF program:

```java
long cookie = BPFJ.bpf_get_attach_cookie(ctx);
```

The `long cookie` parameter is optional — existing cookie-less overloads
still work (they pass `cookie = 0L`).

## kprobe.multi

```java
@BPFFunction(section = "kprobe.multi/all", autoAttach = false)
@KProbeMulti("*")
int onSyscall(Ptr<?> ctx) {
    long cookie = BPFJ.bpf_get_attach_cookie(ctx);
    // ...
    return 0;
}

// ...

String[] syms = {"__x64_sys_read", "__x64_sys_write", /* ... */};
long[] cookies = new long[syms.length];
for (int i = 0; i < syms.length; i++) cookies[i] = i;
prog.attachKProbeMulti(prog.getProgramByName("onSyscall"), syms, cookies, false);
```

Feature gate: `Features.hasAttachType(BPFAttachType.TRACE_KPROBE_MULTI)`
must return true. On older kernels the call throws
`BPFLoadError.UnsupportedKernel("attach_type TRACE_KPROBE_MULTI", "5.18")`
before touching libbpf.

## uprobe.multi

```java
prog.attachUprobeMulti(
        prog.getProgramByName("onMany"),
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        new String[]{"malloc", "free", "getenv"},
        new long[]{1L, 2L, 3L},
        false /* not retprobe */);
```

Feature gate: `Features.hasAttachType(BPFAttachType.TRACE_UPROBE_MULTI)`
(kernel ≥ 6.6).

## Auto-attach interaction

`autoAttachPrograms()` and `attachAllUprobes(pid, path)` deliberately SKIP
programs whose section starts with `kprobe.multi/`, `kretprobe.multi/`,
`uprobe.multi/`, or `uretprobe.multi/`. Multi-attach needs the symbol
array — you must call `attachKProbeMulti` / `attachUprobeMulti` explicitly.

## Sample

See `bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java`
— attaches to 20 syscall entries and prints the top-10 by call count.
```

- [ ] **Step 2: Add README bullet**

Append to `README.md` under the "Documentation" section (find the list of doc links; add one line):

```markdown
- [Attach cookies and multi-attach](docs/attach-cookies-multi.md) — per-attachment `u64` cookies and `kprobe.multi` / `uprobe.multi`.
```

- [ ] **Step 3: Commit**

```bash
git add docs/attach-cookies-multi.md README.md
git commit -m "docs: attach cookies and kprobe.multi / uprobe.multi guide"
```

---

## Task 12: Final polish and verification sweep

**Files:** (verification only)

- [ ] **Step 1: Full-module regression on thinkstation**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl annotations,bpf,bpf-samples -am -DskipTests install'
```
Expected: BUILD SUCCESS.

- [ ] **Step 2: JVM tests**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=AttachCookieUnitTest,AttachKProbeMultiUnitTest,AttachAnnotationTest test'
```
Expected: all green.

- [ ] **Step 3: vng end-to-end tests**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- bash -lc "HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=CookieAttachTest,KProbeMultiSmokeTest,UProbeMultiSmokeTest test" 2>&1 | tee /tmp/vng-test-logs/final-sweep.log'
```
Expected: PASS 3/3.

- [ ] **Step 4: Grep for placeholders / TODO / emoji**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && git diff --name-only HEAD~12..HEAD | xargs grep -nE "TODO|FIXME|XXX|:-\)" 2>/dev/null || echo clean'
```
Expected: `clean`.

- [ ] **Step 5: Final commit if any polish needed**

```bash
git commit --allow-empty -m "chore: attach cookies + multi-attach sweep complete"
```

---

## Self-review

Spec coverage:
- Part A cookie fix: Tasks 1 (helper stub + opts layouts) + 2 (kprobe cookie) + 3 (uprobe cookie).
- Part B multi: Tasks 4 (annotations) + 5 (kprobe.multi) + 6 (uprobe.multi) + 7 (auto-attach wiring).
- Part C verification: Tasks 8 (CookieAttachTest) + 9 (KProbeMultiSmokeTest + UProbeMultiSmokeTest) + 10 (sample) + 12 (sweep).
- Docs: Task 11.

Type / signature consistency:
- `attachKProbe(prog, symbol, retprobe, cookie)` — used in Tasks 2, 8. Consistent.
- `attachKProbeMulti(prog, symbols, cookies, retprobe)` — Tasks 5, 8, 9, 10. Consistent.
- `attachUprobeMulti(prog, binaryPath, funcNames, cookies, retprobe)` — Tasks 6, 9. Consistent.
- `BPFJ.bpf_get_attach_cookie(Ptr<?> ctx)` — Task 1 signature, used in Tasks 8, 9, 10. Consistent.
- `BPFProgram.isMultiAttachSection(String)` — Task 7. Used inside `autoAttachPrograms` and `attachAllUprobes` in the same task.
- `validateMultiArrays(String[], long[])` — Task 5. Reused in Task 6.

No placeholders detected on rescan.

---
