# Design proposals for the top 5 hello-ebpf peer-library gaps

## Preamble

This document turns the two peer-library surveys —
`/Users/i560383_1/code/experiments/hello-ebpf/docs/superpowers/research/research-gap-catalog-rust-go.md`
(aya, libbpf-rs, cilium/ebpf, libbpfgo) and
`/Users/i560383_1/code/experiments/hello-ebpf/docs/superpowers/research/research-gap-catalog-otel-awesome.md`
(OpenTelemetry eBPF profiler + qmonnet/awesome-ebpf) — into implementation-ready
designs for the five highest-leverage gaps. It is a design pass only: nothing is
built, and the intended reader is the hello-ebpf maintainer.

Shared design principles across all five proposals:

- Fit the existing surface. New map wrappers follow the shape of
  `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFDevMap.java`
  and `.../BPFRingBuffer.java` — annotated with `@BPFMapClass(cTemplate=..., javaTemplate=...)`,
  extend `BPFMap` (or `BPFBaseMap` where appropriate), expose C-side helpers as
  `@BuiltinBPFFunction`/`@NotUsableInJava` stubs that throw `MethodIsBPFRelatedFunction`.
- New program types register (a) a SEC prefix in
  `BPFFunction.autoAttachableSections`, (b) an attach path on `BPFProgram`
  mirroring the shape of `attachKProbe` / `attachPerfEvent` / `xdpAttach`, and
  (c) a shorthand annotation in `me.bechberger.ebpf.annotations.bpf` when a
  single-string attach target makes sense.
- The user-facing runtime is idiomatic Java: `Stream<T>` and `Iterator<T>` for
  cursor-like readers, `CompletableFuture<Void>` for async lifecycles,
  `AutoCloseable` for anything that owns a link fd, `SLF4J` for stray logs.
- Panama FFI additions land in the same `me.bechberger.ebpf.bpf.raw.Lib`
  regeneration bucket. Struct layouts follow the manual-layout pattern used
  today for `bpf_program__attach_uprobe_opts` (`BPFProgram.java:670`).

The five gaps addressed, in the order asked:

1. Socket-plane program types plus SOCKMAP/SOCKHASH map wrappers.
2. kprobe.multi / uprobe.multi with per-site cookies (closing the existing
   hardcoded-cookie regression).
3. BPF iterator programs exposed as `Stream<Record>` / `Iterator<Record>`.
4. HotSpot / native DWARF unwinder and Java-frame symbolization for the
   profiler.
5. Perf-event-array wrapper plus hotplug-aware sampling and hardware perf
   counter helpers.

## Gap 1 — Socket-plane program types + SOCKMAP/SOCKHASH map wrappers

### Restated problem

The rust-go catalog names `sk_msg` / `sk_skb` / `sock_ops` and their
SOCKMAP/SOCKHASH backing store as the third universal gap (present in all four
peer libraries, missing from hello-ebpf). The
`me.bechberger.ebpf.bpf.map.MapTypeId` enum already lists `SOCKMAP`,
`SOCKHASH`, `REUSEPORT_SOCKARRAY`, but there is no wrapper class, no attach
path, and no helper binding for the redirect helpers. Without this, hello-ebpf
can only observe traffic (XDP / TC / cgroup\_skb) — it cannot rewrite or
redirect socket data, which excludes the entire Cilium / Merbridge / L7-mesh
category of use cases.

### Proposed Java-side API

New shorthand annotations under `me.bechberger.ebpf.annotations.bpf`:

```java
@Retention(RUNTIME) @Target(METHOD)
public @interface SkMsg {}          // section = "sk_msg", autoAttach via sock_map attach

@Retention(RUNTIME) @Target(METHOD)
public @interface SkSkb {           // section = "sk_skb/stream_verdict" or "/stream_parser"
    Kind value() default Kind.VERDICT;
    enum Kind { PARSER, VERDICT }
}

@Retention(RUNTIME) @Target(METHOD)
public @interface SockOps {}        // section = "sockops"

@Retention(RUNTIME) @Target(METHOD)
public @interface SkLookup {}       // section = "sk_lookup"

@Retention(RUNTIME) @Target(METHOD)
public @interface SkReuseport {}    // section = "sk_reuseport"
```

New map wrappers under `me.bechberger.ebpf.bpf.map`:

```java
@BPFMapClass(cTemplate = """
    struct {
        __uint(type, BPF_MAP_TYPE_SOCKMAP);
        __uint(max_entries, $maxEntries);
        __type(key, u32);
        __type(value, u64);
    } $field SEC(".maps");
    """, javaTemplate = "new $class($fd, $maxEntries)")
public class BPFSockMap extends BPFMap {
    public boolean put(int slot, int sockFd);
    public boolean delete(int slot);
    @BuiltinBPFFunction("bpf_sock_map_update($arg1, $arg2, &$this, $arg3)")
    @NotUsableInJava
    public long bpf_update(Ptr<bpf_sock_ops> ctx, Ptr<?> key, long flags);
    @BuiltinBPFFunction("bpf_sk_redirect_map(&$this, $arg1, $arg2, $arg3)")
    @NotUsableInJava
    public long bpf_sk_redirect(Ptr<__sk_buff> skb, int key, long flags);
    @BuiltinBPFFunction("bpf_msg_redirect_map(&$this, $arg1, $arg2, $arg3)")
    @NotUsableInJava
    public long bpf_msg_redirect(Ptr<sk_msg_md> msg, int key, long flags);
}

public class BPFSockHash<K> extends BPFMap {
    public boolean put(K key, int sockFd);
    @BuiltinBPFFunction("bpf_sock_hash_update($arg1, &$this, $arg2, $arg3)")
    @NotUsableInJava public long bpf_update(Ptr<bpf_sock_ops> ctx, Ptr<K> key, long flags);
    @BuiltinBPFFunction("bpf_sk_redirect_hash(&$this, $arg1, $arg2, $arg3)")
    @NotUsableInJava public long bpf_sk_redirect(Ptr<__sk_buff> skb, Ptr<K> key, long flags);
    @BuiltinBPFFunction("bpf_msg_redirect_hash(&$this, $arg1, $arg2, $arg3)")
    @NotUsableInJava public long bpf_msg_redirect(Ptr<sk_msg_md> msg, Ptr<K> key, long flags);
}

public class BPFReuseportSockArray extends BPFMap { /* similar shape */ }
```

New attach methods on `BPFProgram`:

```java
public BPFLink attachSockOps(ProgramHandle prog, String cgroupName);
public BPFLink attachSkMsg(ProgramHandle prog, BPFSockMap map);      // or BPFSockHash
public BPFLink attachSkSkb(ProgramHandle prog, BPFSockMap map, SkSkb.Kind kind);
public BPFLink attachSkLookup(ProgramHandle prog, String netnsPath); // "/proc/self/ns/net"
public BPFLink attachSkReuseport(ProgramHandle prog, int socketFd);
```

Helpers `bpf_sk_assign(ctx, sk, flags)` and `bpf_sk_select_reuseport(ctx, map,
key, flags)` land on the `BPFJ` facade using the same
`@BuiltinBPFFunction("bpf_sk_assign($arg1, $arg2, $arg3)")` shape.

### Proposed C-side codegen / template

The compiler plugin already emits `SEC("<section>") int fname(...)` for any
`@BPFFunction` with a `section()`. The five new shorthand annotations expand at
annotation-processor time into `@BPFFunction(section="sk_msg", autoAttach=true)`
(and so on). The plugin needs no new codegen; it only needs to accept the new
sections in `Translator.java` (which today derives from `BPFFunction.section()`
without special-casing hooks). The
`autoAttachableSections` set in
`/Users/i560383_1/code/experiments/hello-ebpf/annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFFunction.java:92`
must be extended:

```java
Set<String> autoAttachableSections = Set.of(
    "fentry", "fexit", "kprobe", "kretprobe", "ksyscall", "tp", "lsm",
    "sk_msg", "sk_skb", "sockops", "sk_lookup", "sk_reuseport");
```

For non-libbpf-auto-attachable ones (sk\_msg needs a sockmap fd, sk\_lookup
needs a netns fd), autoAttach stays false and the user calls
`attachSkMsg(prog, sockMap)` explicitly. The `autoAttachPrograms()` code path
at `BPFProgram.java:1075` gets a dispatch table keyed on the section prefix that
routes to the right attach helper — the current shape (LSM-vs-generic) already
uses this pattern.

### Kernel / libbpf touch points

- `bpf_prog_attach(prog_fd, target_fd, BPF_SK_MSG_VERDICT / BPF_SK_SKB_STREAM_*
  / BPF_CGROUP_SOCK_OPS / BPF_SK_LOOKUP / BPF_SK_REUSEPORT_SELECT)` — this is
  the low-level path. libbpf also exposes `bpf_program__attach_sockmap`,
  `bpf_program__attach_netns`, and `bpf_link_create` with `attach_type` set.
- Panama additions: `bpf_prog_attach(int prog_fd, int target_fd, int
  attach_type)` and `bpf_program__attach_netns(prog, netns_fd)`.
- Struct layouts: `bpf_sock_ops`, `bpf_sock`, `sk_msg_md`, `sk_reuseport_md`
  are BTF types — the compiler plugin already imports vmlinux types from
  `BpfDefinitions.java`, so context parameters can be typed
  `Ptr<bpf_sock_ops>` transparently.

### Fit with existing hello-ebpf machinery

- Extend `MapTypeId` — already present, no change.
- Add wrappers under
  `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/map/`.
- Extend `BPFFunction.autoAttachableSections`
  (`.../annotations/bpf/BPFFunction.java:92`).
- Add attach helpers to
  `.../bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` right after
  the existing `cgroupAttach` (line ~1268); mirror the LSM attach pattern.
- Extend the shorthand-annotation loop in
  `BPFProgram.java:504` (`getShorthandAttachName`) to include the five new
  annotations.
- The annotation processor currently walks `@BPFMapDefinition` fields and emits
  map-creation stubs in the generated `*Impl.java`; it needs no change beyond
  recognising the new `@BPFMapClass` annotations, which it already handles
  generically.

### Sample program

```java
@BPF(license = "GPL")
public abstract class SockMeshShortcut extends BPFProgram {
    @BPFMapDefinition(maxEntries = 65536)
    BPFSockHash<SockKey> sockets;

    @Type
    record SockKey(int localPort, int remotePort, int localIp, int remoteIp) {}

    @SockOps
    int trackSockets(Ptr<bpf_sock_ops> ctx) {
        if (ctx.val().op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
            ctx.val().op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
            SockKey k = keyFromOps(ctx);
            sockets.bpf_update(ctx, Ptr.of(k), BPF_NOEXIST);
        }
        return 0;
    }

    @SkMsg
    int redirectMsg(Ptr<sk_msg_md> msg) {
        SockKey peer = mirror(msg);
        return (int) sockets.bpf_msg_redirect(msg, Ptr.of(peer), BPF_F_INGRESS);
    }

    public static void main(String[] args) throws Exception {
        try (var p = BPFProgram.load(SockMeshShortcut.class)) {
            p.attachSockOps(p.getProgramByName("trackSockets"), "kubepods.slice");
            p.attachSkMsg(p.getProgramByName("redirectMsg"), p.sockets);
            Thread.currentThread().join();
        }
    }
}
```

### Rollout plan

- **M1 — SOCKMAP + `attachSockOps` + `bpf_sock_map_update`.** Ships
  `BPFSockMap`, the `@SockOps` annotation, `attachSockOps(prog, cgroupName)`,
  the `bpf_sock_map_update` helper binding. Integration test on thinkstation:
  attach `SockOps` handler to a cgroup, spawn two `nc` peers, observe the
  sockmap slot count from userspace via a batch scan.
- **M2 — `sk_msg` and `bpf_msg_redirect_map`.** Adds `@SkMsg`,
  `attachSkMsg(prog, sockMap)`, and the redirect helpers. Test: two-loopback
  socket pair, `sk_msg` handler that returns `SK_PASS` with a redirect;
  userspace asserts payload arrives on the mirror socket.
- **M3 — `sk_skb` parser + verdict.** Adds `@SkSkb(PARSER)` and `@SkSkb(VERDICT)`
  plus `attachSkSkb`. Test: HTTP-request framer that hands whole requests as
  units.
- **M4 — `BPFSockHash<K>` with parametric key.** Adds the hash flavour; needs
  the annotation processor to emit the correct `__type(key, ...)` in the C
  template based on the generic parameter (same trick `BPFHashMap` uses).
  Test: 5-tuple keyed redirection.
- **M5 — `sk_lookup` + `sk_reuseport` + `BPFReuseportSockArray`.** Ships
  `@SkLookup` (attach to netns) and `@SkReuseport` (attach to a listening fd).
  Test: two-port listener that routes odd/even destination ports to different
  processes.

M2 depends on M1 (needs a sockmap to redirect into). M3 is independent of M2.
M4 depends on M1. M5 is independent.

### Risks and open questions

- SEC-name variants differ across libbpf versions (`sk_skb/stream_verdict` vs
  `sk_skb`). Need to confirm which prefix current libbpf recognises for the
  auto-attach path — falling back to explicit `bpf_prog_attach` may be safer.
- The `bpf_sock_hash_update` helper takes the key as a pointer to bytes with
  size baked into the map's value size — generic wrappers on `BPFSockHash<K>`
  need to enforce that `sizeof(K)` matches the C-side declared key type; the
  annotation processor's existing type-size check for `BPFHashMap` should
  extend cleanly.
- `sk_reuseport` attach is via `setsockopt(SO_ATTACH_REUSEPORT_EBPF)`, not
  `bpf_prog_attach`. This is a separate code path in the attach helper.
- Interaction with sched\_ext: none — socket-plane programs run in softirq /
  syscall context, disjoint from struct\_ops.
- Verifier acceptance of `bpf_msg_redirect_hash` depends on kernel version
  (5.10+). Should the design gate the annotation with `@Requires` metadata?
  Recommendation: yes, add a `minKernel = "5.10"` attribute to each shorthand
  annotation and surface it via `Requires.java`.

### Effort estimate

- M1: M (1.5 w)
- M2: S (0.5 w)
- M3: M (1 w)
- M4: S (0.5 w) — extends M1
- M5: M (1.5 w)

Total: 5 weeks for one engineer.

## Gap 2 — kprobe.multi / uprobe.multi with per-site cookies

### Restated problem

Both the rust-go catalog (`§Program types "kprobe.multi and uprobe.multi"`)
and the awesome-ebpf survey mark this as a top-3 universal gap. Peers can
attach one program to hundreds of kernel symbols in one syscall and let the
handler distinguish sites via `bpf_get_attach_cookie()`. Hello-ebpf still loops
`attachKProbe` per symbol.

Related regression: `bpf_cookie` is declared in the `UPROBE_OPTS_LAYOUT`
struct at
`/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java:673`
but hardcoded to `0L` at line 711. Cookie plumbing is not exposed on any
attach path. The unified design below fixes both.

### Proposed Java-side API

New shorthand annotations:

```java
@Retention(RUNTIME) @Target(METHOD)
public @interface KProbeMulti {
    String[] symbols() default {};       // fixed list at compile time
    String  symbolsPattern() default ""; // libbpf-style glob, resolved at attach
    boolean returnProbe() default false;
}

@Retention(RUNTIME) @Target(METHOD)
public @interface UProbeMulti {
    String  binary();
    String[] symbols() default {};
    long[]   offsets() default {};       // when the caller has offsets, not names
    boolean  returnProbe() default false;
}
```

New attach methods on `BPFProgram`:

```java
public record KProbeMultiSite(String symbol, long cookie) {}
public BPFLink attachKProbeMulti(ProgramHandle prog, List<KProbeMultiSite> sites,
                                  boolean retprobe);
public BPFLink attachKProbeMulti(ProgramHandle prog, String glob, boolean retprobe);

public record UProbeMultiSite(String symbol, long offset, long cookie) {}
public BPFLink attachUProbeMulti(ProgramHandle prog, String binaryPath, int pid,
                                  List<UProbeMultiSite> sites, boolean retprobe);
```

C-side helper binding (BPF-visible):

```java
@BuiltinBPFFunction("bpf_get_attach_cookie($arg1)")
@NotUsableInJava
public static long getAttachCookie(Ptr<?> ctx) {
    throw new MethodIsBPFRelatedFunction();
}
```

Cookie plumbing on the existing `attachUprobe`: add an overload that takes a
`long bpfCookie` and stops writing 0L at line 711. Same for a new
`attachKProbe(prog, symbol, retprobe, cookie)` overload that uses
`bpf_program__attach_kprobe_opts` instead of the current
`bpf_program__attach_kprobe`.

### Proposed C-side codegen / template

The BPF C function body stays identical — one function serves N sites. The
compiler plugin currently emits `SEC("kprobe/<sym>") int fname(pt_regs *ctx)`;
for a `@KProbeMulti` method it must emit `SEC("kprobe.multi/*")` (a wildcard
place-holder; libbpf ignores it because the actual site list is passed at
attach). A `@UProbeMulti` method emits
`SEC("uprobe.multi/<binary>:*") int fname(pt_regs *ctx)`.

Inside the handler, the user calls `getAttachCookie(ctx)` which lowers to
`bpf_get_attach_cookie(ctx)`. No change to `Translator.java` beyond adding
the two new SEC prefixes.

### Kernel / libbpf touch points

- `bpf_program__attach_kprobe_multi_opts(prog, pattern, opts)` — libbpf ≥ 1.0.
  Panama binding:
  ```
  MemorySegment bpf_program__attach_kprobe_multi_opts(
      MemorySegment prog, MemorySegment pattern,
      MemorySegment opts);   // struct with cnt, syms/addrs, cookies, retprobe
  ```
- `bpf_program__attach_uprobe_multi(prog, pid, path, funcPattern, opts)` —
  libbpf ≥ 1.3. Needs a small struct-layout binding for
  `struct bpf_uprobe_multi_opts` (cnt / syms / offsets / cookies / retprobe /
  ref\_ctr\_offsets / pid).
- `bpf_get_attach_cookie` helper is helper ID 174, no vmlinux dependency.
- Cookie plumbing for the existing single-site paths uses the already-mapped
  `bpf_program__attach_uprobe_opts` (just write the field) and adds a
  `bpf_program__attach_kprobe_opts` binding (four fields: sz, bpf\_cookie,
  offset, retprobe).

### Fit with existing hello-ebpf machinery

- Add `@KProbeMulti` / `@UProbeMulti` under
  `.../annotations/bpf/`.
- Extend `getShorthandAttachName` at
  `.../bpf/BPFProgram.java:503`.
- Extend `autoAttachableSections` at
  `.../annotations/bpf/BPFFunction.java:92` with `"kprobe.multi"`,
  `"uprobe.multi"`.
- Fix the hardcoded `0L` at `.../bpf/BPFProgram.java:711` by adding an
  overload that threads a `bpfCookie` parameter, then delegate the existing
  method to it.
- The autoAttach path (`BPFProgram.java:1075`) needs a dispatch step: when
  a program has section `kprobe.multi/*`, gather the annotation's symbols and
  call `attachKProbeMulti` instead of the generic `bpf_program__attach`.
- Emit a helper on the generated Impl class (annotation-processor change under
  `bpf-processor/`) that returns the compile-time `symbols[]` for each
  `@KProbeMulti` method — mirrors the way `getAutoAttachablePrograms()` is
  emitted today.

### Sample program

```java
@BPF(license = "GPL")
public abstract class OpenatFamily extends BPFProgram {
    @Type record OpEvent(int pid, long cookie, long ts) {}

    @BPFMapDefinition(maxEntries = 1 << 16)
    BPFRingBuffer<OpEvent> events;

    @KProbeMulti(symbols = {
        "do_sys_openat2", "__x64_sys_openat", "do_faccessat",
        "do_unlinkat", "do_symlinkat", "do_renameat2"})
    int onFileSyscall(Ptr<pt_regs> ctx) {
        OpEvent e = new OpEvent(
            (int) bpf_get_current_pid_tgid(),
            getAttachCookie(ctx),
            bpf_ktime_get_ns());
        events.reserveAndSubmit(e);
        return 0;
    }

    public static void main(String[] args) throws Exception {
        try (var p = BPFProgram.load(OpenatFamily.class)) {
            p.autoAttachPrograms();     // fires attachKProbeMulti
            p.events.consume((buf, evt) ->
                System.out.printf("pid=%d symIdx=%d ts=%d%n",
                    evt.pid(), evt.cookie(), evt.ts()));
        }
    }
}
```

The compile-time cookie for symbol `i` is `i` by convention; expose a
`KProbeMulti.SITES` static that the user can pass to a `Map<Long, String>` at
runtime to decode.

### Rollout plan

- **M1 — Cookie plumbing on existing attach paths.** Fix the 0L at
  `BPFProgram.java:711`, add cookie parameter to `attachUprobe` overloads, add
  `attachKProbe(..., cookie)` via `bpf_program__attach_kprobe_opts`. Bind
  `bpf_get_attach_cookie` in `BPFJ`. Unit test: two kprobes on the same handler
  with distinct cookies, decode by cookie in a `BPFRingBuffer`.
- **M2 — `attachKProbeMulti` with fixed symbol list.** Add the Panama binding
  for `bpf_program__attach_kprobe_multi_opts`, the new SEC prefix, the
  autoAttach dispatch, and the `@KProbeMulti(symbols=...)` annotation.
  Integration test on thinkstation: attach to six `do_*` symbols in one call
  and verify the link-fd count in `/proc/self/fdinfo/*/link` is exactly one.
- **M3 — Glob / pattern support.** Extend `attachKProbeMulti` to accept a glob
  string (libbpf resolves against `/proc/kallsyms`). Test: `symbolsPattern =
  "do_sys_*"`.
- **M4 — `attachUProbeMulti`.** New Panama binding, new annotation. Integration
  test: uprobe over multiple libc symbols on a `stress-ng --malloc` workload.
- **M5 — Auto-cookie generation.** Annotation-processor sugar: assign an
  auto-incrementing cookie to each symbol in `@KProbeMulti(symbols=...)` and
  emit a static `Map<Long, String>` on the generated Impl so users can label
  events without maintaining the cookie assignment by hand.

M2 depends on M1 (needs cookie plumbing); M3 depends on M2; M4 is independent
of M2/M3; M5 depends on M2.

### Risks and open questions

- `bpf_program__attach_kprobe_multi_opts` requires kernel 5.18. Should the
  annotation carry `@Requires(minKernel = "5.18")` and the loader downgrade to
  N single-site attaches on older kernels? Recommendation: yes, add the
  fallback with a warning.
- `symbolsPattern` semantics differ subtly between glob (kernel side) and Java
  regex — document the libbpf glob syntax explicitly.
- Verifier interaction: `bpf_get_attach_cookie` is only valid inside
  `kprobe.multi` / `uprobe.multi` / `perf_event` programs. Compiler-plugin
  should refuse to translate a call from a non-cookie-carrying context.
- Cookie collisions across `attachKProbeMulti` calls sharing a program: the
  attach-time cookie is per-link, not global. Doc-only clarification.
- Interaction with sched\_ext: struct\_ops attach path is different; no risk
  of cross-contamination.

### Effort estimate

- M1: S (0.5 w)
- M2: M (1 w)
- M3: S (0.5 w)
- M4: M (1 w)
- M5: S (0.5 w)

Total: 3.5 weeks.

## Gap 3 — BPF iterator programs

### Restated problem

Iterator programs (`SEC("iter/task")`, `iter/tcp`, `iter/bpf_map`,
`iter/cgroup`, `iter/task_file`, `iter/bpf_prog`, `iter/udp`, `iter/sock`) let
a BPF program produce a `seq_file`-like stream that userspace reads by opening
the link fd. All four peer libraries have this; hello-ebpf does not. Java is a
natural home for this pattern — a `Stream<T>` over live kernel state (all
tasks, all sockets, all cgroups) is exactly what observability tools want.

### Proposed Java-side API

Shorthand annotation:

```java
@Retention(RUNTIME) @Target(METHOD)
public @interface Iter {
    /** target: task, tcp, udp, tcp6, udp6, sock, sock_map, bpf_map, cgroup, task_file, bpf_prog, ... */
    String value();
    /** optional restriction: pass a pid, cgroup fd, or map fd at attach time */
    Restrict restrict() default Restrict.NONE;
    enum Restrict { NONE, PID, CGROUP_FD, MAP_FD }
}
```

New attach + read API on `BPFProgram`:

```java
public class BPFIterator<T> implements Iterator<T>, AutoCloseable {
    public boolean hasNext();
    public T next();
    public void close();
}

public <T> BPFIterator<T> attachIter(ProgramHandle prog, Class<T> recordType);
public <T> BPFIterator<T> attachIter(ProgramHandle prog, Class<T> recordType,
                                     IterRestriction restriction);
public <T> Stream<T> streamIter(ProgramHandle prog, Class<T> recordType);
```

`IterRestriction` is a sealed interface: `IterRestriction.pid(int)`,
`IterRestriction.cgroupFd(int)`, `IterRestriction.mapFd(int)`.

BPF-side helpers exposed as `@BuiltinBPFFunction`:

```java
public class BPFIter {
    @BuiltinBPFFunction("BPF_SEQ_PRINTF(ctx->meta->seq, $arg1, $args...)")
    @NotUsableInJava
    public static void seqPrintf(String fmt, Object... args);

    @BuiltinBPFFunction("bpf_seq_write($arg1, $arg2, sizeof(*$arg2))")
    @NotUsableInJava
    public static long seqWrite(Ptr<?> ctx, Ptr<?> record);
}
```

### Proposed C-side codegen / template

The compiler plugin needs a new context-type mapping: `@Iter("task")` methods
receive a `Ptr<bpf_iter__task>`, whose fields are `meta` (with `seq`) and
`task`. Similarly `iter/tcp` → `bpf_iter__tcp`, etc. These BTF types are all in
vmlinux.h and reachable via `BpfDefinitions.java`.

Emit:

```c
SEC("iter/task")
int dumpTasks(struct bpf_iter__task *ctx) {
    struct task_struct *task = ctx->task;
    if (task == NULL) return 0;
    Record r = ...;
    bpf_seq_write(ctx->meta->seq, &r, sizeof(r));
    return 0;
}
```

The framework should prefer the binary `bpf_seq_write` path over
`BPF_SEQ_PRINTF` because Java-side parsing of a printf format is fragile.
`bpf_seq_write` writes a fixed-size `@Type`-annotated record; userspace reads
back an integer number of records from the link fd. This is the same trick
libbpf-tools uses for `bpf_iter/tcp`.

### Kernel / libbpf touch points

- `bpf_program__attach_iter(prog, &opts)` with `struct bpf_iter_attach_opts`
  carrying `link_info` (union: pid / cgroup / map fd). Kernel 5.11+.
- Retrieve the link fd via `bpf_link__fd(link)`.
- `bpf_iter_create(link_fd)` returns an iterator fd; `read(iter_fd, buf, N)`
  streams the serialized records.
- Panama additions: `bpf_program__attach_iter`, `bpf_iter_create`, and enough
  of `struct bpf_iter_link_info` to fill in `map.map_fd`,
  `cgroup.cgroup_fd`, `task.pid`, `task.tid`.

### Fit with existing hello-ebpf machinery

- Add `@Iter` annotation under
  `.../annotations/bpf/`.
- Extend `autoAttachableSections` at
  `.../annotations/bpf/BPFFunction.java:92` with `"iter"`.
- Register the SEC prefix `"iter"` in `Translator.java` context-type
  resolution alongside the existing kprobe/fentry mappings (grep for how
  `bpf_perf_event_data` context type is currently plumbed).
- Add `BPFIterator` class next to `BPFRingBuffer` under
  `.../bpf/src/main/java/me/bechberger/ebpf/bpf/map/` (it is not a map, but
  colocation with other consumer types is cleaner than a new package).
- Add `attachIter` / `streamIter` on `BPFProgram` next to `rawTracepointAttach`
  (`BPFProgram.java:1139`).
- Add a small Panama layout for `bpf_iter_attach_opts` — mirror the pattern at
  `BPFProgram.java:670`.

The record type marshalling reuses the existing `@Type` machinery in
`BPFType.java` — the Impl class already knows how to convert `@Type` records
into byte layouts.

### Sample program

```java
@BPF(license = "GPL")
public abstract class DumpTcpFlows extends BPFProgram {

    @Type
    record Flow(int pid, int localPort, int remotePort, int state,
                long rxBytes, long txBytes) {}

    @Iter("tcp")
    int dumpTcp(Ptr<bpf_iter__tcp> ctx) {
        Ptr<sock_common> sk = ctx.val().sk_common;
        if (sk == null) return 0;
        Flow f = new Flow(
            bpf_get_current_pid_tgid() >> 32,
            ntohs(sk.val().skc_num),
            ntohs(sk.val().skc_dport),
            sk.val().skc_state,
            0, 0);
        BPFIter.seqWrite(Ptr.of(ctx.val().meta.seq), Ptr.of(f));
        return 0;
    }

    public static void main(String[] args) throws Exception {
        try (var p = BPFProgram.load(DumpTcpFlows.class);
             Stream<Flow> flows = p.streamIter(
                 p.getProgramByName("dumpTcp"), Flow.class)) {
            flows.filter(f -> f.state() == TCP_ESTABLISHED)
                 .forEach(f -> System.out.printf(
                     ":%d -> :%d%n", f.localPort(), f.remotePort()));
        }
    }
}
```

### Rollout plan

- **M1 — `iter/task` end to end.** Ships `@Iter("task")`, the
  `BPFIterator<T>` reader, `attachIter`, the `bpf_seq_write` helper binding,
  and enough context-type resolution for `bpf_iter__task`. Integration test:
  dump all tasks, compare cardinality against `ps -e | wc -l` within a
  tolerance.
- **M2 — `iter/tcp` + `iter/tcp6` + `iter/udp` variants.** Add the three
  context types to the mapping table. Test: compare against `ss -tan` output.
- **M3 — `iter/bpf_map` + `iter/bpf_prog` + `iter/cgroup`.** Plus the
  `IterRestriction` machinery for map/cgroup-scoped iterators. Test: dump
  entries of an already-loaded pinned hash map without a schema (raw bytes).
- **M4 — `Stream<T>` wrapper and buffered reader.** Backing the Java-side
  reader with an 8 KiB buffer and record framing (peek fixed sizeof(T),
  advance). Async variant `streamIterAsync` returns a `Publisher<T>` for
  RxJava / Reactor consumers. Test: back-pressure by pausing the consumer and
  watching the reader block.
- **M5 — Aggregation view for the JFR pipeline.** Ship an `iter/task` sample
  that emits per-process CPU-time deltas into a JFR event — the "read-only"
  half of continuous profiling.

M2/M3 depend on M1. M4 depends on M1 (needs the reader). M5 depends on M1.

### Risks and open questions

- The set of iterator kinds is kernel-version-gated (e.g., `iter/tcp` needs
  6.0+, `iter/sock_map` needs 6.5+). Document per-iter minimum kernel and
  gate with `@Requires`.
- `bpf_iter__tcp` context struct fields drift between kernels — `sk_common`
  vs `sk`. The compiler plugin already handles this via CO-RE relocations, but
  the sample should use `BPF_CORE_READ` to be robust.
- Record-framing over `read(iter_fd, buf, N)` is not self-describing. If the
  BPF handler emits variable-sized records via `BPF_SEQ_PRINTF`, the design
  falls apart. Recommendation: constrain the initial API to fixed-size `@Type`
  records only, document `BPF_SEQ_PRINTF` as an unsafe escape hatch.
- Interaction with sched\_ext: `iter/scx_dsq` is already used by hello-ebpf's
  DSQ iterator (`bpf_iter_scx_dsq`). Naming needs to be distinct enough not
  to confuse users — recommend calling the new class `BPFSeqIterator` if
  clarity wins over brevity.
- The link fd created by `bpf_program__attach_iter` is bound to a filter
  (pid / cgroup); re-reading is not idempotent. Should the `Iterator<T>`
  contract allow re-open? Recommend: no; document it as one-shot, add a
  `refresh()` that closes and re-attaches with the same restriction.

### Effort estimate

- M1: L (2 w) — new prog type, new reader, new context mapping.
- M2: S (0.5 w)
- M3: M (1 w)
- M4: M (1 w)
- M5: S (0.5 w)

Total: 5 weeks.

## Gap 4 — HotSpot + native DWARF unwinder + Java-frame symbolization

### Restated problem

`CPUProfiler` at
`/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CPUProfiler.java:130`
uses `bpf_get_stackid` for both kernel and user stacks. That helper walks
frame pointers only. Modern Linux binaries (glibc, Go, Rust with PGO, most
JIT'd code) omit frame pointers, so user stacks are empty or truncated. For
JIT'd Java code the sampler prints `libjvm.so+0xNNN` — a Java-first framework
should be able to render Java method names in its own profiler.

The OTel eBPF profiler solves this with (a) a `.eh_frame`-based unwinder that
runs inside eBPF using per-executable stack-delta tables, (b) a HotSpot tracer
that walks the CodeCache to identify JIT'd methods, and (c) an executable-ID
pipeline keyed on `.note.gnu.build-id` that lets symbolization run offline.
Additionally, off-CPU sampling and hotplug-aware perf event opening round the
story out.

This gap is the largest of the five. The design below decomposes it into
independent milestones so partial delivery still gives value.

### Proposed Java-side API

New sampler / profiler classes under
`me.bechberger.ebpf.bpf.profiling/`:

```java
public interface StackUnwinder {
    List<Frame> unwind(int pid, long[] rawIps);
}

public record Frame(String symbol, long fileOffset, String buildId,
                    Language language) {
    public enum Language { NATIVE, JAVA, PYTHON, RUBY, PHP, DOTNET, V8, PERL, BEAM, GO }
}

public class DwarfNativeUnwinder implements StackUnwinder { ... }
public class HotSpotUnwinder implements StackUnwinder { ... }
public class CompositeUnwinder implements StackUnwinder { ... }   // chain

public class BuildIdResolver {
    public String buildIdFor(int pid, long ip);
    public Path localSymbolFor(String buildId);
    public interface RemoteSource {
        Optional<byte[]> fetch(String buildId);
    }
    public void addSource(RemoteSource src);
}
```

New attach helper on `BPFProgram` that abstracts the CPU-hotplug lifecycle
(also serving Gap 5):

```java
public class PerfEventAttachment implements AutoCloseable {
    public void awaitReady();
    public IntStream attachedCpus();
    public void close();
}

public PerfEventAttachment attachPerfEventOnAllCPUs(
    ProgramHandle prog,
    PerfEventSpec spec);

public record PerfEventSpec(PerfType type, long config, long samplePeriod) {}
```

The `CPUProfiler` sample gets rewritten to use `attachPerfEventOnAllCPUs`,
`DwarfNativeUnwinder`, and `HotSpotUnwinder` composed. The existing
`bpf_get_stackid` path stays as a fallback for the "frame pointers only" case.

For the BPF side, the framework ships a set of tail-called unwinder programs
under a new `.o` colocation model:

```
me.bechberger.ebpf.bpf.profiling.unwinder.NativeUnwinder     // eh_frame walker
me.bechberger.ebpf.bpf.profiling.unwinder.HotSpotUnwinder    // JIT CodeCache walker
me.bechberger.ebpf.bpf.profiling.unwinder.Dispatcher         // orchestration
```

`Dispatcher` is a `PROG_ARRAY`-backed dispatcher that inspects the current PID's
recorded language and tail-calls the right unwinder.

### Proposed C-side codegen / template

The unwinder needs a family of maps:

- `BPFHashMap<Integer, ExecutableInfo>` — per-PID mapping to (executable file
  id, base address). Written from userspace after parsing `/proc/pid/maps`.
- `BPFArrayOfMaps<Integer, InnerMap>` — outer keyed on executable file id;
  inner is a `BPFArray` of stack-delta entries derived from `.eh_frame`.
  (Gap: `ARRAY_OF_MAPS` wrapper is missing today — required prerequisite,
  breaks out as its own dependency; call this out under risks.)
- `BPFHashMap<Integer, InterpreterState>` — per-PID HotSpot metadata:
  CodeCache high/low, current thread pointer offset, thread-local slot.
- `BPFStackTraceMap stacks` — reused for the final `(pid, frames[])` output.
- `BPFPROGArray tailCallTable` — indexed by "next unwinder to run": 0 = native
  eh\_frame walker, 1 = HotSpot walker, 2 = symbolizer commit.

The C body of the eh\_frame unwinder is a bounded loop (verifier-friendly: 128
iterations max, tail-call to itself when the budget runs out — this is exactly
what the OTel profiler does).

Because writing the full unwinder in hello-ebpf's Java DSL would stress the
compiler plugin, the design punts on that: **the unwinder programs are shipped
as pre-compiled `.o` files** bundled in the framework jar, loaded via a new
`BPFProgram.loadBuiltin("profiling.unwinder")` factory. Users still write
their own `@BPFFunction` handlers in Java for the *sampler* half; the
*unwinder* half is framework-provided.

### Kernel / libbpf touch points

- Perf event hotplug: subscribe to `/sys/devices/system/cpu/online` via
  inotify, re-run `perf_event_open` when a CPU appears, close the fd when it
  disappears.
- `bpf_map_lookup_elem` for the tail-call PROG\_ARRAY.
- Panama: no new bindings beyond what already exists — the whole thing is
  built on the existing map / attach primitives.
- `.eh_frame` parsing runs in Java userspace using a small ELF parser (or
  by shelling out to `readelf -w` initially, replaced by a Panama binding to
  libunwind's `dwarf_read_encoded_value` in a later milestone).
- `.note.gnu.build-id` parsing is trivial ELF-note reading.

### Fit with existing hello-ebpf machinery

- Reuse `BPFStackTraceMap` from
  `.../bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFStackTraceMap.java`.
- The current `StackSymbolizer.java` at
  `.../bpf-samples/src/main/java/me/bechberger/ebpf/samples/StackSymbolizer.java`
  becomes the "native + build-id" path — extend `readMaps` (line 60) and
  `loadKallsyms` (line 250) to also read `.note.gnu.build-id`.
- `BPFProgram.load(Class)` gains a sibling
  `BPFProgram.loadBuiltin(String moduleName)` that loads a pre-compiled
  `.o` shipped inside the jar. This is a new loader path but a small one.
- `PerfEvent.java` (`.../bpf/perf/PerfEvent.java`) gets a companion
  `PerfEventAttachment` class that wraps the hotplug logic.
- The sample program `CPUProfiler.java` becomes a thin driver over the new
  API — the sampler stays, the collector is rewritten to consume `Frame`
  objects instead of raw IPs.

### Sample program

```java
public class ContinuousProfilerCli {
    public static void main(String[] args) throws Exception {
        var duration = Duration.ofMinutes(5);
        try (var sampler = new SamplerProgram();
             var unwinderModule = BPFProgram.loadBuiltin("profiling.unwinder");
             var attachment = sampler.attachPerfEventOnAllCPUs(
                 sampler.getProgramByName("onSample"),
                 new PerfEventSpec(PerfType.SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, 1_000_000))) {

            StackUnwinder unwinder = new CompositeUnwinder(
                new HotSpotUnwinder(),      // matches libjvm.so mappings
                new DwarfNativeUnwinder(),  // fallback for everything else
                StackUnwinder.framePointers()); // last-resort

            BuildIdResolver resolver = new BuildIdResolver()
                .addSource(BuildIdResolver.debuginfod("https://debuginfod.elfutils.org"));

            var offCpu = new OffCpuTracer(sampler);
            offCpu.start();

            Thread.sleep(duration);

            Report r = new Report(sampler, unwinder, resolver);
            r.writeHtml(Paths.get("flame.html"));
            r.writeOffCpu(Paths.get("off-cpu.html"));
        }
    }
}
```

### Rollout plan

- **M1 — Hotplug-aware `attachPerfEventOnAllCPUs`.** Ships
  `PerfEventAttachment` with inotify on `/sys/devices/system/cpu/online`.
  Rewrites the existing `CPUProfiler` main loop on top of it. Test:
  `chcpu -d 1 && sleep 2 && chcpu -e 1` mid-run; verify no fd leaks and no
  gaps in the sample stream after the reattach.
- **M2 — Build-id keying + `BuildIdResolver`.** Parse `.note.gnu.build-id`
  in `StackSymbolizer`, key the symbol cache on build-id instead of path.
  Add a Debuginfod fetcher. Test: profile a stripped container binary, then
  symbolize offline using a debuginfo package.
- **M3 — Off-CPU sampler.** New sample program: a `sched_switch` tracepoint
  writing `(pid, kstackid, ustackid, delta_ns)` into a per-CPU histogram map;
  Java-side aggregation into an off-CPU flame graph. Depends only on M1 for
  hotplug tolerance.
- **M4 — DWARF native unwinder.** Ship the pre-compiled `.o` +
  `DwarfNativeUnwinder` Java driver + `.eh_frame` parser +
  `ARRAY_OF_MAPS` support (recognise this brings in another gap; scope
  carefully). Test: profile a `-fomit-frame-pointer` Go binary and verify
  stacks reach `main`.
- **M5 — HotSpot unwinder.** Ships `HotSpotUnwinder`, the CodeCache reader
  BPF program, and a small `HotSpotMetadataProvider` that reads the current
  JVM's CodeCache range at startup via jvmci / hsdis or by parsing
  `/proc/self/maps` for `hsperfdata`. Test: attach to a running JVM, produce a
  flame graph with resolved Java method names.
- **M6 — Remote symbolization split.** Wire event capture to write only
  `(build_id, offset)` pairs to a persistent log; write a companion tool that
  symbolizes offline. Prerequisite for OTel profiling-signal compatibility.

M2 is independent of M1. M3 depends on M1. M4 depends on
`ARRAY_OF_MAPS` (call out as a separate mini-gap — approx S). M5 depends on
M4 (uses the same dispatcher). M6 depends on M2.

### Risks and open questions

- The eh\_frame unwinder is a substantial verifier engineering effort. The OTel
  profiler needed multiple iterations to satisfy the verifier bound-checks.
  Recommendation: start by porting OTel's `native_stack_trace.ebpf.c` largely
  verbatim (BSD/Apache-2.0), then re-express in the framework's DSL if
  desired.
- HotSpot's CodeCache layout is not part of the JDK's stable ABI. The design
  needs to pick specific JDK versions to support (21 LTS, 25 LTS?) and gate
  the unwinder with a small kernel-loaded probe that reads a well-known JVM
  field and refuses to attach on mismatch.
- Requires `ARRAY_OF_MAPS` support, which is a separate missing feature. The
  design either takes the dependency or degrades to a single flat delta table
  (worse memory locality but simpler).
- Kernel version floor for tail-calls with maps > 32 entries: 5.10+.
- Off-CPU on `sched_switch` may miss under sched\_ext load (context sees the
  scheduler's kernel task rather than the user task). Interaction with
  hello-ebpf's own scheduler machinery must be verified before shipping M3
  concurrently with a live sched\_ext scheduler.
- Remote symbolization needs a wire format — should the framework take a
  dependency on the OTel profiling proto? Recommendation: yes for M6, but
  keep M1-M4 wire-format-agnostic.

### Effort estimate

- M1: M (1 w)
- M2: S (0.5 w)
- M3: M (1 w)
- M4: L (4 w) — the eh\_frame walker
- M5: L (3 w)
- M6: M (1.5 w)

Total: 11 weeks. If shipping in fewer, M1+M2+M3 is 2.5 weeks and already
covers 60% of the value (hotplug tolerance + build-id + off-CPU).

## Gap 5 — Perf-event-array wrapper + hardware perf counter helpers

### Restated problem

The OTel-awesome catalog §2.6 flags `BPF_MAP_TYPE_PERF_EVENT_ARRAY` as a
missing wrapper. Two categories of use cases need it:

- Pre-ringbuf tracing samples (bcc, most awesome-ebpf tools, OTel Network's
  `events` map) on kernels < 5.8 or where the per-CPU shape is preferable.
- Hardware perf counter readouts from inside a probe via
  `bpf_perf_event_read_value` — the IPC-per-uprobe / cache-miss-per-syscall
  pattern.

hello-ebpf has `PerfEvent.java` for a single event but no map wrapper, no
`bpf_perf_event_output` binding, and no `bpf_perf_event_read_value` binding.

### Proposed Java-side API

New map wrapper:

```java
@BPFMapClass(cTemplate = """
    struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
    } $field SEC(".maps");
    """,
    javaTemplate = "new $class<>($fd, $b1)")
public class BPFPerfEventArray<E> extends BPFMap {

    @FunctionalInterface
    public interface EventCallback<E> {
        void call(int cpu, E event) throws Throwable;
    }

    public void consume(EventCallback<E> cb);          // blocking, single-consumer
    public void consumeAsync(EventCallback<E> cb);     // background thread + epoll
    public void close();

    /** BPF-side: emit an event on the current CPU. */
    @BuiltinBPFFunction(
        "bpf_perf_event_output($arg1, &$this, BPF_F_CURRENT_CPU, $arg2, sizeof(*$arg2))")
    @NotUsableInJava
    public long output(Ptr<?> ctx, Ptr<E> data);

    /** BPF-side: read a hardware counter mapped into this array. */
    @BuiltinBPFFunction(
        "bpf_perf_event_read_value(&$this, $arg1, $arg2, sizeof(*$arg2))")
    @NotUsableInJava
    public long readValue(long index, Ptr<bpf_perf_event_value> buf);
}
```

The reader shape mirrors `BPFRingBuffer` (single-consumer, callback-based),
except events carry a `cpu` argument because the underlying map is per-CPU.

Second, generalise the hotplug-aware attach helper from Gap 4 so that
callers can populate a `BPFPerfEventArray` from a set of hardware perf events
opened across all CPUs:

```java
public class HardwareCounterAttachment implements AutoCloseable {
    public HardwareCounterAttachment(BPFPerfEventArray<?> map, PerfEventSpec spec);
    public void openOnAllCPUs();
    public IntStream attachedCpus();
    public void close();
}
```

Third, new PMU-config constants under
`me.bechberger.ebpf.bpf.perf.PerfCounterKind` (an enum of the well-known
`PERF_COUNT_HW_*` values so users don't need to hand-code them).

### Proposed C-side codegen / template

`bpf_perf_event_output` requires a context pointer (`skb` / `pt_regs` /
`bpf_perf_event_data`) whose type varies by program. The `@BuiltinBPFFunction`
template takes `$arg1` as the context and lowers to
`bpf_perf_event_output(ctx, &map, BPF_F_CURRENT_CPU, &data, sizeof(data))`.
Because this is single-string template substitution, no compiler-plugin change
is needed.

The `bpf_perf_event_read_value` binding is a straight helper call: the caller
passes an `long` index (CPU) and a `Ptr<bpf_perf_event_value>`; the helper
fills `counter`, `enabled`, `running`. The `bpf_perf_event_value` BTF type is
already accessible via `BpfDefinitions.java` (used by
`PerfEvent.readValue`, line 136).

### Kernel / libbpf touch points

- `perf_buffer__new(map_fd, pageCnt, sampleCb, lostCb, ctx, opts)` — the
  userspace reader creates one perf buffer over the whole per-CPU array.
- `perf_buffer__poll(pb, timeout_ms)` — the blocking read loop.
- `perf_buffer__epoll_fd(pb)` — for epoll multiplexing across many.
- Panama additions: three new symbols (`perf_buffer__new`,
  `perf_buffer__poll`, `perf_buffer__free`).
- For the hardware counter path: `perf_event_open` with
  `type = PERF_TYPE_HARDWARE`, `config = PERF_COUNT_HW_INSTRUCTIONS` etc.,
  then `bpf_map_update_elem(map_fd, &cpu, &pfd)`.
- No new kernel version floor: perf event arrays have existed since 3.19.

### Fit with existing hello-ebpf machinery

- Add `BPFPerfEventArray.java` next to `BPFRingBuffer.java` under
  `.../bpf/src/main/java/me/bechberger/ebpf/bpf/map/`.
- Reuse the callback trampoline machinery from `BPFRingBuffer` (there are
  currently two: `EventCallback<E>` and `EventCallbackWOBuffer<E>` starting at
  `BPFRingBuffer.java:78`). The perf-event-array version keeps the same
  shape.
- The hotplug-attachment class shares implementation with Gap 4's
  `PerfEventAttachment` — build it once and use it for both sampling and
  hardware-counter attach.
- Extend `MapTypeId` with `PERF_EVENT_ARRAY` — it's already in the enum, so
  this is a no-op.
- Extend the annotation processor to recognise `BPFPerfEventArray<E>` in a
  field decl (same generic-type-resolution as `BPFRingBuffer<E>`); the
  processor already has a code path for typed maps, so it's a copy-paste.
- The compiler-plugin recognises `output(...)` and `readValue(...)`
  automatically because `@BuiltinBPFFunction` methods are handled generically
  in `Translator.java`.

### Sample program

```java
@BPF(license = "GPL")
public abstract class SyscallIpcSampler extends BPFProgram {

    @Type
    record SyscallSample(int pid, long instructions, long cycles) {}

    @BPFMapDefinition(maxEntries = 0)   // one slot per CPU
    BPFPerfEventArray<SyscallSample> events;

    @BPFMapDefinition(maxEntries = 0)
    BPFPerfEventArray<Void> hwCycles;   // populated userspace-side

    @Kprobe("__x64_sys_openat")
    int enter(Ptr<pt_regs> ctx) {
        long instr;
        long cycles;
        bpf_perf_event_value inst = ...;
        events.readValue(BPFJ.currentCpuId(), Ptr.of(inst));  // hwInstructions map
        instr = inst.counter;
        events.readValue(BPFJ.currentCpuId(), Ptr.of(inst));  // hwCycles map
        cycles = inst.counter;
        SyscallSample s = new SyscallSample(
            (int) bpf_get_current_pid_tgid(), instr, cycles);
        events.output(ctx, Ptr.of(s));
        return 0;
    }

    public static void main(String[] args) throws Exception {
        try (var p = BPFProgram.load(SyscallIpcSampler.class)) {
            new HardwareCounterAttachment(p.hwCycles,
                new PerfEventSpec(PerfType.HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 0))
                .openOnAllCPUs();
            p.autoAttachPrograms();
            p.events.consume((cpu, s) ->
                System.out.printf("cpu=%d pid=%d IPC=%.2f%n",
                    cpu, s.pid(), (double) s.instructions() / s.cycles()));
        }
    }
}
```

### Rollout plan

- **M1 — `BPFPerfEventArray<E>` wrapper + `bpf_perf_event_output` binding
  + userspace `consume(cb)`.** Ships the map wrapper, the Panama bindings for
  `perf_buffer__new` / `perf_buffer__poll` / `perf_buffer__free`, and a
  single-threaded blocking consumer. Test: two syscalls, `output()` in the
  handler, drain in the consumer, assert equal event counts.
- **M2 — `consumeAsync` + epoll multiplexing.** Multiple perf-event-arrays
  drained by one thread. Test: two maps, one thread, no ordering constraint,
  assert lower CPU than N-thread version.
- **M3 — `HardwareCounterAttachment` + hardware-counter sample.** Ships the
  attachment class and the `SyscallIpcSampler` sample. Depends on the shared
  hotplug helper from Gap 4 M1 (or ship a private copy first, then unify).
- **M4 — `bpf_perf_event_read_value` binding + PerfCounterKind constants.**
  Split the read-value helper so it's available without the array wrapper
  (some samples want the single-event `PerfEvent.readValue` at
  `PerfEvent.java:134` which already exists — this milestone just makes it
  consistent with the new API and adds `PERF_COUNT_HW_*` constants).
- **M5 — Kernel-version fallback in `BPFEvents` composer.** Auto-select
  `BPFRingBuffer` on 5.8+ and `BPFPerfEventArray` on older kernels for
  library-level event streams. Test: run on a 5.4 (RHEL 8) VM via vng and
  verify graceful degradation.

M2 depends on M1. M3 depends on M1 and (ideally) shares
`PerfEventAttachment` with Gap 4 M1. M4 is a small independent add. M5
depends on M1.

### Risks and open questions

- The `bpf_perf_event_output` helper's context type varies by program (skb vs
  pt\_regs vs perf\_event\_data). The generic `Ptr<?>` in the helper signature
  keeps the compiler-plugin happy but weakens type checking; consider
  overloading per context type once samples surface real friction.
- The perf ring buffer's per-CPU size defaults are historically small
  (16 pages); the wrapper should expose a `pages` parameter matching what
  `perf_buffer__new` takes.
- `bpf_perf_event_read_value` returns `-ENOENT` if the slot is empty; the
  wrapper must surface this rather than silently returning zero.
- Hotplug during hardware-counter sampling: opening perf events for
  `PERF_TYPE_HARDWARE` on a CPU that goes offline mid-run is exactly the
  reason Gap 4's `PerfEventAttachment` exists. Coordinate M3 with Gap 4 M1.
- Should the design also cover the `SEC("perf_event") + array + read_value`
  three-way pattern used for on-CPU sampling with hardware events? That's the
  natural extension but potentially overlaps Gap 4. Recommendation: keep the
  three-way pattern for a dedicated sample under Gap 4 M5.

### Effort estimate

- M1: M (1.5 w)
- M2: S (0.5 w)
- M3: M (1 w) — assumes Gap 4 M1's helper is shared
- M4: S (0.5 w)
- M5: S (0.5 w)

Total: 4 weeks.

## Cross-cutting recommendations

### Shared infrastructure to build once

Three pieces of framework code recur across all five designs and should be
factored out before any of the milestones lands:

- **A `TypedLinkWithCookie` helper on `BPFProgram`.** Every new attach path
  (kprobe.multi, uprobe.multi, sk\_msg via netns fd, iter via cgroup fd)
  needs to fill a small opts struct with `sz`, some kind of target fd or
  pattern, and an optional cookie. Today the layout of
  `UPROBE_OPTS_LAYOUT` at `BPFProgram.java:670` is hand-crafted, and Gap 2 M1
  will add three more such layouts. A single generic `AttachOptsBuilder`
  that takes a `Map<String, Object>` and materialises the struct via
  Panama would remove ~150 lines of repetition and centralise the cookie fix.
- **A `PerfEventAttachment` lifecycle class.** Both Gap 4 and Gap 5 need
  "open perf event on every CPU, react to hotplug, own the fds, close them
  cleanly". Build it once next to `PerfEvent.java`.
- **A `BPFBuiltinObjectLoader` for pre-compiled framework `.o` files.**
  Gap 4's unwinder programs and (later) Gap 3's iterator helpers benefit
  from being distributed as pre-compiled artifacts inside the framework jar.
  This is a small addition to `BPFProgram.load` and unblocks any future
  "framework-shipped BPF program" (aya-log-style structured logging is the
  natural third client).

### Priority order — if only 2 of 5 ship next release

**Ship Gap 2 (kprobe.multi + cookies) and Gap 5 (perf-event-array + HW
counters).** Rationale:

- Gap 2 has the highest ROI-to-effort ratio: 3.5 weeks total, closes an
  existing regression (hardcoded cookie), and unlocks bpftrace-scale tracing
  from Java. Every serious tracing user hits this the moment they try to
  shadow a syscall family.
- Gap 5 is the second-cheapest (4 weeks) and unblocks two large categories:
  older-kernel compatibility (RHEL 8 / 5.4-era kernels) and IPC / cache-miss
  probes that no other Java tool can do. It also delivers the shared
  `PerfEventAttachment` helper that Gap 4 depends on.

Gap 4 is the most valuable long-term ("Java framework can profile Java")
but at 11 weeks it does not fit a single release cycle; splitting off M1-M3
(2.5 w) as a "profiling polish" mini-release before the full unwinder lands
is the pragmatic play.

Gap 1 (socket plane) and Gap 3 (iterators) both take ~5 weeks and are
lower-priority than Gap 2/5 because they are net-new capabilities rather
than fixes to existing shortcomings — deferring them one release cycle is
acceptable.

### Second-tier gaps not covered here

Ranked by "next most valuable" among the two catalogs:

- **USDT probes for the JVM (`hotspot:method__entry`, `hs:gc__begin`, ...)**
  — a killer JFR-complementary feature, medium effort, well-supported by
  libbpf's `bpf_program__attach_usdt`.
- **AF\_XDP + XSKMAP for line-rate userspace networking** — the DPDK-for-Java
  play; large effort but very high strategic value.
- **`.eh_frame` unwinder standalone (Gap 4 M4)** — even without HotSpot, a
  frame-pointer-less native unwinder is enough to profile Go, Rust, and
  modern C++ correctly.
- **Batch map operations (`BPF_MAP_LOOKUP_BATCH`)** — 5-10x speedup for
  scheduler-stat drains, JFR aggregations, and any histogram flush. Small
  effort, wide reach.
- **TCX + netfilter attach paths** — modern replacements for TC clsact and
  the netfilter integration story respectively; both are becoming table
  stakes for network-observability frameworks.
