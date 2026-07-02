# Cilium/ebpf deep-read: loader-level gaps below the README

Source: /tmp/ebpf-research/cilium-ebpf at commit `5621ed9` ("ci: reduce likelihood of 0ns bpf runtime stats on arm64").

Purpose: enumerate loader-level features cilium/ebpf exposes as user-facing API but that hello-ebpf's Java surface hides, forgets, or does not implement. hello-ebpf uses libbpf via Panama so many low-level knobs are handled, but a lot is still user-visible surface that Java callers never get.

---

## 1. Feature-probe API — the single most-missing thing

`features/` is a first-class package with three orthogonal probes: program type, program type × helper, map type, and miscellaneous kernel-capability probes. Each probe is memoised (`internal.NewFeatureCache`), returns `nil` / `ebpf.ErrNotSupported`, and is derived by actually trying to load a minimal program or create a minimal map.

Enumerated probe surface (verified files):

- `features/prog.go:20` — `HaveProgramType(ebpf.ProgramType) error`. Matrix at :50 covers every program type from SocketFilter → Netfilter, with custom `Fn` for types that need `AttachType`/`License`/`AttachTo` (CGroupSockAddr, CGroupSockopt, Tracing, StructOps, Extension, LSM, SkLookup, Syscall, Netfilter).
- `features/prog.go:236` — `HaveProgramHelper(pt, asm.BuiltinFunc) error`. Verifier-log-based probe (`invalid func #N` vs `program of this type cannot use helper #N`, :286-308) — extraordinary trick: use the verifier's error to distinguish "helper unknown" from "helper wrong-typed".
- `features/map.go:18` — `HaveMapType(ebpf.MapType) error`. Special-cases for cgroup-storage, storage (BTF-required), and map-in-map (probeNestedMap :55).
- `features/misc.go` — `HaveLargeInstructions()` (>4096 insns, 5.2+), `HaveBoundedLoops()` (5.3+), `HaveV2ISA()` (4.14), `HaveV3ISA()` (5.1), `HaveV4ISA()` (6.6).
- `features/link.go` — `HaveBPFLinkUprobeMulti()`, `HaveBPFLinkKprobeMulti()`, `HaveBPFLinkKprobeSession()`.

Cilium usage:
```go
if err := features.HaveProgramType(ebpf.LSM); err != nil { /* fallback */ }
if err := features.HaveProgramHelper(ebpf.Kprobe, asm.FnGetCurrentTask); ...
```

Java sketch:
```java
Features.hasProgramType(BPFProgramType.LSM);       // throws or returns Optional/enum
Features.hasHelper(BPFProgramType.KPROBE, BPFHelper.BPF_FUNC_get_current_task);
Features.hasKprobeMulti();
Features.hasIsaV3();
```

The probe-by-loading pattern would need a rescue path so probe failures do not leak fds; hello-ebpf already loads dummy progs in tests so the plumbing is 90% there. **Refines** research-gap-catalog-rust-go.md §"Feature-detection API".

## 2. Batch map operations

`map.go:1245` `BatchLookup(cursor *MapBatchCursor, keysOut, valuesOut any, opts *BatchOptions) (int, error)`, `:1269` `BatchLookupAndDelete`, `:1394` `BatchUpdate`, plus batch-delete. Cursor is opaque bytes (:1277-1281) — first call passes `cursor.opaque == nil`, subsequent calls reuse. Chunked pagination: kernel returns `ENOSPC` when a hash bucket exceeds the batch, `ENOENT` when done, both surfaced by the wrapper. Per-CPU maps go through a separate path (`batchLookupPerCPU`, :1312) that unmarshals `nr_cpus * value_size` per key.

Usage sketch:
```go
cursor := &ebpf.MapBatchCursor{}
keys := make([]uint32, 256)
vals := make([]uint64, 256)
for {
    n, err := m.BatchLookup(cursor, keys, vals, nil)
    process(keys[:n], vals[:n])
    if errors.Is(err, ebpf.ErrKeyNotExist) { break }
}
```

Java: `int BPFMap.batchLookup(BatchCursor cur, K[] keysOut, V[] valuesOut, BatchOptions opts)`. Effort is small (single syscall via existing Panama; per-CPU only matters if hello-ebpf grows `PerCPU*` accessors). **Refines** research-gap-catalog-rust-go.md §"Batch map operations" — the deep detail is the opaque cursor + ENOSPC/ENOENT contract, which callers must observe or silently miss entries.

Also on `Map`: `Freeze()` (`map.go:1604`), `Memory()` for BPF_F_MMAPABLE maps (`:475`), `AvailableBytes` and mmapped `.data/.rodata` accessed as a `*Memory` region — hello-ebpf's `GlobalVariable<T>` reads/writes through libbpf's cached view rather than the mmap the kernel exposes, which is fine, but there is no `freeze()` and no way to lock a map after init.

## 3. Per-CPU perf event array reader (Reader + Record)

`perf/reader.go:139` — `Reader` wraps `PerfEventArray` fd + per-CPU `perfEventRing`s + a single `epoll.Poller` (`:140`). Options at `:165`:

```go
type ReaderOptions struct {
    WakeupEvents int   // wake after N events
    Watermark    int   // wake after N bytes
    Overwritable bool  // overwrite-mode ring
}
type Record struct {
    CPU         int
    RawSample   []byte
    LostSamples uint64
    Remaining   int
}
```

Public API: `NewReader(m, perCPUBuffer)`, `NewReaderWithOptions`, `Read()`/`ReadInto(*Record)`, `SetDeadline(t time.Time)` (`:305`), `Pause`/`Resume` (`:409`/`:431`, protected by `pauseMu`), `Flush()` (`:461`), `BufferSize()`. Loss reporting piggybacks on `PERF_RECORD_LOST`, decoded at `:92`.

Contrast with hello-ebpf: `BPFRingBuffer` is a ring-buffer reader; there is no `BPFPerfEventArray` reader at all. Perf-event-array is still the go-to for older kernels (5.7 predates ring buffers being ubiquitous) and for correlating per-CPU output. **Refines** research-gap-catalog-rust-go.md §"PerfEventArray reader".

Non-obvious deltas beyond just "add a reader":

- Multi-map coordination via one `epoll` fd — Reader owns N per-CPU fds and epolls them together.
- `Pause`/`Resume` at the perf-event ioctl level (PERF_EVENT_IOC_DISABLE/ENABLE) — hello-ebpf has no equivalent for ring buffer either.
- `SetDeadline` returns `os.ErrDeadlineExceeded` — Java `pollDeadline(Duration)` would be the natural equivalent.
- Overwritable mode surfaces negative `Record.Remaining`.

## 4. Ring buffer reader — deltas

`ringbuf/reader.go:82` — smaller API than perf, but note:

- `SetDeadline(t time.Time)` (`:101`) — hello-ebpf's ring buffer only exposes a blocking `poll`. Cilium's default is blocking-with-deadline; timeout returns `os.ErrDeadlineExceeded`.
- `Read()` vs `ReadInto(*Record)` (`:115` / `:123`) — the latter reuses `Record.RawSample`, critical for high-rate consumers. hello-ebpf allocates per callback.
- `AvailableBytes()` (`:174`) — producer-lag monitoring, kernel exposes it in map info.
- `Flush()` (`:168`) — pairs with `BPF_RB_NO_WAKEUP` producers.
- Behind the scenes there is a `RawReader` (`ringbuf/raw_reader.go`) that surfaces `Lease` / `ReadSample`/`Commit` primitives for callers who want zero-copy. Java would want a `Slice`-based callback that must not escape.
- Multi-map coordination: cilium doesn't multiplex ring buffers by default — each `Reader` owns one map — but the `poller` interface (`:22`) is pluggable so users can build an epoll set. **Refines** research-gap-catalog-rust-go.md §"Ring buffer / perf-buffer epoll multiplexing".

## 5. Link update / info / pin — the second-class link ops

`link/link.go` defines a `Link` interface (`:21`) with these obligations that hello-ebpf's Java `Link` type does not surface:

- `Update(*ebpf.Program)` (`:187`) and `UpdateArgs(RawLinkUpdateOptions{New, Old, Flags})` (`:201`) — wraps `BPF_LINK_UPDATE`. Load-bearing for **freplace** (swap in a new function-replacement program without detach/re-attach), for **cgroup mprog atomic swap**, and for **tcx anchor replace**. hello-ebpf cannot swap a live program.
- `Info() (*Info, error)` (`:249`) — wraps `BPF_OBJ_GET_INFO_BY_FD` on the link fd, plus link-type-specific extras (`TCXInfo.Ifindex/AttachType` at `tcx.go:80`; iter link's `TargetName` at `iter.go:74`; perf-event link's `PerfEvent()` file at `perf_event.go:121`).
- `NewFromFD(fd int)` (`:61`) and `NewFromID(id ID)` (`:73`) — **adoption**: pick up a link created by another process (e.g. loaded by a persisted pinned link).
- `LoadPinnedLink(fileName, opts)` (`:86`) — polymorphic reopen from bpffs, returning the correct concrete type via `sys.ObjGetTyped`.
- `Iterator` (`:265`) — walk `BPF_LINK_GET_NEXT_ID`, materialise `Link` per id. This is how you enumerate every attached BPF program on the system.
- `QueryPrograms(QueryOptions{Target, Attach, QueryFlags})` (`link/query.go:64`) — wraps `BPF_PROG_QUERY` for cgroup/tcx/netkit. Returns `AttachedProgram{ID, linkID}`, so callers can discover what's currently attached to a cgroup or netdev, including revision counters for mprog.

Effort in Java: expose `Link.update(BPFProgram newProg)`, `Link.info()`, static `Link.fromId(int)`, `Link.walk()`. Especially `LINK_UPDATE` is the missing piece for freplace and for the `mprog` ordering story (see anchors below). **Refines** rust-go catalog §"freplace / Extension" and §"tcx/netkit" — the deep detail is that ordering + update + anchor are three separate API pieces, not one.

Related: `link/anchor.go` — cilium exposes `Anchor` (`:22`) with helpers `Head()`, `Tail()`, `BeforeLink/AfterLink`, `BeforeProgram/AfterProgram`, `ReplaceProgram(target)`, and `-ByID` variants. This is the **tcx/cgroup/netkit mprog ordering** API surface. hello-ebpf has no anchor concept; even if it added tcx attach it would default to `append` semantics without callers being able to insert or replace at a position.

## 6. Program loading knobs

`prog.go:70` `ProgramOptions` and `:110` `ProgramSpec` expose knobs hello-ebpf hides behind libbpf's `bpf_object__load`:

- `ProgramOptions.LogLevel` (`:86`) — bitmap `LogLevelBranch | LogLevelStats`. hello-ebpf's `VerifierLogCapture` only distinguishes "capture or not"; there is no way to request `LogLevelStats` for benchmarking verifier throughput.
- `ProgramOptions.LogSizeStart` + auto-grow-on-truncate (`:88` and `retryLogAttrs` at `:573`, up to `maxVerifierAttempts=30` doubling passes with `maxVerifierLogSize = math.MaxUint32 >> 2`). If a program's verifier log is truncated in hello-ebpf, you get whatever libbpf returned; there is no retry-with-bigger-buffer.
- `ProgramOptions.LogDisabled` (`:94`) — explicit "don't allocate any log buffer".
- `ProgramOptions.KernelTypes` (`:101`) — override kernel BTF for containers or minimal-kernel-BTF scenarios. **Refines** rust-go catalog §"BTF split, kernel module BTF".
- `ProgramOptions.ExtraRelocationTargets` (`:106`) — additional `*btf.Spec` slice for **module BTF** so CO-RE can relocate against symbols only present in a loaded kernel module (e.g. nf_tables, kvm). hello-ebpf's libbpf integration handles vmlinux BTF but there is no user-facing knob to add module BTFs before verification.
- `ProgramSpec.Ifindex` (`:124`) — offloaded programs (nfp XDP). Vestigial but real API.
- `ProgramSpec.AttachType` (`:130`) + `AttachTo` (`:134`) + `AttachTarget *Program` (`:137`) — three fields that together drive fentry/fexit/lsm/freplace target resolution. `findProgramTargetInKernel` (`:1179`) walks vmlinux + module BTF caches.

`RunOptions` (`prog.go:828`) is richer than hello-ebpf's PROG_TEST_RUN wrapper: `Data`, `DataOut`, `Context`, `ContextOut`, `Repeat`, `Flags`, `CPU`, `BatchSize` (for XDP live-frame mode: `BPF_F_TEST_XDP_LIVE_FRAMES`), plus `Benchmark(in, repeat, reset)` (:916) that returns `time.Duration` per iteration. hello-ebpf's test-run works only for `SEC("syscall")` and takes no context; **refines** rust-go catalog §"Test-run beyond SEC("syscall")".

## 7. Everything else worth surfacing

1. **`MapInfo.Frozen()`, `Memlock()`, `MapExtra()`, `BTFID()`** (`info.go:214`, `:204`, `:195`, `:185`). Reflection on maps by fd. `ProgramInfo` adds `JitedInsns`, `JitedKsymAddrs`, `JitedLineInfos`, `LineInfos()`, `FuncInfos()`, `Instructions()` (`info.go:671`), `LoadTime`, `VerifiedInstructions`, `Tag`. This is what powers `bpftool prog dump jited` and `bpftool prog show`; a Java `BPFProgram.info()` returning this bag is a foundation for observability tooling.
2. **`Program.Stats()`** (`prog.go:679`) + kernel `bpf_stats_enable` → per-program run count / total ns. **Refines** rust-go catalog §"Program stats".
3. **`Program.BindMap(*Map)`** (`prog.go:1158`) — pin a map's lifetime to a program without referencing it in code. Useful for sidecar maps.
4. **`pin.WalkDir(root, opts)`** (`pin/walk_other.go:21`) — bpffs directory walker yielding typed `Pin{Path, Object io.Closer}`. Enumerate everything a daemon has pinned across restarts. **Refines** rust-go §"Program pinning to bpffs".
5. **Cookies everywhere.** `KprobeOptions.Cookie`, `UprobeOptions.Cookie`, `TracingOptions.Cookie`, `LSMOptions.Cookie` (`kprobe.go:28`, `tracing.go:121`, etc.). Callers read them with `bpf_get_attach_cookie()`. hello-ebpf's `@BPF` attach annotations do not thread a cookie through. **Refines** rust-go §"Attach cookies".
6. **`KprobeOptions.Offset`** (`kprobe.go:32`) — attach a kprobe at symbol+offset (needed for inlined-callsite probing). **`KprobeOptions.RetprobeMaxActive`** (`:39`) — the concurrent-invocation slot count. **`KprobeOptions.TraceFSPrefix`** (`:43`) — control the tracefs event name prefix.
7. **`Executable.Symbol(address)`** (`uprobe.go:239`) + `SymbolOffset` (`:230`) — reverse lookup: given a uprobe fire address, name the function. Powers user-space symbolisation for perf/ring-buffer output.
8. **`Iter.Open() io.ReadCloser`** (`iter.go:84`) — iter programs are triggered by *reading* the file descriptor returned by `BPF_ITER_CREATE`. hello-ebpf lacks iter attach entirely (already flagged) but the shape is important: the user gets an `InputStream` whose bytes are the program's `seq_printf` output.
9. **`Perf events as attach points`** (`perf_event.go:344` `openTracepointPerfEvent`, and the `attachPerfEvent` path at `:281`) — the *raw* `perf_event_open` attach used by uprobe/kprobe/tracepoint under the hood is exposed enough that callers can attach a plain PMU perf counter (cpu-cycles, cache-misses) to a program. The `PerfEvent()` accessor (`:121`) returns the underlying `*os.File` for further ioctls. hello-ebpf has no perf-event-attach type; this is the mechanism for **profile-driven** BPF (sample stack on cpu-cycles PMU overflow).
10. **`Collection.Assign(to any)`** (`collection.go:124`) — reflection-based binding of a struct's tagged fields to programs/maps/variables (`ebpf:"progname"` tag). Java equivalent would need annotation-driven wiring rather than tags; hello-ebpf already generates Java classes so this is already covered by codegen, but the "load an ELF blob at runtime and bind it to a Java record" workflow is not — cilium's `Assign` is what makes their `bpf2go` output usable.

Small extras noted in passing: `MapReplacements` in `CollectionOptions` (`:38`) supports **map sharing between collections** without a pin round-trip; `Cache *btf.Cache` (`:44`) amortises BTF decode across many loads; `MapSpec.Compatible(m)` (`map.go:274`) checks pre-existing pinned maps for schema drift before adoption.

## 8. Per-gap cross-reference

| This doc | Existing catalog entry | Note |
|---|---|---|
| §1 Feature-probe API | rust-go §"Feature-detection API" | Refines: enumerate the exact probe list, expose the verifier-log helper-probe trick. |
| §2 Batch map ops | rust-go §"Batch map operations" | Refines: opaque cursor + `ENOSPC` chunk semantics + per-CPU path. |
| §3 Per-CPU perf reader | rust-go §"PerfEventArray reader" | Refines: `Pause`/`Resume`, `SetDeadline`, `LostSamples`, overwritable-mode. |
| §4 Ring buffer deltas | rust-go §"Ring buffer / perf-buffer epoll multiplexing" | Refines: `SetDeadline`, `ReadInto`, `AvailableBytes`, `Flush`, `RawReader` lease. |
| §5 Link update/info/pin | rust-go §"freplace" and §"tcx / netkit" | New: `LINK_UPDATE` + `Anchor` + `Iterator` + `QueryPrograms`. Not previously called out as their own gap. |
| §6 Program-loading knobs | rust-go §"BTF split, kernel module BTF" (partial) | Refines: `ExtraRelocationTargets`, verifier log auto-grow, `LogLevelStats`. |
| §7.1 MapInfo/ProgInfo reflection | *(new)* | JITed insns/ksyms/line-infos are user-visible via BPF_OBJ_GET_INFO_BY_FD; hello-ebpf has no `.info()` bag. |
| §7.2 Program.Stats | rust-go §"Program stats" | Refines: cilium already ships this; matches the gap. |
| §7.3 BindMap | *(new)* | Small but zero-analogue in hello-ebpf. |
| §7.4 pin.WalkDir | rust-go §"Program pinning to bpffs + skeleton reopen" | Refines: bpffs tree walk with typed reopen. |
| §7.5 Attach cookies | rust-go §"Attach cookies" | Refines: cookies are on every attach type, not just kprobe. |
| §7.6 Kprobe extras | rust-go §"Attach cookies" adjacent | New: `Offset`, `RetprobeMaxActive`, `TraceFSPrefix`. |
| §7.7 Executable.Symbol | *(new)* | User-space symbolisation primitive. |
| §7.8 Iter open() streams | rust-go §"BPF iterator programs" | Refines: the API shape is a `Reader`, not a callback. |
| §7.9 Raw perf-event attach | rust-go doesn't mention profile-attach | New: PMU-driven sampling as first-class attach. |
| §7.10 Collection.Assign | *(new, but partially subsumed by hello-ebpf codegen)* | Reflection binding for external ELF blobs. |

Word count ≈ 1970.
