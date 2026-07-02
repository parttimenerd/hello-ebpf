# libbpf-rs deep-read: skeleton-codegen and query gaps

Source: `/tmp/ebpf-research/libbpf-rs` at commit `92abca649a6a11dcc3329ac27e9439344764d77f`. Cross-refs: `research-gap-catalog-rust-go.md`, `research-cilium-ebpf-deep-dive.md`, `research-aya-deep-dive.md`.

## 1. Skeleton three-phase lifecycle (SkelBuilder to OpenSkel to Skel)

libbpf-rs's generated skeleton exposes three distinct phases via traits (`libbpf-rs/src/skeleton.rs:322-399`):

1. **`SkelBuilder`** (`skeleton.rs:322`): holds an `ObjectBuilder` for pre-open opts (object name, kconfig path, btf_custom_path, kernel_log_level). `open()` calls `bpf_object__open_skeleton`.
2. **`OpenSkel`** (`skeleton.rs:374`): the object is parsed but not yet loaded. This is the mutation window — callers can call `set_type()`, `set_max_entries()`, `set_pin_path()` on any map (`map.rs:181-256`), `set_autoload()`, `set_autoattach()`, `set_attach_target()`, `set_flags()`, `set_ifindex()`, `set_log_level()` on any program (`program.rs:352-421`), and write `.rodata` structs directly. `load()` calls `bpf_object__load_skeleton`.
3. **`Skel`** (`skeleton.rs:389`): loaded object with FD-backed maps and progs. `attach()` walks every SEC and creates links; also returns typed `LinksStruct` with `Option<Link>` per program (generated at `libbpf-cargo/src/gen/mod.rs:714-747`).

**hello-ebpf status:** `BPFProgram.load()` (`BPFProgram.java:150-171`) is *single-phase*: constructor of the generated `*Impl` opens+loads+attaches in one shot; `initGlobals()` runs immediately AFTER load. There is no window to (a) disable a program with `autoload=false`, (b) bump `max_entries` at runtime based on RLIMIT/CPU count, (c) rewrite `.rodata` before the verifier bakes it into instructions (the whole point of rodata as verifier-constants), (d) override attach target by fd for `fentry`/`freplace`, (e) change program type or set ifindex for offload/HW-XDP metadata. All of these are baked at annotation-processor time or unavailable.

**New gap (S+M).** Split `BPFProgram.load()` into `openBuilder().open() -> OpenBPFProgram.load() -> BPFProgram`. `OpenBPFProgram` exposes `programs().<name>().setAutoload(false)`, `maps().<name>().setMaxEntries(n)`, `rodata().<field>().set(v)`. Effort: M — mostly plumbing since libbpf handles all state.

## 2. Typed `.rodata` / `.data` / `.bss` / `.kconfig` access

libbpf-cargo emits a struct per data section by walking `BTF_KIND_DATASEC` and generating one Rust field per `BTF_KIND_VAR` with correct padding (`libbpf-cargo/src/gen/btf.rs:1033-1099`). The section-name-to-type mapping supports custom sections: `.data.<name>`, `.rodata.<name>`, `.bss.<name>` become `data_<name>`, `rodata_<name>`, `bss_<name>` (`gen/mod.rs:253-278`, `InternalMapType` enum). Access is via mmap: at open-time, `map_mmap_ptr(mmap_idx)` casts the mmap slab to `&mut types::rodata` (`gen/mod.rs:496-505`), so writes go through the mmap page that libbpf hands to the kernel as the map's initial value. Example: `runqslower` sets `rodata.min_us = opts.latency` between `open()` and `load()` (`examples/runqslower/src/main.rs:85-94`).

Post-load, `.data` and `.bss` are still mmap-writable; `.rodata` becomes read-only. libbpf-cargo enforces this at compile time by exposing `&types::rodata` (immut ref) after load vs `&mut types::rodata` (mut ref) after open (`gen/mod.rs:401-411`).

**`.kconfig`** is auto-populated by libbpf from `/proc/config.gz` and `/boot/config-$(uname -r)`. The BPF C code declares `extern int LINUX_KERNEL_VERSION __kconfig;` (`examples/capable/src/bpf/capable.bpf.c:11`) and libbpf resolves them at load. libbpf-cargo emits a typed `types::kconfig` struct for read-only access.

**hello-ebpf status:** `GlobalVariable<T>` (`bpf/src/main/java/me/bechberger/ebpf/bpf/GlobalVariable.java:40-190`) covers `.data` only, and uses `bpf_map_lookup_elem`/`bpf_map_update_elem` — NOT mmap. Consequences:
- No `.rodata` support at all (the verifier-constant use case is gone; `runqslower`-style dead-code elimination not achievable).
- `.bss` is silently the same as `.data` because zero-init statics land there.
- `.kconfig` unsupported. Users cannot check `LINUX_KERNEL_VERSION` or `CONFIG_HZ` from C.
- Set/get pay a syscall each; libbpf-rs pays a memory access after the initial mmap.
- Because init runs AFTER `bpf_object__load()`, initial values baked into instructions come from the C source, not Java — defeating half the point.
- The `.data` offset scan uses BTF (`GlobalVariable.java:65-73`) — the same BTF walk libbpf-cargo does — but the codegen output is a name+offset map, not a typed accessor. Callers still write `program.set("count", myVar, 42)` rather than `program.rodata().count().set(42)`.

**New gap (M).** (a) Add `@RodataVariable<T>` / `@KconfigVariable<T>` alongside `GlobalVariable<T>`. (b) Move `.data`/`.bss`/`.rodata` reads/writes to the mmap page via `Map.getMemory()` (which cilium/ebpf already exposes as `*Memory` per `research-cilium-ebpf-deep-dive.md:55`) instead of syscall. (c) Emit typed nested classes on `*Impl.java`: `impl.rodata().minUs.set(500)`, so users get IDE completion. (d) Enforce set-before-load ordering.

Refines: `research-gap-catalog-rust-go.md` section "Skeleton codegen with typed map handles" — that entry mentions typed accessors for maps/progs but does not call out the mmap-backed `.rodata`/`.data`/`.bss`/`.kconfig` split, which is the actual DX win.

## 3. Kernel-BTF-to-Rust type generation (`libbpf-cargo/src/gen/btf.rs`)

libbpf-cargo walks the BPF object's BTF (which usually pulls in `vmlinux.h` transitively) and emits a Rust type per BTF `Struct`/`Union`/`Enum`/`Enum64`/`Datasec` (`btf.rs:695-748`). Notable features:

- **Alignment-aware padding**: `is_struct_packed()` (`btf.rs:136-163`) detects when a struct's declared size is a multiple of its alignment and all non-bitfield members are naturally aligned. `required_padding()` (`btf.rs:172-208`) inserts `__pad_N: [u8; K]` fields to preserve exact layout — critical for CO-RE, since the BPF verifier does field-relative accesses.
- **Bitfields → padding**: bitfields are skipped and covered by padding (`btf.rs:796-802`). Consequence: you cannot read bitfield members from Rust; but the *layout* is correct so CO-RE still works from C.
- **Anonymous structs/unions** get synthetic names `__anon_<N>` with a stable per-object numbering (`btf.rs:34, 443-468`).
- **Enums**: unified `EitherEnum` covers regular and Enum64 (`btf.rs:75-987`).
- **Arrays >32** get manual `impl Default` because Rust's derive-Default caps at 32-length arrays (`btf.rs:782-783`).
- **Datasec** structs (see §2 above) support named-datasec `.data.foo`/`.rodata.bar`.
- **Empty unions** are skipped (Rust rejects them; `btf.rs:770-772, 810-814`).
- The `type_definition` entry point takes a `processed: &mut HashSet<TypeId>` to dedupe when the same BTF type is referenced by multiple maps/globals (`btf.rs:687-748`).

**hello-ebpf status:** `bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/*Definitions.java` (2M+ lines, e.g. `TaskDefinitions`, `SkbDefinitions`, `ZstdDefinitions`) provides pre-generated kernel-BTF bindings. So the KERNEL-side bindings are (mostly) covered by a static dump. Gap already listed in `research-gap-catalog-rust-go.md` under "CO-RE / vmlinux.h autogen at build time" (Effort L). Two libbpf-cargo details worth incorporating when hello-ebpf writes its regen path:

1. **Per-BPF-object BTF, not just vmlinux BTF**: libbpf-cargo runs `gen_skel_types` on each `.bpf.o`'s own BTF, so custom C structs a user's `@BPF` class declares in raw C become typed Java records automatically. hello-ebpf's `@Type` annotation only covers Java-declared structs; a C-side `struct my_event { … };` inside a `#code` block is invisible to Java unless the user manually mirrors it.
2. **Named-datasec `.data.mystate`** support (`gen/mod.rs:270-278`) — hello-ebpf's `GlobalVariable` scan hardcodes ".data" (`GlobalVariable.java:69`) so any `SEC(".data.foo")` variable is invisible.

**Refinement gap (S+M).** After every C-compile, run BTF dedup on the `.bpf.o` and emit `record`-shaped Java bindings for each user-declared C struct into the generated `*Impl.java`, keyed by BTF type name.

## 4. Query API (`libbpf-rs/src/query.rs`, 1289 LOC)

Iterator-style enumeration of every loaded BPF object:

- **`ProgInfoIter`** (`query.rs:196-467`) — walks `BPF_PROG_GET_NEXT_ID`, opens each with `BPF_PROG_GET_FD_BY_ID`, calls `BPF_OBJ_GET_INFO_BY_FD`. Configurable via `ProgInfoQueryOptions` (`:203-291`) to include xlated/JIT insns, map ids, line info, func info, jited ksyms, prog tags, jited func lens, jited line info.
- **`MapInfoIter`** (`:529`) — same shape, returns `MapInfo` (`:471`).
- **`BtfInfoIter`** (`:591-627`) — enumerates every BTF blob (vmlinux + modules + program BTFs).
- **`LinkInfoIter`** (`:1284`) — enumerates every attached link. `LinkInfo` (`:896`) is an enum with a specialised variant per link type: `RawTracepointLinkInfo`, `TracingLinkInfo`, `CgroupLinkInfo`, `IterLinkInfo`, `NetNsLinkInfo`, `NetfilterLinkInfo`, `XdpLinkInfo`, `SockMapLinkInfo`, `NetkitLinkInfo`, `TcxLinkInfo`, `StructOpsLinkInfo`, `KprobeMultiLinkInfo`, `UprobeMultiLinkInfo`, `PerfEventLinkInfo` (each with type-specific fields — e.g. `KprobeMultiLinkInfo` exposes flags+addrs+cookies+missed; `UprobeMultiLinkInfo` exposes path+offsets+cookies+pid). This is far richer than a raw `bpf_link_info` blob.

**hello-ebpf status:** none. This is listed in `research-gap-catalog-rust-go.md` under "Query loaded objects" (Effort M).

**Refinement.** The catalog entry cites libbpf-rs but understates it. The gap should note the **per-link-type typed info**: hello-ebpf's future `BPFQuery.links().stream()` should return `sealed interface LinkInfo permits KprobeMultiLinkInfo, UprobeMultiLinkInfo, TcxLinkInfo, ...` mirroring libbpf-rs's enum. Without that, `bpftool link show`-in-Java degenerates to a numeric attach_type + fd_by_id.

Also new: `ProgInfoQueryOptions` includes `include_xlated_prog_insns` (`:236`), which powers `bpftool prog dump xlated id N` — showing the verifier-rewritten BPF bytecode, useful for debugging why a helper call got inlined or a map-lookup got optimised. hello-ebpf has no such capability.

## 5. BPF streams (bpf_stream_open / bpf_prog_stream_read)

`libbpf-rs/src/streams.rs:1-54` wraps `bpf_prog_stream_read` (`libbpf_sys::bpf_prog_stream_read`). Each program gets two streams: `BPF_STDOUT` (id=1) and `BPF_STDERR` (id=2), exposed on `ProgramMut` as `.stdout()` and `.stderr()` returning `impl Read` (`libbpf-rs/src/program.rs:1699-1706`).

Kernel side: `bpf_stream_open()` + `bpf_stream_printk()` are helpers introduced in **kernel 6.16** for BPF-side character streams — a per-program in-kernel ring the userspace loader drains via a syscall. Unlike `bpf_trace_printk` (global sink, kernel-log spam) and unlike ringbuf (needs per-object map declaration + userspace poll loop), streams are (a) per-program, (b) opt-in from C with no map, (c) buffered without a userspace consumer thread — a caller can pull whenever.

**hello-ebpf status:** none. This is genuinely new; not in any prior deep-read or gap catalog.

**New gap (S).** Emit `.stdout(): InputStream` and `.stderr(): InputStream` methods on `*Impl.java`, backed by a JNI wrapper over `bpf_prog_stream_read`. Requires kernel >= 6.16 (feature-gate via new `Features.hasProgStreams()`). Effort: S — 50-line JNI stub.

Note: this is DISTINCT from the aya-log-style "structured logging" gap (`research-gap-catalog-rust-go.md` §"BPF logging framework"); streams are the kernel-level primitive, aya-log is a higher-level formatter that could be built on top.

## 6. BPF static linker (`libbpf-rs/src/linker.rs`)

Wraps `bpf_linker__new`/`bpf_linker__add_file`/`bpf_linker__add_buf`/`bpf_linker__finalize` (`linker.rs:24-83`). Purpose: combine N `.bpf.o` files into one, deduplicating BTF and rewriting symbol references. Enables:

- **Shared subprogram libraries**: `libcommon.bpf.o` with `static __always_inline u64 rate_limit(struct sock *sk)`, linked into each of `firewall.bpf.o`, `throttle.bpf.o`.
- **BTF dedup across compilation units** — without linker, each `.o` has its own copy of `struct sk_buff`, doubling BTF size.
- **Cross-object global-variable sharing** via `SEC(".data.shared")`.

**hello-ebpf status:** the compiler plugin (`bpf-compiler-plugin/`) emits one C file per `@BPF` class, compiled independently to `.bpf.o`. There is no linker step; each `.bpf.o` is loaded as its own BPF object. Two consequences:

1. **No shared C helpers across `@BPF` classes.** A user who wants a `computeHash()` C function usable from two `@BPF` classes must either (a) duplicate the C source into both classes (`#code` blocks), or (b) drop into a `BuiltinBPFFunction` template. Not fatal, but a real limitation for anyone building a library of `@BPF` classes.
2. **No cross-object map sharing at BPF-static-link time.** Cross-`@BPF` map sharing is instead handled at load-time by `@SharedFrom` (see recent commit `2aec091 fix(processor): @SharedFrom mapName override`), which finds a producer's already-pinned map by name. That's the runtime approach — Cilium/ebpf docs already covered it — but the static-link path is the fastest one, avoiding pin bookkeeping and needing no producer-first ordering.

**New gap (M).** Add a `@BPF(linkWith = {Common.class, Utils.class})` mode that runs `bpf_linker__add_file` on the built `.o`s before load, producing a single-object skeleton. Effort: M — the plugin already knows both `.o` paths; needs a `libbpf::bpf_linker__*` JNI wrapper and a coordinator in `BPFProgram.load()`.

## 7. TC / XDP attach option deltas

Options in libbpf-rs not yet noted in other deep-reads:

- **`TC_CUSTOM` hook** (`tc.rs:16, TC_H_CLSACT`) with custom parent (`tc.rs:122-127`) — allows attaching to a non-clsact qdisc parent (e.g. HTB class). hello-ebpf's TC support (already listed as a gap) should include this option; without it, TCX is the only path but TCX requires kernel >= 6.6.
- **`TcHook::replace(bool)`** (`tc.rs:133-140`) with `BPF_TC_F_REPLACE` — atomic in-place replacement of an existing tc filter. Distinct from XDP's `bpf_xdp_attach` REPLACE flag.
- **`TcHook::query()`** (`tc.rs:169-181`) — read `prog_id` for a hook, letting a Java daemon detect that another process has claimed the qdisc slot.
- **`Xdp::replace(ifindex, old_prog_fd)`** (`xdp.rs:97-109`) — atomic replace-by-fd (uses `XDP_FLAGS_REPLACE`), stronger than replace-by-id since it eliminates the TOCTOU between query and replace.
- **`Xdp::query()` returning full `bpf_xdp_query_opts`** (`xdp.rs:82-86`) — exposes attach mode, feature_flags, hw_prog_id, skb_prog_id, drv_prog_id.

**Refinement of `research-gap-catalog-rust-go.md` §"tcx/netkit/netfilter"**: when implementing, mirror these five methods on `TCHook`/`XDPHook`. In particular the `replace-by-fd` atomicity story matters for HA daemons.

Netfilter (`netfilter.rs:1-68`) exposes `NetfilterOpts { protocol_family, hooknum, priority, flags }` where `flags` includes `BPF_F_NETFILTER_IP_DEFRAG` (`:41-43`) — hello-ebpf's future netfilter attach should surface this flag; without it your netfilter program sees IP fragments individually. That single flag is the main thing to copy verbatim.

## 8. Cross-reference

| §  | Gap | Status vs catalog |
|----|-----|-------------------|
| 1  | Three-phase open/load/attach lifecycle | **New**. Not in rust-go catalog or cilium deep-read. Enables per-map open-time config, autoload toggle, log-level per-program. |
| 2  | Typed `.rodata`/`.data`/`.bss`/`.kconfig` with mmap-backed access | **Refines** rust-go §"Skeleton codegen with typed map handles" and §"Feature-detection API" (adds `.kconfig` auto-injection specifically). New sub-gap: `.rodata` as verifier-constants for dead-code elimination. |
| 3  | Per-`.bpf.o` BTF struct emission (user-declared C structs in Java) + named-datasec | **New** sub-gap. Refines rust-go §"CO-RE / vmlinux.h autogen" which covers only *kernel* BTF. |
| 4  | Query API with typed per-link-type info + xlated bytecode dump | **Refines** rust-go §"Query loaded objects" — that entry doesn't mention typed `KprobeMultiLinkInfo` variants or `include_xlated_prog_insns`. |
| 5  | BPF streams (kernel 6.16, bpf_prog_stream_read) | **New**. Neither in rust-go catalog nor cilium/aya deep-reads. |
| 6  | BPF static linker (multi-object linking) | **New**. Not in rust-go catalog. Relevant given hello-ebpf's one-C-file-per-`@BPF`-class design. |
| 7  | TC/XDP `replace-by-fd`, `TC_CUSTOM`, `query()`, netfilter `IP_DEFRAG` | **Refines** rust-go §"tcx/netkit/netfilter" — those are known gaps; these are the specific option-level details to copy. |

## Summary

The three highest-value new gaps this deep-read surfaces: (1) three-phase lifecycle enabling open-time mutation (unlocks `.rodata` verifier-constants, `set_autoload`, `set_max_entries`, `set_attach_target`); (2) full-shape typed rodata/data/bss/kconfig struct emission with mmap-backed I/O — bigger than "typed map handles" alone; (3) BPF streams (kernel 6.16) — a small but genuinely absent primitive. Static linker (§6) is a lower-priority but nontrivial ergonomics gap for anyone building a library of `@BPF` classes.
