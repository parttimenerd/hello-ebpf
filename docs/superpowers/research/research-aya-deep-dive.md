# Aya deep-read: gaps hidden below the README

Source: `/tmp/ebpf-research/aya` at commit `773ca715385b97eb0c26a581b53246c0c4306959` (`git -C /tmp/ebpf-research/aya rev-parse HEAD`).
Baseline: [research-gap-catalog-rust-go.md](research-gap-catalog-rust-go.md) and [research-gap-catalog-otel-awesome.md](research-gap-catalog-otel-awesome.md). Gaps already flagged there (program/map types, iterators, cookies, feature-detection, batch ops, aya-log at a high level, USDT, etc.) are NOT re-listed. This file only records gaps only visible when reading source.

## 1. New gaps surfaced (not in prior catalog)

### Gap 1: `perf_event_open` wrapper with full PMU / HW / SW / Breakpoint / Raw / Cache / Tracepoint configuration

- **Aya location:** `aya/src/programs/perf_event.rs:22-475`. See `PerfEventConfig` (Hardware / Software / TracePoint / HwCache / Raw / Breakpoint / Pmu) at lines 25-75; `SamplePolicy` (Period vs Frequency) at 346-352; `PerfEventScope` (CallingProcess / OneProcess / AllProcessesOneCpu, each with optional CPU) at 366-384; `attach(config, scope, sample_policy, inherit)` at 450-475.
- **What it is:** Aya opens the perf fd for the caller. The user picks a PMU / hardware counter / software event / kernel tracepoint / hardware breakpoint / dynamic PMU (`/sys/bus/event_source/devices/*/type`), chooses `Period` vs `Frequency`, chooses per-CPU vs per-PID scope, and toggles `inherit` for forked children.
- **hello-ebpf equivalent:** `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java:1121` — `attachPerfEvent(ProgramHandle, int pfd)`. Takes a pre-opened `perf_event_open(2)` file descriptor; the user has to call the syscall themselves with FFM, meaning users need to hand-roll `perf_event_attr` layout. No high-level configuration API exists.
- **Why it matters:** Every `SEC("perf_event")` sample (CPU cycles profiling, cache-miss profiling, per-CPU hardware breakpoint tracing) hits this gap. Even the CPU-clock profiler sample requires ~100 lines of `perf_event_attr` layout to write today.
- **Effort estimate:** M. `perf_event_attr` is stable, and the enum shapes are already there in `runtime` bindings — a `PerfEventConfig` sealed interface + `SamplePolicy` + `PerfEventScope` on top of a `perf_event_open(2)` FFM call would be under a day.
- **Snippet (aya):**
```rust
// aya/src/programs/perf_event.rs:450
pub fn attach(
    &mut self,
    config: PerfEventConfig,
    scope: PerfEventScope,
    sample_policy: SamplePolicy,
    inherit: bool,
) -> Result<PerfEventLinkId, ProgramError> {
    let perf_fd = perf_event_open(
        config, scope, sample_policy,
        WakeupPolicy::Events(1), inherit, 0,
    )?;
    let link = perf_attach(prog_fd, perf_fd, None /* cookie */)?;
    self.data.links.insert(PerfEventLink::new(link))
}
```

### Gap 2: uprobe attach with symbol resolution, `AbsoluteOffset`, and `SymbolOffset`

- **Aya location:** `aya/src/programs/uprobe.rs:53-160` (`UProbeAttachLocation::{Symbol,SymbolOffset,AbsoluteOffset}` + `from_virtual_address(instruction_address, section_address, section_offset)`), `:315-347` (`resolve_attach_target_basename` walks `/proc/<pid>/maps` and falls back to `/etc/ld.so.cache`), `:229-281` (`attach(point, target, scope)`).
- **What it is:** Aya lets a user attach a uprobe by (a) symbol name, (b) symbol + byte offset inside the function, (c) absolute file offset, or (d) an ELF virtual address that Aya translates to a file offset. `libc` is resolved via `ld.so.cache` and `/proc/<pid>/maps`, so `attach("malloc", "libc", ...)` works without the caller finding the .so path.
- **hello-ebpf equivalent:** `BPFProgram.attachUprobe(prog, retprobe, pid, binaryPath, funcName)` at `BPFProgram.java:705,741,754`. Requires an absolute binary path — no `libc` shortcut, no offset-into-function, no VA translation. Delegates entirely to libbpf `bpf_program__attach_uprobe_opts`, which needs the caller to know the symbol offset already.
- **Why it matters:** SSL/TLS interception needs `SSL_write+N` (mid-function offset), and generic userspace tracers frequently target absolute offsets from DWARF resolution. Neither is expressible today.
- **Effort estimate:** M. `/proc/<pid>/maps` and `/etc/ld.so.cache` parsers are the bulk of the work; symbol resolution can reuse `elf` from the JDK or a small helper.
- **Snippet (aya):**
```rust
// aya/src/programs/uprobe.rs:54
pub enum UProbeAttachLocation<'a> {
    Symbol(&'a str),
    SymbolOffset(&'a str, u64),
    AbsoluteOffset(u64),
}

impl UProbeAttachLocation<'static> {
    pub fn from_virtual_address(
        instruction_address: u64,
        section_address: u64,
        section_offset: u64,
    ) -> Result<Self, UProbeAttachLocationError> { /* … */ }
}
```

### Gap 3: `LoadOptions` / global-variable override, per-map `max_entries` override, per-map pin path override

- **Aya location:** `aya/src/bpf.rs:118-383`. Builder API: `.override_global(name, &value, must_exist)` (272-278), `.map_max_entries(name, u32)` (307-310), `.map_pin_path(name, path)` (340-343), `.default_map_pin_directory(path)` (239-242), `.extension(name)` (362-365), `.allow_unsupported_maps()` (215-218), `.verifier_log_level(level)` (380-383).
- **What it is:** Before any map or program is loaded, users can (a) patch `.rodata`/`.data` symbols so the eBPF C sees compile-time constants baked in at load time (`static volatile const struct { … } cfg;`), (b) resize maps declared with `max_entries=0` at compile time based on runtime nr_cpus, (c) point specific maps at pre-existing bpffs pins for cross-process map sharing.
- **hello-ebpf equivalent:** Nothing. `BPFProgram.load()` reads a bundled ELF and calls libbpf. There is no ergonomic way to patch a `volatile const int NUM_CPUS` before load, and map `max_entries` is fixed by the `@BPFMapDefinition` annotation (an annotation-processor-time constant), forcing a rebuild to change map sizes.
- **Why it matters:** Every real profiler / observability tool needs runtime map sizing (`max_entries = nr_cpus * 4096`). Global rodata patching is the standard "config knob" mechanism in libbpf-based Go/Rust tools; without it, users hard-code values or add a HASH map with a single entry.
- **Effort estimate:** L. Requires modifying the BTF/ELF before it hits libbpf, or exposing `bpf_map__set_max_entries` / `bpf_object__set_kversion` / `.rodata` patching via FFM. The annotation processor already parses `@BPFMapDefinition`, so wiring `.maxEntries(name, N)` builder-side is feasible.
- **Snippet (aya):**
```rust
// aya/src/bpf.rs:263
let bpf = EbpfLoader::new()
    .override_global("VERSION", &2u32, true)
    .override_global("PIDS", &[1234u16, 5678], true)
    .map_max_entries("events", nr_cpus * 4)
    .map_pin_path("shared_state", "/sys/fs/bpf/foo/state")
    .load_file("file.o")?;
```

### Gap 4: `ProgramInfo` / `MapInfo` / `LinkInfo` — `BPF_OBJ_GET_INFO_BY_FD` surface

- **Aya location:** `aya/src/programs/info.rs:34-236` (ProgramInfo: `id`, `tag`, `size_jitted`, `size_translated`, `loaded_at`, `created_by_uid`, `map_ids`, `name`, `gpl_compatible`, `btf_id`, `run_time`, `run_count`, `verified_instruction_count`, `memory_locked`, `fd`, `from_pin`); `aya/src/maps/info.rs:27-129` (MapInfo: `map_type`, `id`, `key_size`, `value_size`, `max_entries`, `map_flags`, `name`, `fd`, `from_pin`); `aya/src/programs/links.rs:114-140` (LinkInfo: `id`, `program_id`, `link_type`). Plus `loaded_programs()`, `loaded_maps()`, `loaded_links()` iterators (`info.rs:287-298`, `maps/info.rs:157-162`, `programs/mod.rs:1602`).
- **What it is:** Aya wraps `BPF_OBJ_GET_INFO_BY_FD` for all three object kinds and exposes iterators over every loaded prog/map/link in the kernel. `size_translated`, `verified_instruction_count`, `run_time_ns`, `run_cnt`, `memory_locked` come from this — the numbers that `bpftool prog show` displays.
- **hello-ebpf equivalent:** Nothing beyond what libbpf returns implicitly. No `listPrograms()`, no `programInfo()`, no `mapInfo()`, no `linkInfo()`. Users cannot introspect an existing pinned program from Java.
- **Why it matters:** Building a `bpftool prog show` equivalent in Java is currently impossible. Any observability workflow that wants to attach to pre-existing programs, verify verifier stats, or diagnose "why is this prog using 4MB of memlock" needs this.
- **Effort estimate:** M. Straight FFM wrappers around `bpf(BPF_OBJ_GET_INFO_BY_FD)`, `BPF_PROG_GET_NEXT_ID`, `BPF_MAP_GET_NEXT_ID`, `BPF_LINK_GET_NEXT_ID`. Similar work to the existing pin/link handling.
- **Snippet (aya):**
```rust
// aya/src/programs/info.rs:177,200,205
pub const fn run_time(&self) -> Duration { Duration::from_nanos(self.0.run_time_ns) }
pub fn verified_instruction_count(&self) -> Option<u32> {
    (self.0.verified_insns > 0).then_some(self.0.verified_insns)
}
pub fn memory_locked(&self) -> Result<u32, ProgramError> {
    get_fdinfo(self.fd()?.as_fd(), "memlock")
}
```

### Gap 5: Extension / `freplace` program type — dynamic function replacement

- **Aya location:** `aya/src/programs/extension.rs:57-201`. `Extension::load(program_fd, func_name)` (79-87) resolves BTF id of `func_name` in the target program, `attach()` (96-121) creates a link that hijacks the target function, and `attach_to_program(other_prog, other_func)` (134-158) atomically re-targets after BTF-signature verification.
- **What it is:** Extension programs replace global functions in already-loaded BPF programs at runtime. Requires BTF on both. This is the mechanism that lets tools like Katran hot-reload a redirect function without dropping traffic.
- **hello-ebpf equivalent:** Nothing. The gap catalog acknowledges "freplace/Extension known missing" but doesn't record the concrete API shape (BTF-id lookup, `attach_to_program` for hot-swap).
- **Why it matters:** Any Java-based traffic-shaping / policy engine on XDP wants zero-downtime replacement of a policy function. Also: this is the only way to instrument another BPF program's internals — you can attach an Extension to log arguments and pass through.
- **Effort estimate:** M–L. BTF lookup is already available in hello-ebpf (`BTFParser`); the missing pieces are `bpf(BPF_PROG_LOAD)` with `attach_btf_id`, `attach_prog_fd`, and `bpf_link_create` with `BPF_LINK_TYPE_TRACING` + target BTF id.
- **Snippet (aya):**
```rust
// aya/src/programs/extension.rs:79
pub fn load(&mut self, program: ProgramFd, func_name: &str) -> Result<(), ProgramError> {
    let (btf_fd, btf_id) = get_btf_info(program.as_fd(), func_name)?;
    data.attach_btf_obj_fd = Some(btf_fd);
    data.attach_prog_fd = Some(program);
    data.attach_btf_id = Some(btf_id);
    load_program_without_attach_type(BPF_PROG_TYPE_EXT, data)
}
```

### Gap 6: XDP mode selection (Skb / Driver / Hardware) and `XDP_FLAGS_REPLACE` atomic swap

- **Aya location:** `aya/src/programs/xdp.rs:41-63` (`XdpMode::{Default,Skb,Driver,Hardware}` with `XDP_FLAGS_{SKB,DRV,HW}_MODE`), `:114-174` (`attach(iface, mode)` and `attach_to_if_index`), `:193-240` (`attach_to_link(existing_link)` for atomic prog swap via `bpf_link_update` or netlink `XDP_FLAGS_REPLACE` / `IFLA_XDP_EXPECTED_FD` on kernel ≥ 5.7).
- **What it is:** Users pick between generic-XDP (fallback in the network stack), native driver-XDP (fast path), and hardware-offloaded XDP (SmartNIC). `attach_to_link` implements compare-and-swap replacement so a rolling upgrade never leaves the interface unattached.
- **hello-ebpf equivalent:** `BPFProgram.xdpAttach(prog, ifindex)` at `BPFProgram.java:1187` — hard-codes `XDP_FLAGS_UPDATE_IF_NOEXIST` (no mode flags, defaults to whatever the kernel picks). No mode selector, no atomic replace.
- **Why it matters:** SmartNIC deployments (Netronome/BlueField offload) need `XDP_FLAGS_HW_MODE`. Development on a machine without native-XDP drivers needs `XDP_FLAGS_SKB_MODE`. Blue/green deployments need `attach_to_link` — otherwise there's a window where the NIC has no XDP program.
- **Effort estimate:** S. Add an `XdpMode` enum, wire it into `bpf_xdp_attach`'s `flags`, add `xdpReplace(link, prog)` calling `bpf_link_update`.

### Gap 7: TC attach with priority/handle control, TCX ordering, and `SchedClassifierLink::{priority, handle, classid}` introspection

- **Aya location:** `aya/src/programs/tc.rs:135-192` (`TcAttachOptions::Netlink(NlOptions{ priority, handle, classid })` vs `TcAttachOptions::TcxOrder(LinkOrder)`), `:308-320` (`attach_with_options`), `:448-489` (`query_tcx` to list attached TCX programs), `:601-655` (link introspection: `attached()`, `attach_type()`, `priority()`, `handle()`, `classid()`), `:660-673` (`qdisc_add_clsact`, `qdisc_detach_program`). `programs/links.rs:660-740` (`LinkOrder::{first, last, before_link, after_link, before_program, after_program, before_program_id, after_program_id}` — the mprog multi-attach API).
- **What it is:** Aya exposes both legacy netlink TC and the newer TCX link API with `BPF_F_BEFORE`/`AFTER` / `BPF_F_REPLACE` / `BPF_F_LINK` / `BPF_F_ID` flags to slot a program into a specific ordinal position among other attached programs. Also queries live TCX chain state.
- **hello-ebpf equivalent:** `BPFProgram.tcAttach(prog, ifindex, ingress)` at `BPFProgram.java:1203` — no priority argument (always kernel-assigned), no handle argument, no TCX, no ordering. Detaches the whole clsact qdisc via `tc qdisc del` before attaching, which will nuke other programs sharing the interface.
- **Why it matters:** Multi-tenant hosts (Cilium + a userland TC filter + hello-ebpf) need TCX ordering to coexist. Blowing away clsact on attach is currently a correctness bug.
- **Effort estimate:** M. TCX partially overlaps with existing "tcx known missing" but the specific delta here is `LinkOrder` and the mprog flag family — priority/handle/classid readback and `before_link`/`after_program_id` chaining.
- **Snippet (aya):**
```rust
// aya/src/programs/tc.rs:135
pub enum TcAttachOptions {
    Netlink(NlOptions),  // priority, handle, classid
    TcxOrder(LinkOrder), // BPF_F_BEFORE/AFTER/REPLACE
}
// aya/src/programs/links.rs:694
pub fn before_link<L: MultiProgLink>(link: &L) -> Result<Self, LinkError> {
    Ok(Self { link_ref: LinkRef::Fd(link.fd()?.as_raw_fd()),
              flags: MprogFlags::BEFORE | MprogFlags::LINK })
}
```

### Gap 8: `sleepable` / `xdp.frags` section prefix selection via annotation

- **Aya location:** `aya-ebpf-macros/src/fentry.rs:12-41`, `fexit.rs:12-41`, `lsm.rs:12-41`, `uprobe.rs`, `xdp.rs:26-56`. `#[fentry(sleepable)]` emits `SEC("fentry.s/…")`; `#[lsm(sleepable)]` emits `SEC("lsm.s/…")`; `#[xdp(frags)]` emits `SEC("xdp.frags")`.
- **What it is:** A single boolean attribute switches the ELF section prefix, which the kernel interprets as "this program may sleep (need trampoline-safe helpers)" or "this XDP program handles multi-buffer packets".
- **hello-ebpf equivalent:** `@BPFFunction(section = "…")` accepts an arbitrary literal, so a user *can* write `section = "fentry.s/foo"` today — but there is no annotation flag, no documentation about which sections support which suffixes, and no compiler-plugin validation that `sleepable` requires kernel ≥ 5.10 or that XDP multi-buf requires the driver to support it. Codebase search finds no `sleepable` or `xdp.frags` usage.
- **Why it matters:** Sleepable BPF is required to read files (bpf_d_path), use bpf_copy_from_user, or interact with any helper that grabs a sleepable lock. Multi-buffer XDP is needed for jumbo frames / TSO. Both are currently reachable only by a user who knows the exact libbpf ELF convention.
- **Effort estimate:** S. Add `sleepable=true` boolean to `@BPFFunction` and expand the compiler plugin's SEC generator to translate it. Add `frags=true` for XDP.

### Gap 9: `EbpfLoader::allow_unsupported_maps()` — graceful fallback for maps only used from BPF

- **Aya location:** `aya/src/bpf.rs:196-218`. Programs that declare a map the running kernel doesn't understand (e.g. `BPF_MAP_TYPE_ARENA` on 6.8) normally fail to load. `.allow_unsupported_maps()` marks such maps as "created best-effort, may not be accessible from userspace" so the rest of the program still loads.
- **What it is:** A load-time compatibility knob. Especially useful for programs that build BTF-conditional feature toggles: "if arena is available, use it; otherwise fall back to per-CPU array". Aya lets the same ELF work on both.
- **hello-ebpf equivalent:** Nothing. If the annotation processor emits a map type unsupported on the current kernel, `BPFProgram.load()` will fail with a libbpf error — the user must ship two separate program artifacts.
- **Why it matters:** hello-ebpf ships eBPF as bundled JARs. Making one JAR work on RHEL 8 (5.4) and Ubuntu 24.04 (6.8) needs feature-gated maps, which needs graceful skip-on-unsupported.
- **Effort estimate:** S. Set a flag on `BPFProgram` before calling `bpf_object__load`; wrap each `bpf_map__set_autocreate(map, false)` call for unsupported types.

### Gap 10: aya-log — structured BPF-side logging with format-string DSL

- **Aya location:** `aya-log-common/src/lib.rs:12-389` (wire format: `Level`, `RecordFieldKind`, `ArgumentKind`, `DisplayHint`); `aya-log-parser/src/lib.rs:1-171` (`{}`, `{:x}`, `{:X}`, `{:i}`, `{:mac}`, `{:MAC}`, `{:p}` parser); `aya-log-ebpf-macros/src/expand.rs:1-282` (proc-macro turns `info!(&ctx, "seen {} bytes from {:i}", n, ip)` into serialized args on the BPF side); `aya-log/src/lib.rs:96-1305` (userspace: reads from a `AYA_LOGS` `RingBuf` map, reassembles the record, and dispatches to the standard `log` crate).
- **What it is:** A three-layer system:
  1. `aya-log-parser` parses the Rust format string into a `Vec<Fragment>` at *compile time*.
  2. `aya-log-ebpf-macros` emits BPF-side code that packs `(RecordFieldKind, [type_tag, size, bytes])+` into a ring-buffer entry. Zero libbpf-level `bpf_trace_printk`.
  3. `aya-log` userspace consumes the ring-buffer entries, reconstitutes the format string, and calls `log::Log::log(&Record { ... })`.
  Types the BPF side can log: signed/unsigned ints, `f32`/`f64`, `Ipv4Addr`/`Ipv6Addr`, `[u8; 4/6/16]`, `[u16; 8]`, `&[u8]`, `&str`, `*const T`. Display hints per argument.
- **hello-ebpf equivalent:** `bpf_trace_printk` (via `@BuiltinBPFFunction("bpf_trace_printk(...)")`) or hand-rolled ring-buffer records. No structured framework, no format-string parser, no display hints, no `AYA_LOGS`-equivalent map, no userspace consumer that dispatches to `java.util.logging` or SLF4J.
- **Why it matters:** `bpf_trace_printk` is single-writer, rate-limited, human-only, and doesn't support arg formatting beyond the fixed `%d`/`%s`/`%x` set. Every non-trivial hello-ebpf program either logs to a ring-buffer with a Java-side switch statement (see how the scheduler samples do it — `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java:1018` for the switch dispatch pattern) or reinvents this framework badly.
- **Effort estimate:** L. Full equivalent needs: (a) a format-string parser in the annotation processor, (b) a codegen path emitting ring-buffer writes on the BPF side, (c) a Java-side reader dispatching to `System.Logger`/SLF4J. The `aya-log-common` wire format is stable enough to reuse verbatim, so wire compatibility with existing aya-log tools would even be free. The prior catalog flags this at high level; this deep-read confirms the exact shape (format DSL: `{:i}`/`{:mac}`/`{:x}`, seven display hints, per-arg type tags).
- **Snippet (aya):**
```rust
// aya-log-ebpf-macros/src/expand.rs — BPF side sees:
error!(&ctx, "denied {} -> {:i}:{}", verdict, src_ip, dport);
// aya-log-parser/src/lib.rs:60 — the parser accepts these hints:
":x" => LowerHex, ":X" => UpperHex, ":i" => Ip,
":mac" => LowerMac, ":MAC" => UpperMac, ":p" => Pointer,
// aya-log/src/lib.rs:100 — userspace side reads the RingBuf, decodes,
// dispatches through log::Log. Reads the map named "AYA_LOGS".
```

## 2. Attach-option deltas per program type

| Program type | Aya options (fields) | hello-ebpf equivalent | Missing options |
|---|---|---|---|
| kprobe/kretprobe | `(fn_name, offset, pid?, cookie?)` — `programs/kprobe.rs:79`, `probe.rs:137` | `attachKprobe(name)` — `BPFProgram.java` around :649 | `offset` inside function, `pid` filter, `cookie` (5.15+) |
| uprobe/uretprobe | `UProbeAttachLocation::{Symbol,SymbolOffset,AbsoluteOffset}` + libname resolution + `UProbeScope::{AllProcesses,CallingProcess,OneProcess}` + cookie — `uprobe.rs:53,182,229` | `attachUprobe(prog, retprobe, pid, binaryPath, funcName)` :705 | Bare libname (`"libc"`), symbol+offset, absolute offset, VA translation, cookies |
| xdp | `(iface_or_ifindex, XdpMode)`, `attach_to_link` for atomic swap — `xdp.rs:114,193` | `xdpAttach(prog, ifindex)` :1187, `XDP_FLAGS_UPDATE_IF_NOEXIST` hard-coded | `XdpMode::{Skb,Driver,Hardware}`, atomic replace, `XDP_FLAGS_REPLACE` |
| tc (SchedCLS) | `TcAttachOptions::{Netlink(priority,handle,classid), TcxOrder(LinkOrder)}`; `qdisc_add_clsact`; live query of TCX chain — `tc.rs:135,308,448` | `tcAttach(prog, ifindex, ingress)` :1203; execs `tc qdisc del` shell-out | Priority, handle, classid, TCX ordering, TCX query |
| tracepoint | `attach(category, name)` — `trace_point.rs:78` | Attach by SEC name via libbpf autoattach | (Roughly parity here) |
| perf_event | full `PerfEventConfig` + `SamplePolicy(Period/Frequency)` + `PerfEventScope` + `inherit` — `perf_event.rs:450` | `attachPerfEvent(prog, pfd)` :1121 with caller-supplied fd | Entire event/scope/policy configuration; see Gap 1 |
| cgroup_skb | `attach(cgroup_fd, CgroupSkbAttachType::{Ingress,Egress}, CgroupAttachMode::{Single,AllowOverride,AllowMultiple})` — `cgroup_skb.rs:87` | `cgroupAttachInternal(handle, cgroupName)` :1247, single mode only | `AllowOverride`, `AllowMultiple`, explicit Ingress/Egress selection |
| LSM | `attach()` — `lsm.rs`; also `LsmCgroup` (:1247, `lsm_cgroup.rs`) | Attach by SEC via libbpf | `lsm_cgroup` distinct attach with cgroup target |
| fentry/fexit | attach with sleepable prefix (`SEC("fentry.s/…")`) — `aya-ebpf-macros/src/fentry.rs:41` | Attach by SEC via libbpf; no sleepable flag | See Gap 8 |
| Extension | `load(target_prog, func_name)`, `attach()`, `attach_to_program(other, other_func)` — `extension.rs:79,96,134` | Nothing | See Gap 5 |

## 3. Info APIs (BPF_OBJ_GET_INFO_BY_FD)

See Gap 4. The specific ProgramInfo fields aya exposes and hello-ebpf doesn't (verified by re-reading `aya/src/programs/info.rs:34-236`):
- `id()`, `tag()` (SHA of instructions — stable across load cycles unlike ID), `size_jitted()`, `size_translated()`, `loaded_at()` (SystemTime), `created_by_uid()`, `map_ids()` (which maps this program references), `gpl_compatible()`, `btf_id()`, `run_time()` / `run_count()` (populated when `bpf_stats_enable` is on), `verified_instruction_count()` (5.16+), `memory_locked()` (parsed from `/proc/self/fdinfo/<fd>` memlock line — a non-syscall path aya uses to surface memlock).

MapInfo (aya/src/maps/info.rs:27-129): `map_type`, `key_size`, `value_size`, `max_entries`, `map_flags`, `name`. LinkInfo (aya/src/programs/links.rs:114-140): `id`, `program_id`, `link_type`. All three have `from_pin(path)` constructors and `fd()` accessors. Aya also provides `loaded_programs()`, `loaded_maps()`, `loaded_links()` — iterator wrappers around `BPF_{PROG,MAP,LINK}_GET_NEXT_ID`. None of these exist on hello-ebpf.

## 4. Aya-log — the missing structured-log framework

End-to-end mechanics (from source, not the README):

**Compile time (BPF-side proc macro, `aya-log-ebpf-macros/src/expand.rs:71-282`):**
1. `info!(&ctx, "eof {:x} pid={} ip={:i}", flags, pid, ip)` is intercepted.
2. `aya-log-parser` runs at proc-macro expansion and turns `"eof {:x} pid={} ip={:i}"` into `Vec<Fragment>` (literals + `Parameter { hint }`). Fragments with `hint=DisplayHint::LowerHex/Ip/etc.` correspond to `:x`/`:i` at parse time.
3. The macro emits BPF code that: (a) reserves a ring-buffer entry sized for the header + N argument records, (b) writes `Level`, `Target` (module path), `Module`, `File`, `Line`, `NumArgs` fields in a tag-length-value stream, then (c) for each argument emits `[ArgumentKind::U64|Ipv4Addr|...][size][bytes]` — argument types dispatched via a `Argument` trait sealed to a fixed set (see `aya-log-common/src/lib.rs:113-149`).

**Kernel side:** each `error!/warn!/info!/debug!/trace!` becomes ~40 lines of ring-buffer writes with no `bpf_trace_printk` fallback. The BPF program only knows how to serialize; the format string itself is *not* in the BPF program.

**User space (`aya-log/src/lib.rs:96-1305`):**
1. `EbpfLogger::init(&mut bpf)` looks up a map named `AYA_LOGS` (hard-coded, `MAP_NAME = "AYA_LOGS"` at line 69), takes ownership of it as a `RingBuf`, and polls.
2. For each ring-buffer entry, it decodes the tag-length-value stream, reconstitutes the format string (either statically compiled into the userspace binary from the same source or reconstructed from the target/level/module metadata plus the argument display hints), and calls `log::Log::log(&Record { level, target, module_path, file, line, args })`.
3. `env_logger`, `simplelog`, etc. then output to stderr / files / journald.

**Effort estimate to port to Java:** L (roughly 2-3 weeks). Blockers:
- Format-string parser in the annotation-processor stage (mirror of `aya-log-parser`, ~200 LOC).
- Codegen path in the compiler plugin that emits `bpf_ringbuf_reserve` + writes + `bpf_ringbuf_submit` for each `Log.info(ctx, "fmt", args...)` call.
- Java-side `RingBuf` consumer + `System.Logger`/SLF4J bridge (leverage existing `BPFRingBufferMap` — path: `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFRingBufferMap.java` if present).
- Wire format decision: reuse `aya-log-common` layout for tool interop, or invent a Java-idiomatic one.

## 5. Macro / annotation deltas

What aya-ebpf-macros expresses that hello-ebpf annotations don't (from `aya-ebpf-macros/src/`):
- **`sleepable` attribute** on `fentry`, `fexit`, `lsm`, `uprobe`, `uretprobe` — see Gap 8. Not a section-name literal, a boolean.
- **`frags` attribute** on `xdp` — enables `SEC("xdp.frags")` for multi-buffer packets.
- **`xdp(map = "cpumap"|"devmap")`** — attaches the XDP program to a `BPF_MAP_TYPE_CPUMAP` / `DEVMAP` slot for XDP-redirect (`aya-ebpf-macros/src/xdp.rs:27-55`). Currently hello-ebpf's CPUMAP/DEVMAP wrappers exist but there's no way to associate a specific handler function with a map slot.
- **`sk_msg`, `sk_skb(kind = stream_parser|stream_verdict)`, `sk_reuseport`, `sk_lookup`, `sock_ops`, `socket_filter`, `flow_dissector`** — proc macros exist even for the "program types known missing" gaps. Each emits a distinctive `SEC(...)` prefix that the C-based hello-ebpf compiler plugin would need to teach the annotation processor. The relevant files are one per program type in `aya-ebpf-macros/src/`.
- **`btf_map`** (`aya-ebpf-macros/src/btf_map.rs`) — declares a map through BTF metadata rather than the older `struct bpf_map_def` format. hello-ebpf uses `struct { ... } SEC(".maps")` BTF-style already via its compiler plugin, so this is roughly parity.
- **`btf_tracepoint`** — `SEC("tp_btf/...")` — flagged as known missing in the prior catalog, but the annotation shape here is trivial (single argument, the tracepoint name).

## 6. Everything else worth surfacing

- **`SamplePolicy::Frequency(hz)`** at `aya/src/programs/perf_event.rs:346-352`. Frequency-based sampling auto-adjusts the period to hit a target Hz — the perf profiler idiom. Without it, users manually re-tune period whenever the workload changes.
- **`inherit` flag** on `PerfEvent::attach` at `:455` — automatically samples forked children. Missing means Java-side profiling can't follow `fork()` in the target process.
- **`bpf_stats_enable`** — mentioned at `aya/src/sys/enable_stats.rs` (`Stats::RunTime`). This is what populates `ProgramInfo::run_time()` / `run_count()`. Prior catalog flags at high level; the specific syscall is `BPF_ENABLE_STATS` with type argument. Trivial to expose.
- **`memory_locked()` via `/proc/self/fdinfo/<fd>`** — `aya/src/programs/utils.rs:get_fdinfo`. A non-obvious way to get memlock size that doesn't require `CAP_SYS_ADMIN`.
- **`RawTracePointRunOptions`** at `aya/src/programs/mod.rs:1031-1058` — `BPF_PROG_TEST_RUN` for raw tracepoints supports a `[u64; 12]` ctx_in (up to 12 tracepoint args) and CPU pinning via `BPF_F_TEST_RUN_ON_CPU`. hello-ebpf's PROG_TEST_RUN today (`BPFProgram.java:983`) only exercises `SEC("syscall")` — it doesn't expose test-run for raw tracepoints, xdp, or `TestRunAttrs::xdp_live_frames` (aya at `mod.rs:965`: sets `BPF_F_TEST_XDP_LIVE_FRAMES` for XDP replay at line-rate).
- **`FdLink::pin(path)`** (`aya/src/programs/links.rs:283-297`) + `PinnedLink::from_pin(path)` (:342-360) + `PinnedLink::unpin()` (:363-366). hello-ebpf pins programs and maps but the `FdLink`-typed pin is called out because *every* link type in aya converts to/from `FdLink` (`impl_try_into_fdlink!` / `impl_try_from_fdlink!` macros around `links.rs:568-604`), giving a uniform pin/reload story across program types. hello-ebpf's link pin story is less uniform.
- **`bpf_link_update` for atomic program swap** — used in xdp.rs:199 and tc.rs. This is the mechanism for zero-downtime prog upgrade on a live link. No hello-ebpf equivalent.
- **`ProgAttachLink` (`aya/src/programs/links.rs:373-441`)** — the underlying `BPF_PROG_ATTACH`/`BPF_PROG_DETACH` link wrapper used by cgroup programs. Exposes `CgroupAttachMode::{Single, AllowOverride, AllowMultiple}` via `BPF_F_ALLOW_OVERRIDE` / `BPF_F_ALLOW_MULTI` at :42-62. hello-ebpf cgroup attach hardcodes single-mode.
- **`ReusePortSocketFilter`** at `aya/src/programs/socket_filter.rs:308-372` — a separate type from `SocketFilter`, attached with `SO_ATTACH_REUSEPORT_EBPF`, distinct from `sk_reuseport`. Confusing overlap the prior catalog didn't disambiguate.
