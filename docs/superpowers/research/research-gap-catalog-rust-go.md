# Gap catalog: hello-ebpf vs Rust/Go peer eBPF libraries

Scope: what features exist in aya, libbpf-rs, cilium/ebpf, or libbpfgo but are missing from hello-ebpf.

Peer repos surveyed:

- aya — https://github.com/aya-rs/aya (Rust, pure-Rust loader)
- libbpf-rs — https://github.com/libbpf/libbpf-rs (Rust binding to libbpf) + libbpf-cargo
- cilium/ebpf — https://github.com/cilium/ebpf (pure-Go loader)
- libbpfgo — https://github.com/aquasecurity/libbpfgo (Go binding to libbpf)

hello-ebpf baseline (from `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/`):

- Program types: kprobe/kretprobe, uprobe/uretprobe, fentry/fexit, tracepoint, raw_tracepoint, LSM, ksyscall, perf_event, XDP, TC (SchedCLS via TCHook), cgroup_skb (CGroupHook), struct_ops sched_ext, SEC("syscall") via PROG_TEST_RUN.
- Maps: HASH, ARRAY, PROG_ARRAY, PERCPU_HASH, PERCPU_ARRAY, LRU_HASH, LRU_PERCPU_HASH, LPM_TRIE, RINGBUF, USER_RINGBUF, QUEUE, STACK, BLOOM_FILTER, ARENA, STACK_TRACE, INODE_STORAGE, TASK_STORAGE, SK_STORAGE, CPUMAP, DEVMAP, TIMER embed. `MapTypeId` enum knows SOCKMAP/SOCKHASH/XSKMAP/HASH_OF_MAPS/ARRAY_OF_MAPS/CGROUP_STORAGE/PERCPU_CGROUP_STORAGE/REUSEPORT_SOCKARRAY/DEVMAP_HASH/STRUCT_OPS but has no wrapper class.
- Runtime: link + map pinning, BTF parse (types.go equivalent), verifier log capture, ring buffer poll (one at a time), typed callbacks, bpf_prog_test_run for SEC("syscall").
- No: USDT, kprobe.multi, uprobe.multi, freplace/Extension, netfilter, netkit, tcx, socket_filter, sk_lookup, sk_reuseport, sk_msg, sk_skb, sock_ops, cgroup_sock, cgroup_sock_addr, cgroup_sockopt, cgroup_device, cgroup_sysctl, lsm_cgroup, tp_btf, lwt, lirc, BPF iterator programs (SEC("iter/*")), AF_XDP/XSK userspace, batch map ops, kprobe attach cookies, tokens, per-CPU perf event array reader with epoll multiplexing, feature-detection helpers, skeleton-style bindings with typed map handles.

## 1. Summary

Gap count by peer (features present in that peer, absent in hello-ebpf):

- aya: 22
- libbpf-rs: 20
- cilium/ebpf: 25
- libbpfgo: 22

Top 3 gaps present in ALL four peers:

1. **kprobe.multi / uprobe.multi attach** — bulk single-syscall attach to hundreds/thousands of kernel or userspace symbols. All four peers ship this; hello-ebpf still loops one kprobe per symbol.
2. **BPF iterator programs (SEC("iter/*"))** — user-consumable `seq_file`-style dumps of tasks/maps/sockets from a BPF program. All four peers expose a `link_create` + read(fd) API.
3. **Socket-plane program types (sk_msg / sk_skb / sock_ops / sockmap / sockhash)** — the whole "cilium-style" L7 socket redirection surface. All four peers can load and attach it; hello-ebpf has neither program type nor SOCKMAP/SOCKHASH map wrappers.

Runners-up in 3 of 4: USDT (aya missing), freplace/Extension (libbpfgo has via generic attach), cgroup_sock*/cgroup_sockopt (libbpfgo only via SEC() + generic attach), AF_XDP.

## 2. Per-gap entries

### Program types

#### kprobe.multi and uprobe.multi (bulk attach)

- What it is: a single BPF link attaching one program to a list of kernel symbols (or userspace offsets) with one syscall, with optional per-symbol cookie. Reduces attach cost from O(N) to O(1) and lets the handler distinguish sites via `bpf_get_attach_cookie()`.
- Peers: aya ✓, libbpf-rs ✓, cilium/ebpf ✓, libbpfgo ✓
- Peer example (cilium/ebpf, `link/kprobe_multi.go`):
  ```go
  l, _ := link.KprobeMulti(prog, link.KprobeMultiOptions{
      Symbols: []string{"do_sys_openat2", "do_unlinkat"},
      Cookies: []uint64{1, 2},
  })
  ```
  libbpfgo selftest: `selftest/uprobe-multi/main.go` uses `AttachUprobeMulti`.
- Why it matters for hello-ebpf: syscall tracing samples (`LogOpenAt2Calls`, `SyscallCounter`) currently instrument one symbol at a time. A `@KprobeMulti(symbols = {...})` annotation would let one Java program shadow entire subsystems (all `do_*` file syscalls) with one attach and dispatch by cookie, matching what bpftrace/Cilium do.
- Effort: M — libbpf provides `bpf_program__attach_kprobe_multi_opts`; needs a new annotation, a new attach path in BPFProgram, and a way for the C emitter to keep a single function body.

#### BPF iterator programs (SEC("iter/task"), iter/bpf_map, iter/tcp, iter/udp, iter/sock, iter/task_file, iter/bpf_prog, iter/cgroup)

- What it is: `BPF_PROG_TYPE_TRACING` with `BPF_TRACE_ITER`. The program produces a `seq_file` stream; userspace opens the link fd, does `read()`, and gets a formatted dump. Different from the in-kernel `bpf_iter_scx_dsq` iterator that hello-ebpf uses for the sched_ext DSQ.
- Peers: aya ✓ (`programs/iter.rs`), libbpf-rs ✓ (`Program::attach_iter`, `Iter` struct), cilium/ebpf ✓ (`link.AttachIter`), libbpfgo ✓ (`AttachGeneric` + `link-reader.go`; `selftest/iter/`, `selftest/iterators/`).
- Peer example (libbpf-rs):
  ```rust
  let prog = obj.progs_mut().dump_task().unwrap();
  let mut iter = LinkIter::new(prog.attach_iter().unwrap()).unwrap();
  let mut buf = String::new();
  iter.read_to_string(&mut buf).unwrap();
  ```
- Why it matters for hello-ebpf: today, dumping "all TCP sockets" or "all cgroups" from Java has to go through `/proc` or `ss`. A `SEC("iter/task")` program authored in Java (with `@Iter("task")`) could stream typed rows into a Java `Iterator<Record>` — a natural fit for the observability samples and the JFR pipeline.
- Effort: L — requires new program type, `bpf_program__attach_iter`, link fd → InputStream bridge, and a Java-side codegen path to emit `bpf_seq_printf`/`BPF_SEQ_PRINTF`.

#### Socket redirection plane: sk_msg + sk_skb + sock_ops + sockmap/sockhash

- What it is: the sockmap datapath. `sock_ops` populates a SOCKMAP; `sk_msg` rewrites/redirects egress socket data; `sk_skb` verdicts ingress. Powers Cilium socket-level LB and mTLS termination.
- Peers: aya ✓ (`programs/sk_msg.rs`, `sk_skb.rs`, `sock_ops.rs`, `maps/sock/sock_map.rs`, `sock_hash.rs`), libbpf-rs ✓ (generic SEC-based attach), cilium/ebpf ✓ (SockMap MapType + SkMsg/SkSKB/SockOps ProgramType), libbpfgo ✓ (via generic SEC attach).
- Peer example (aya declaration):
  ```rust
  #[map(name = "SOCKS")]
  static mut SOCKS: SockHash<u32> = SockHash::<u32>::with_max_entries(1024, 0);
  #[sk_msg]
  pub fn on_msg(ctx: SkMsgContext) -> u32 { … sk_redirect_hash(&ctx, &SOCKS, &key, 0) }
  ```
- Why it matters for hello-ebpf: this is the entire "L7 in eBPF" story (Cilium, Katran-lite). Without SOCKMAP/SOCKHASH + sk_msg/sk_skb, hello-ebpf can only observe packets (XDP/TC/cgroup_skb) — it cannot rewrite or redirect socket data.
- Effort: L — three new program types, two new map types, and kfunc/helper bindings for `bpf_msg_redirect_hash`, `bpf_sk_redirect_map`, `bpf_sock_hash_update`.

#### sk_lookup

- What it is: `BPF_PROG_TYPE_SK_LOOKUP` runs at `inet_lookup()` and lets a BPF program pick which listening socket a new connection binds to. Enables per-CIDR service redirection without touching iptables.
- Peers: aya ✓ (`sk_lookup.rs`), cilium/ebpf ✓ (`SkLookup` program type, `link.AttachNetNs`), libbpf-rs ✓ (generic SEC attach + `bpf_program__attach_netns`), libbpfgo ✓ (SEC-based).
- Peer example (aya):
  ```rust
  #[sk_lookup] pub fn service(ctx: SkLookupContext) -> u32 { … bpf_sk_assign(&ctx, &sk, 0) }
  ```
- Why it matters for hello-ebpf: implementing "sidecarless" service resolution or blue/green routing from Java requires this hook. Currently impossible.
- Effort: M — one program type, `bpf_program__attach_netns`, helper bindings.

#### sk_reuseport

- What it is: `BPF_PROG_TYPE_SK_REUSEPORT` picks which SO_REUSEPORT socket in a REUSEPORT_SOCKARRAY receives a given packet, replacing the kernel hash. Used for connection-affinity load balancers.
- Peers: aya ✓ (`sk_reuseport.rs`, `maps/sock/reuseport_sock_array.rs`), cilium/ebpf ✓ (`SkReuseport` + `ReusePortSockArray`), libbpf-rs ✓, libbpfgo ✓.
- Peer example (aya):
  ```rust
  #[map] static SOCKS: ReusePortSockArray = ReusePortSockArray::with_max_entries(64, 0);
  #[sk_reuseport] fn balance(ctx: SkReuseportContext) -> u32 { … bpf_sk_select_reuseport(&ctx, &SOCKS, &idx, 0) }
  ```
- Why it matters for hello-ebpf: enables writing L4 load balancers from Java. `REUSEPORT_SOCKARRAY` is in `MapTypeId` but has no wrapper.
- Effort: M.

#### flow_dissector

- What it is: overrides the kernel's L2/L3 header parser (RSS, RFS, XPS, sockmap keys) with a BPF program.
- Peers: aya ✓ (`flow_dissector.rs`), cilium/ebpf ✓ (`FlowDissector` program type), libbpf-rs ✓ (SEC-based), libbpfgo ✓ (SEC-based).
- Peer example (aya): `#[flow_dissector] fn dissect(ctx: FlowDissectorContext) -> u32 { … }`
- Why it matters: needed for GUE/VXLAN/GRE-aware RSS, and for making custom protocols play well with the socket layer. Complements XDP-only parsing hello-ebpf already has.
- Effort: M.

#### freplace / Extension (BPF_PROG_TYPE_EXT)

- What it is: replace or extend a specific target function in an already-loaded BPF program at attach time. Powers hot-patching of running BPF (e.g. Cilium can push a new bpf_lxc.o without reloading the whole datapath).
- Peers: aya ✓ (`extension.rs`), libbpf-rs ✓ (`Program::attach_freplace`), cilium/ebpf ✓ (`Extension` program type + `link.AttachFreplace`), libbpfgo ✓ (via generic attach + BTF ID plumbing).
- Peer example (aya):
  ```rust
  let ext: &mut Extension = bpf.program_mut("ext").unwrap().try_into().unwrap();
  ext.load(target_prog.fd().unwrap(), "target_func").unwrap();
  ext.attach().unwrap();
  ```
- Why it matters: hello-ebpf schedulers currently need a full unload+reload to change dispatch policy. freplace would allow swapping only the changed BPF function.
- Effort: L — needs BTF target function resolution and a new load path.

#### tcx (traffic-control eXpress) and netkit

- What it is: modern replacement for `clsact` TC attach; multi-program, ordered attach with cookies; kernel 6.6+. netkit is the peer for container-veth.
- Peers: aya ✓ (via tc.rs new APIs), cilium/ebpf ✓ (`link/tcx.go`, `link/netkit.go`), libbpf-rs ✓, libbpfgo ✓ (`tchook.go` supports tcx path).
- Peer example (cilium/ebpf):
  ```go
  l, _ := link.AttachTCX(link.TCXOptions{Program: prog, Interface: idx, Attach: ebpf.AttachTCXIngress})
  ```
- Why it matters: hello-ebpf's TCHook uses the legacy `bpf_tc_attach` path with priority/handle bookkeeping. tcx eliminates priority juggling and enables clean chaining with other TC BPFs.
- Effort: M.

#### netfilter (BPF_PROG_TYPE_NETFILTER)

- What it is: attach BPF to netfilter hook points (NF_INET_PRE_ROUTING etc.) with priority. Kernel 6.4+.
- Peers: aya (partial via `netfilter` skeleton), cilium/ebpf ✓ (`link/netfilter.go`, `Netfilter` program type), libbpf-rs ✓ (`netfilter.rs`), libbpfgo ✓.
- Peer example (libbpf-rs `netfilter.rs`): `Program::attach_netfilter(nf_hooknum, priority, ...)`.
- Why it matters: lets Java-authored programs co-exist with legacy iptables/nftables chains — critical for enterprise firewall integration where you can't remove nftables.
- Effort: M.

#### cgroup_sock, cgroup_sock_addr, cgroup_sockopt, cgroup_device, cgroup_sysctl

- What it is: family of cgroup-scoped hooks. `cgroup_sock_addr` rewrites `connect()`/`sendmsg()` addresses (Cilium socket LB). `cgroup_sockopt` intercepts `setsockopt`. `cgroup_device` gates `mknod`. `cgroup_sysctl` gates `/proc/sys` writes.
- Peers: aya ✓ (all five), cilium/ebpf ✓ (all five in `link/cgroup.go`), libbpf-rs ✓ (SEC + generic attach), libbpfgo ✓ (`AttachCgroup` + `AttachCgroupLegacy`).
- Peer example (aya):
  ```rust
  #[cgroup_sock_addr(connect4)] fn cb(ctx: SockAddrContext) -> i32 { ctx.set_user_ip4(...); 1 }
  ```
- Why it matters: hello-ebpf's `CGroupHook` only exposes `cgroup_skb/ingress` and `cgroup_skb/egress`. All the interesting cgroup-scope policy hooks — the ones Cilium uses for L4 LB, and that container runtimes use for device gating — are unreachable from Java today.
- Effort: M for each; L collectively.

#### tp_btf (BTF-typed raw tracepoints)

- What it is: raw tracepoints where arguments are BTF-typed pointers, so the BPF program can call `BPF_CORE_READ` on them without `bpf_probe_read`. Cheaper and safer than classic raw_tp.
- Peers: aya ✓ (`tp_btf.rs`), cilium/ebpf ✓ (`Tracing` attach type BPF_TRACE_RAW_TP), libbpf-rs ✓ (via SEC "tp_btf/"), libbpfgo ✓.
- Peer example (aya): `#[tp_btf("sched_switch")] fn on_switch(ctx: BtfTracePointContext) -> i32 { … }`
- Why it matters for hello-ebpf: JFR/GC tracers currently use `SEC("raw_tp/…")` with unsafe reads. tp_btf gives typed access to `prev_state`/`prev`/`next` for `sched_switch` etc.
- Effort: S — mostly a new section name + a `@TpBtf` annotation.

#### lsm_cgroup

- What it is: LSM hooks scoped to a cgroup rather than global. Kernel 6.0+.
- Peers: aya ✓ (`lsm_cgroup.rs`), cilium/ebpf ✓, libbpf-rs ✓ (SEC), libbpfgo ✓.
- Peer example (aya): `#[lsm_cgroup(hook = "file_open")] fn h(ctx: LsmContext) -> i32 { … }`
- Why it matters: hello-ebpf's `@LSM` fires globally; a per-cgroup variant would let ForbiddenFile-style demos scope to a container.
- Effort: S once LSM works — new section prefix + cgroup fd attach.

#### socket_filter (BPF_PROG_TYPE_SOCKET_FILTER)

- What it is: the original classic-BPF-replacement program type, attached with `setsockopt(SO_ATTACH_BPF)`. Simple packet capture from user sockets.
- Peers: aya ✓ (`socket_filter.rs`), cilium/ebpf ✓ (`link/socket_filter.go`, plus README example), libbpf-rs ✓, libbpfgo ✓.
- Peer example (cilium/ebpf `example_sock_elf_test.go`): opens raw socket, calls `syscall.SetsockoptInt(fd, SOL_SOCKET, SO_ATTACH_BPF, progFd)`.
- Why it matters: lets you build a per-process pcap replacement (like `tcpdump -i any` restricted to your PID's sockets) from Java. Complements XDP, which is interface-scoped.
- Effort: S.

#### LWT (BPF_PROG_TYPE_LWT_IN/OUT/XMIT/SEG6LOCAL)

- What it is: lightweight-tunneling BPF, attached via `ip route add … encap bpf`. Powers SRv6 (Seg6Local) datapaths.
- Peers: aya ✓, cilium/ebpf ✓, libbpf-rs ✓ (SEC), libbpfgo ✓.
- Why it matters: SRv6 use-cases (service chaining, network programming) are unreachable from Java today. Niche but definitionally missing.
- Effort: M — plus rtnetlink glue.

### Map types

#### SOCKMAP / SOCKHASH

- Peers: all four. Present in `MapTypeId` but no BPFSockMap/BPFSockHash Java wrapper and no helper bindings for `bpf_sock_map_update`, `bpf_sk_redirect_map`, `bpf_msg_redirect_hash`.
- Why it matters: prereq for the sk_msg/sk_skb story above.
- Effort: S once program types land.

#### ARRAY_OF_MAPS / HASH_OF_MAPS

- What it is: two-level maps. Outer map is keyed by tenant/CPU/CIDR; inner map is a full BPFHashMap. Cilium uses this heavily for per-endpoint policy.
- Peers: aya ✓ (`aya/src/maps/of_maps/`), cilium/ebpf ✓ (ArrayOfMaps/HashOfMaps + MapSpec.InnerMap), libbpf-rs ✓, libbpfgo ✓ (`selftest/map-of-maps-*`).
- Peer example (cilium/ebpf):
  ```go
  spec := &ebpf.MapSpec{Type: ebpf.ArrayOfMaps, KeySize:4, ValueSize:4, MaxEntries:10, InnerMap: innerSpec}
  ```
- Why it matters for hello-ebpf: per-CPU per-tenant counters or per-endpoint policy maps are impossible today.
- Effort: M — needs an annotation for the inner spec and a two-step map creation.

#### CGROUP_STORAGE / PERCPU_CGROUP_STORAGE

- Peers: all four have wrappers. hello-ebpf has `MapTypeId.CGROUP_STORAGE` but no class.
- Peer example (aya `maps/cgroup_storage.rs`): `#[map] static Q: CgroupStorage<u64> = CgroupStorage::with_max_entries(0, 0);`
- Why it matters: prereq for cgroup_sock_addr/cgroup_sockopt-scoped state.
- Effort: S.

#### DEVMAP_HASH

- Peers: aya ✓ (`dev_map_hash.rs`), cilium/ebpf ✓, libbpf-rs ✓, libbpfgo ✓.
- Why it matters: XDP redirect to non-contiguous ifindex sets. hello-ebpf has `BPFDevMap` (array-indexed) only.
- Effort: S.

#### AF_XDP userspace socket + XSKMAP support

- What it is: userspace ring buffer over the network stack for zero-copy packet processing. XSKMAP + `xdp_socket_create()` + `xsk_umem` + Rx/Tx rings.
- Peers: aya ✓ (`aya/src/maps/xdp/xsk_map.rs` + external `xsk-rs`), cilium/ebpf ✓ (via `internal/xsk` + Cilium's own AF_XDP integration), libbpf-rs ✓ (via libbpf's `xsk.h` API — re-exported), libbpfgo ✓ (via `helpers/`).
- Peer example (libbpf-rs `xdp.rs`): `Program::attach_xdp` + `XskMap::update`.
- Why it matters for hello-ebpf: without AF_XDP, hello-ebpf's XDP samples can drop/pass/redirect but cannot deliver frames to Java userspace at line rate. A pure DPDK-in-Java alternative.
- Effort: L — needs `xsk_socket__create`, `xsk_umem__create` bindings and ring memory management.

### Loader

#### Batch map operations (BPF_MAP_LOOKUP_BATCH / UPDATE_BATCH / DELETE_BATCH)

- What it is: one syscall reads or writes N entries. Kernel 5.6+. 5-10x speedup for large map drains.
- Peers: aya ✓ (batch methods on HashMap etc.), cilium/ebpf ✓ (`Map.BatchLookup`, `Map.BatchUpdate`, `MapBatchCursor`), libbpf-rs ✓ (`Map::lookup_batch`, `update_batch`), libbpfgo ✓ (`selftest/map-batch`).
- Peer example (cilium/ebpf):
  ```go
  var cursor ebpf.MapBatchCursor
  n, _ := m.BatchLookup(&cursor, keysBuf, valsBuf, nil)
  ```
- Why it matters: `SchedulerStats`, JFR aggregation, and any histogram flush in hello-ebpf currently iterate one key at a time via `bpf_map_lookup_elem`. On a 65k-entry map that is 65k syscalls.
- Effort: M — new methods on BPFBaseMap and per-CPU handling.

#### Program pinning to bpffs + skeleton-style reopen

- What it is: pin a whole program (not just link) to `/sys/fs/bpf/…`, and later reopen an already-loaded object by pin path. Enables long-lived daemons that outlive their loader.
- Peers: aya ✓ (`ProgramInfo::pin`), cilium/ebpf ✓ (`pin` package, `LoadPinnedProgram`), libbpf-rs ✓ (`Program::pin`), libbpfgo ✓ (via libbpf).
- hello-ebpf status: has map + link pinning (`BPFProgram.setMapPinPath`, `bpf_link__pin`) but not `bpf_program__pin` and no reopen-from-pin path.
- Effort: S.

#### Autoattach across all attachable sections

- What it is: libbpf's `bpf_object__attach_skeleton()` walks every prog and attaches by SEC() string. Peers hide this behind one call.
- Peers: aya ✓ (`Bpf::programs` + `attach()` on each), cilium/ebpf ✓ (`link.AttachType` deduced from SEC), libbpf-rs ✓ (`OpenSkel::load()` then `Skel::attach()`), libbpfgo ✓ (`BPFProg.AttachGeneric`).
- hello-ebpf status: `BPFFunction.autoAttachableSections = {"fentry","fexit","kprobe","kretprobe","ksyscall","tp","lsm"}` — misses uprobe/uretprobe/perf_event/xdp/tc/cgroup/raw_tp/sk_*/cgroup_*/iter/lsm_cgroup/tp_btf. Every non-listed hook needs a manual attach call.
- Effort: S — mostly extending the set + routing to the right `bpf_program__attach_*`.

#### Attach cookies (bpf_get_attach_cookie)

- What it is: opaque u64 given at attach time, retrievable inside the BPF handler. Lets one program serve multiple attach sites with per-site state without a map lookup.
- Peers: aya ✓, cilium/ebpf ✓ (`KprobeMultiOptions.Cookies`), libbpf-rs ✓ (`KprobeOpts.cookie`, `UsdtOpts.cookie`), libbpfgo ✓ (`selftest/uprobe-cookie`).
- hello-ebpf status: struct layout defines a `bpf_cookie` field (`BPFProgram.java` line 665, 673) but the value is hardcoded to 0 at line 711. Not exposed to callers.
- Effort: S — plumb one parameter.

#### Test-run beyond SEC("syscall") — XDP/TC/RAW_TP dry-run

- What it is: `BPF_PROG_TEST_RUN` with `ctx_in`/`data_in` for xdp/skb/raw_tp lets you drive a program from Java with a synthetic packet and assert on the output. Standard testing pattern.
- Peers: aya ✓ (`Program::test_run`), cilium/ebpf ✓ (`Program.Test`, `RunOptions{Data, Context, Repeat}`), libbpf-rs ✓ (`Program::test_run`), libbpfgo ✓ (`selftest/prog-run`).
- hello-ebpf status: `runSyscallProgram()` supports SEC("syscall") only. XDP/TC test_run wrappers absent.
- Effort: S — same libbpf function, different ctx layout per prog type.

#### Skeleton codegen with typed map handles (libbpf-cargo / bpf2go / genskel)

- What it is: a build-time tool that emits a language-native struct/class with typed getters for each map and program: `skel.maps().my_hash().lookup(&key)`. Removes stringly-typed `getMapByName("…")`.
- Peers: aya (partial — `EbpfLoader` + typed macros in aya-ebpf), libbpf-rs ✓ (`libbpf-cargo gen skeleton` → `.skel.rs`), cilium/ebpf ✓ (`bpf2go` emits `foo_bpfel.go` with typed struct), libbpfgo (via user tooling, less first-class).
- Peer example (bpf2go):
  ```go
  //go:generate go tool bpf2go foo path/to/src.c
  obj := fooObjects{}
  loadFooObjects(&obj, nil)
  obj.MyProg.Attach(...)
  ```
- hello-ebpf status: has an annotation processor that emits `*Impl.java` (see `bpf-samples/target/generated-sources/annotations/`), but callers still resolve maps by string (`getMapByName("packetLog")`). Gap is the typed-handle ergonomics, not the codegen itself.
- Effort: M — extend the processor to emit typed accessor methods on the generated Impl class.

#### Feature-detection API (features package)

- What it is: probe the running kernel for supported program types, map types, helper functions, ISA versions, link types, and instruction limits — before attempting to load.
- Peers: cilium/ebpf ✓ (`features` package with `HaveProgramType`, `HaveMapType`, `HaveProgramHelper`, `HaveBPFLinkKprobeMulti`, ISA probes), libbpf-rs (partial, via `libbpf_probe_bpf_prog_type`), libbpfgo ✓ (`selftest/probe-features`, `selftest/probe-ringbuf`), aya (via manual `syscall` probes).
- Why it matters: hello-ebpf currently discovers unsupported kernels via a load failure with a cryptic verifier message. A `Features.hasRingBuf()` / `Features.hasLsm()` gate would let callers pick fallback paths (perfbuf vs ringbuf) cleanly.
- Effort: S — thin JNI wrapper over `libbpf_probe_bpf_map_type` / `libbpf_probe_bpf_helper`.

#### BTF split, kernel module BTF, custom BTF for older kernels

- What it is: load `/sys/kernel/btf/<module>` for out-of-tree modules; supply a custom minimized BTF blob for kernels without native BTF (`BTFGen`, BTFHub archive).
- Peers: aya ✓ (`btf` module supports kernel + module BTF), cilium/ebpf ✓ (`btf` package with `LoadKernelSpec`, `LoadSpec` for modules, `SplitBTF`), libbpf-rs ✓ (`Btf` handles), libbpfgo ✓ (`btf.go` supports module BTF).
- hello-ebpf status: `BPFProgram.BTF` reads main-kernel BTF only. No module BTF, no custom BTF override.
- Effort: M.

#### BPF token API (kernel 7.1+)

- What it is: delegated-privileges FD that lets unprivileged processes load pinned program types. Cilium/eBPF README explicitly calls out Linux 7.1 token support.
- Peers: cilium/ebpf ✓ (documented), libbpf-rs ✓ (`bpf_token_create` wired), aya (in progress), libbpfgo ✓ (via libbpf).
- Effort: M — new syscall wrappers + object-open flags.

### Runtime

#### Ring buffer / perf-buffer epoll multiplexing across many maps

- What it is: register multiple ringbufs on one epoll fd so a single consumer thread drains N maps. Standard pattern in tracing daemons.
- Peers: aya ✓ (`RingBuf::poll` + tokio async fd), cilium/ebpf ✓ (`ringbuf.Reader` uses internal epoll, `perf.Reader` too), libbpf-rs ✓ (`ring_buffer__epoll_fd` exposed via `RingBufferBuilder::add(map, callback)`), libbpfgo ✓ (`buf-ring.go` supports multi-map via callbacks).
- hello-ebpf status: `BPFRingBuffer.poll(timeoutMs)` is per-map and blocks a whole thread. `BPFEvents` composes but there's no single-fd epoll drain.
- Effort: M.

#### PerfEventArray reader (per-CPU perf ring buffer)

- What it is: pre-ringbuf way to stream events. `perf_event_open()` + mmap per CPU + epoll. Still relevant for kernels < 5.8 and for hardware-PMU sampling.
- Peers: aya ✓ (`AsyncPerfEventArray`), cilium/ebpf ✓ (`perf.Reader`), libbpf-rs ✓ (`PerfBuffer`), libbpfgo ✓ (`buf-perf.go`).
- hello-ebpf status: hooks `perf_event`, but there is no `BPFPerfEventArray<E>` reader. Programs must either write to a ringbuf (kernel 5.8+) or use `PerfEvent.readValue()` for a single sample.
- Effort: M.

#### USDT (SDT userspace tracepoints)

- What it is: SystemTap-format semaphore-activated userspace tracepoints (in glibc, JVM, Postgres, MySQL). One attach resolves the marker via ELF notes.
- Peers: libbpf-rs ✓ (`Program::attach_usdt`, `UsdtOpts` with cookie), libbpfgo ✓ (`AttachUSDT`, `selftest/usdt`), cilium/ebpf ✓ (elf parses `_SEC_USDT`), aya explicitly does NOT support USDT (see `aya-obj/CHANGELOG.md`: "Since USDT probes aren't currently supported").
- Peer example (libbpfgo):
  ```go
  prog.AttachUSDT(-1, "/usr/lib/libc.so.6", "libc", "memory_sbrk_more")
  ```
- Why it matters for hello-ebpf: the JVM ships dozens of USDT markers (`hotspot:method__entry`, `hs_private:safepoint__begin`, `hs:gc__begin`). Attaching to them from Java would be the killer JFR-complementary feature.
- Effort: M — libbpf's `bpf_program__attach_usdt` does the ELF note parsing; needs a `@USDT(provider, marker)` annotation and semaphore bookkeeping.

#### BPF logging framework (aya-log / bpf-printk-plus)

- What it is: `info!(&ctx, "…{}", val)` inside BPF → structured formatted output in userspace with levels. Beats `bpf_printk` (kernel-log spam, no format-arg types).
- Peers: aya ✓ (aya-log-ebpf + aya-log userspace reader), libbpf-rs (via user tooling), cilium/ebpf (via user tooling), libbpfgo (via user tooling).
- Peer example (aya-log-ebpf):
  ```rust
  use aya_log_ebpf::info;
  info!(&ctx, "blocked port {}", port);
  ```
- Why it matters: hello-ebpf's `BPFJ.bpf_trace_printk` writes to `/sys/kernel/debug/tracing/trace_pipe`, a global sink. A perf-ringbuf-backed structured logger with Java-level integration (SLF4J bridge) would be a big DX win.
- Effort: M — Java-side annotation processor to route printf-style calls to a `BPF_MAP_TYPE_RINGBUF` sink.

#### Live map dump / `bpftool map dump`-equivalent

- What it is: iterate every entry in an already-loaded pinned map from userspace for inspection.
- Peers: aya ✓ (`Map::iter`), cilium/ebpf ✓ (`Map.Iterate`), libbpf-rs ✓ (`Map::keys`, `Map::values`), libbpfgo ✓ (`map-iterator.go`).
- hello-ebpf status: `BPFHashMap` has `entrySet()`/`stream()` but only for that typed handle. There's no way to open a pinned map by path with just a schema and iterate it — you need the whole `BPFProgram` subclass.
- Effort: S — a `BPFMap.openPinned(path, keyType, valueType)` static factory.

### Ergonomics / Toolchain

#### Attach-by-string / dynamic hook creation

- What it is: peers let you supply a hook target at userspace time (`AttachTracepoint("sched", "sched_switch")`), independently of any compile-time annotation. Same C program → many attach sites.
- Peers: aya, cilium/ebpf, libbpf-rs, libbpfgo — all four.
- hello-ebpf status: hook name is baked into `@Tracepoint(category, event)`/`@Fentry(function)` at annotation-processor time. Users cannot pick the target at runtime without re-generating the C.
- Effort: M — needs sections written with wildcards / an attach-time override path.

#### Query loaded objects (bpf(BPF_PROG_GET_NEXT_ID) etc.)

- What it is: enumerate every BPF program and map on the system, get its BTF and stats. Powers `bpftool`.
- Peers: cilium/ebpf ✓ (`ebpf.NewProgramFromID`, `NewMapFromID`), libbpf-rs ✓ (`query` module: `ProgInfoIter`, `MapInfoIter`), libbpfgo ✓ (`module-iterator.go`, `map-iterator.go`), aya ✓ (`loaded_programs`, `loaded_maps`).
- Peer example (libbpf-rs `query.rs`): `ProgInfoIter::default().next()`.
- Why it matters: writing bpftool-in-Java, or exposing "what's loaded" in a health endpoint, is impossible today.
- Effort: M.

#### Program stats (`bpf_stats_enable`)

- What it is: kernel per-program run count + time; togglable via `SYSKALL BPF_ENABLE_STATS`. Cost model for scheduling BPF work.
- Peers: cilium/ebpf ✓ (`EnableStats`), libbpf-rs ✓ (`ProgramStats`), libbpfgo ✓, aya ✓ (`ProgramInfo::run_count`).
- Effort: S.

#### CO-RE / vmlinux.h autogen at build time

- What it is: emit `vmlinux.h` (or Rust/Go equivalent bindings) from the target kernel's BTF at build time, giving the C source strongly-typed access to every kernel struct.
- Peers: aya (via aya-tool or vmlinux-btf), cilium/ebpf (via `bpf2go` + `bpftool btf dump file /sys/kernel/btf/vmlinux format c`), libbpf-cargo ✓ (`libbpf-cargo gen vmlinux`), libbpfgo (via docs).
- hello-ebpf status: hand-generated `BpfDefinitions.java` (28k+ lines, checked in). No refresh path documented, and drift from newer kernels requires manual regeneration.
- Effort: L — needs a Maven plugin goal that runs `bpftool` and re-emits `BpfDefinitions.java`.

## 3. Rejected candidates

- **RingBuffer support** — hello-ebpf has `BPFRingBuffer` with callbacks; not a gap.
- **User ring buffer (BPF_MAP_TYPE_USER_RINGBUF)** — hello-ebpf has `BPFUserRingBuffer` and `BPFUserRingbufCallback`. Not a gap.
- **Arena** — hello-ebpf has `BPFArena` and `BPFTypedArena`. Not a gap.
- **Struct_ops sched_ext** — hello-ebpf has full support (Scheduler.java + userspace scheduler runtime). Not a gap; hello-ebpf is arguably ahead of aya here.
- **Task/inode/sk local storage** — hello-ebpf has `BPFTaskStorage`, `BPFInodeStorage`, `BPFSkStorage`. Not a gap.
- **BLOOM_FILTER map** — hello-ebpf has `BPFBloomFilter`. Not a gap.
- **PROG_TEST_RUN for SEC("syscall")** — hello-ebpf has `runSyscallProgram()`. Kept the "test_run for other prog types" gap separate.
- **Verifier log capture** — hello-ebpf has `VerifierLogCapture`. Not a gap.
- **CO-RE `preserve_access_index`** — hello-ebpf uses `BPF_CORE_READ` (see memory `project_co_re_preserve_access_index.md`). Not a gap.
- **Tail calls** — hello-ebpf has `BPFProgArray` + `TailCallDemo` sample. Not a gap.
- **Global variables** — hello-ebpf has `GlobalVariable` with BTF-driven layout. Not a gap.
- **Ksyscall** — hello-ebpf has it via `@Ksyscall`. Not a gap.

## 4. Retrieval provenance

Fetched 2026-07-01:

- https://github.com/aya-rs/aya (README) — high-level feature list
- https://github.com/libbpf/libbpf-rs — top-level structure
- https://github.com/cilium/ebpf — top-level structure
- https://github.com/aquasecurity/libbpfgo — top-level structure
- https://github.com/aya-rs/aya/tree/main/aya/src/programs — program-type enumeration
- https://github.com/aya-rs/aya/tree/main/aya/src/maps — map enumeration
- https://github.com/aya-rs/aya/tree/main/aya/src/maps/xdp — xsk/dev/cpu maps
- https://github.com/aya-rs/aya/tree/main/aya/src/maps/sock — sockmap/sockhash/reuseport
- https://github.com/aya-rs/aya/tree/main/aya/src/maps/of_maps — array/hash of maps
- https://github.com/aya-rs/aya/tree/main/aya/src/maps/perf — perf_buffer + perf_event_array
- https://github.com/aya-rs/aya/tree/main/aya-log — aya-log example
- https://github.com/libbpf/libbpf-rs/tree/master/libbpf-rs/src — top-level modules incl. `iter.rs`, `netfilter.rs`, `user_ringbuf.rs`, `xdp.rs`
- https://github.com/libbpf/libbpf-rs/tree/master/libbpf-cargo/src — skeleton codegen tool
- https://pkg.go.dev/github.com/cilium/ebpf/link — link enumeration
- https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go — bpf2go workflow
- https://pkg.go.dev/github.com/cilium/ebpf/features — feature-probing API
- https://pkg.go.dev/github.com/cilium/ebpf/perf — perf Reader API
- https://github.com/cilium/ebpf/tree/main/link — kprobe_multi.go, uprobe_multi.go, tcx.go, netkit.go, netfilter.go, iter.go, cgroup.go, socket_filter.go, struct_ops.go, tracing.go, raw_tracepoint.go
- https://github.com/cilium/ebpf/blob/main/types.go — ProgramType and MapType enumerations
- https://pkg.go.dev/github.com/aquasecurity/libbpfgo — Attach* method list
- https://github.com/aquasecurity/libbpfgo/tree/main/selftest — usdt, uprobe-multi, uprobe-cookie, iter, iterators, struct-ops, map-batch, map-of-maps-*, netns, cgroup-legacy, xdp, tc, prog-run, probe-features, probe-ringbuf, spinlocks, tracing-by-offset

hello-ebpf state from local files, no fetch needed:

- `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java`
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/map/MapTypeId.java`
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/map/` (directory listing)
- `/Users/i560383_1/code/experiments/hello-ebpf/annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/` (directory listing)
- `/Users/i560383_1/code/experiments/hello-ebpf/annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFFunction.java` (`autoAttachableSections`)
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/CGroupHook.java`
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/perf/PerfEvent.java`
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/` (sample listing)
