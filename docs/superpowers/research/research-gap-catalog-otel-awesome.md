# Gap Catalog: OpenTelemetry Profiler + awesome-ebpf

Research target: cataloging capabilities that hello-ebpf lacks, as evidenced by
the OpenTelemetry eBPF profilers and the qmonnet/awesome-ebpf catalog. Sibling
research agent covers the Rust/Go peer-library survey; this document
deliberately does not restate aya / libbpf-rs / cilium-ebpf / libbpfgo gaps.

Hello-ebpf baseline reviewed:
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java`
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/bpf/map/`
- `/Users/i560383_1/code/experiments/hello-ebpf/annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/`
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/`

Program types wrapped today (attach helpers or `@BPFFunction` sections): kprobe,
kretprobe, ksyscall, uprobe, uretprobe, tracepoint, raw_tracepoint, fentry,
fexit, LSM, XDP, TC, cgroup, perf_event, struct_ops (sched_ext). Map types with
Java wrappers: HASH, ARRAY, PERCPU_HASH/ARRAY, LRU_HASH, LRU_PERCPU_HASH,
LPM_TRIE, PROG_ARRAY (tail calls), RINGBUF, USER_RINGBUF, QUEUE, STACK,
STACK_TRACE, BLOOM_FILTER, DEVMAP, CPUMAP, TIMER, ARENA (typed), SK_STORAGE,
TASK_STORAGE, INODE_STORAGE. `MapTypeId` also lists SOCKMAP / SOCKHASH / XSKMAP
/ REUSEPORT_SOCKARRAY / CGROUP_STORAGE / STRUCT_OPS but no wrapper classes
exist for them.

## 1. Summary

Gap counts: 9 from the OpenTelemetry profiler / OTel Network collector, 9 from
awesome-ebpf, plus rejected candidates below.

Top 5 highest-impact gaps (weighted for profiler-scale and network
observability, per brief):

1. **DWARF / `.eh_frame`-based native stack unwinder without frame pointers** —
   `CPUProfiler` today relies on `bpf_get_stackid`, which only works if frame
   pointers are present. The OTel profiler ships a full `.eh_frame`
   stack-delta bsearch that runs in-BPF; hello-ebpf cannot profile Rust/Go/C++
   libraries built with `-fomit-frame-pointer`.
2. **Interpreter / JIT stack unwinders (HotSpot, Python, Ruby, PHP, V8, .NET,
   Perl, BEAM)** — every OTel language tracer is a separate BPF program; hello-
   ebpf has only kernel+user native symbolization and cannot render Java frames
   for the JIT'ed code path even though it is a Java framework.
3. **Perf-event-array (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`) wrapper** — every
   pre-ringbuf tracer (bcc, most awesome-ebpf tools, OTel Network's `events`
   map) still uses per-CPU perf event arrays for event streaming; hello-ebpf
   has no wrapper and no `bpf_perf_event_output` helper binding.
4. **Socket-map suite (SOCKMAP, SOCKHASH, sk_msg, sk_skb, sockops,
   sk_reuseport, sk_lookup) and AF_XDP / XSKMAP userspace path** — a
   whole category of userspace-networking use cases (service-mesh short-
   circuit, DPDK-competitor AF_XDP zero-copy, transparent SSL) is
   unreachable. Section names/enum are declared but no framework support
   attaches or manipulates these programs.
5. **Continuous / long-running sampling collector primitives** — no
   aggregation ring, no cardinality control, no on-CPU vs off-CPU split, no
   symbolization cache eviction. `CPUProfiler` is a one-shot windowed sampler
   with no supported way to stream samples over hours.

Full catalog below.

## 2. From OpenTelemetry profilers

### 2.1 DWARF / `.eh_frame` native stack unwinder in eBPF

- **What it is**: A native unwinder that walks stacks without frame pointers by
  bsearching a per-executable "stack delta" table (derived from `.eh_frame`)
  loaded into inner maps and stepping the unwinder across tail-called BPF
  programs. Handles inline frames and correct return addresses.
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/support/ebpf
  — `native_stack_trace.ebpf.c`, `native_stack_trace.h`, `nativeunwind/`
  Go directory that builds the delta tables.
- **Why it matters for hello-ebpf**: `/Users/i560383_1/code/experiments/hello-
  ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CPUProfiler.java`
  passes `PerfEvent.STACK_USER` to `bpf_get_stackid`. That helper walks frame
  pointers only. Any application built with the modern default
  `-fomit-frame-pointer` (glibc, Go, PGO'd Rust) produces truncated or empty
  user stacks. The OTel technique is the state-of-the-art fix; hello-ebpf
  cannot profile most production Linux binaries without it.
- **Rough effort estimate**: L (needs userspace ELF `.eh_frame` parser, delta
  encoder, inner-map management, and a chain of tail-called unwinder programs).

### 2.2 Language interpreter tracers (HotSpot, Python, Ruby, PHP, V8/Node,
     .NET, Perl, Erlang/BEAM, Go labels)

- **What it is**: One BPF program per language runtime that inspects the
  interpreter's data structures (Python frame chain, Ruby VM stack, JVM
  CodeCache, V8 stack frames, PHP `zend_execute_data`, .NET `Thread`,
  Perl `PL_curcop`, BEAM process control block) via `bpf_probe_read_user`
  and emits pseudo-frames tagged with language ID.
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/support/ebpf
  → `hotspot_tracer.ebpf.c`, `python_tracer.ebpf.c`, `ruby_tracer.ebpf.c`,
  `php_tracer.ebpf.c`, `v8_tracer.ebpf.c`, `dotnet_tracer.ebpf.c`,
  `perl_tracer.ebpf.c`, `beam_tracer.ebpf.c`, `go_labels.ebpf.c`;
  matching userspace demangling under
  https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/interpreter/
- **Why it matters for hello-ebpf**: `CPUProfiler.java` produces
  `libjvm.so+0xNNN` frames for JIT'd Java code. A Java-first eBPF framework
  should be able to render Java method names in its own profiler. HotSpot
  support alone would be a strong differentiator; using OTel's approach
  (reading CodeCache via `bpf_probe_read_user` from
  `_thread->_current_pending_monitor` and neighbouring fields) is a
  well-documented pattern.
- **Rough effort estimate**: L per language, M once one is done (each
  interpreter is a self-contained tracer).

### 2.3 Executable-identification / BuildID pipeline

- **What it is**: Reading GNU `.note.gnu.build-id` at unwind time to key
  symbol data by build-id rather than path+inode, so pre-built symbol
  archives (Debian debuginfo, Google symbol server, symbolizer sidecars)
  can be queried offline.
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/libpf
  (`fileid.go`, ELF utility code) and `processmanager/`.
- **Why it matters for hello-ebpf**: `StackSymbolizer.java` locates symbols
  only via `/proc/pid/maps` + local ELF `.dynsym`. Without build-id, hello-
  ebpf cannot re-symbolize old samples on a different host, cannot cache
  per-binary results across restarts, and cannot integrate with the
  emerging OTel profiling signal (which mandates build-id).
- **Rough effort estimate**: S (parse `.note.gnu.build-id`, add caching
  key, expose `String symUser(long ip, long buildId)`).

### 2.4 Remote / offline symbolization split

- **What it is**: Kernel captures raw `(fileId, addr)` frames; symbolization
  runs in a separate process / service (`reporter/collector_reporter.go`,
  `reporter/otlp_reporter.go`).
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/reporter
- **Why it matters for hello-ebpf**: Today symbolization is inline with
  sampling in `CPUProfiler`. That prevents deploying the sampler on
  containers/hosts that lack the target binaries (common in stripped
  container images). A "collect raw, symbolize elsewhere" split is
  a prerequisite for OTel profiling-signal compliance.
- **Rough effort estimate**: M (needs an on-wire event format and a Java
  helper that consumes it).

### 2.5 Off-CPU profiling

- **What it is**: A `sched_switch` tracepoint program that records the
  delta between task de-scheduling and re-scheduling and captures the
  stack at that point.
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/support/ebpf/off_cpu.ebpf.c
- **Why it matters for hello-ebpf**: On-CPU sampling misses lock
  contention, IO waits, and GC pauses. Off-CPU is a standard second
  view for continuous profilers and is a small addition on top of the
  existing perf_event sampler.
- **Rough effort estimate**: S (single tracepoint program, hash keyed on
  pid + stack-id, delta calculated in userspace).

### 2.6 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` wrapper +
     `bpf_perf_event_output` helper

- **What it is**: The classic per-CPU perf event array used to stream
  variable-sized events to userspace, along with the `bpf_perf_event_output`
  helper and the userspace `perf_buffer__poll` glue.
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-network/blob/main/collector/kernel/bpf_src/render_bpf.c
  declares `events` as `BPF_MAP_TYPE_PERF_EVENT_ARRAY`; almost every awesome-
  ebpf tool from the pre-2021 era (bcc/BPFtrace samples, Netronome examples,
  MPLSinIP sample) uses this map.
- **Why it matters for hello-ebpf**: Hello-ebpf standardised on ringbuf
  (`BPFRingBuffer`, `BPFUserRingBuffer`) which needs kernel 5.8+. Any
  attempt to port existing tracing samples from bcc/aya or to interop with
  older kernels still shipping in RHEL 8 will need perf-event-array. It is
  also faster than ringbuf for high-cardinality per-CPU streams because it
  needs no cross-CPU synchronisation on the producer side.
- **Rough effort estimate**: M (new map wrapper, helper binding, and a
  `perf_buffer__poll` Panama binding).

### 2.7 Conntrack / netfilter observability recipes

- **What it is**: The kprobe set attached by OTel Network to observe
  live sockets and NAT state (`__nf_conntrack_confirm`, `nf_ct_delete`,
  `ctnetlink_dump_tuples`, `inet_csk_accept/listen_start`,
  `tcp_retransmit_timer`, `tcp_reset`, `tcp_rcv_established`, ...).
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-network/blob/main/collector/kernel/bpf_src/render_bpf.c
- **Why it matters for hello-ebpf**: Hello-ebpf's networking samples
  (`Firewall.java`, `TCDropEveryThirdOutgoingPacket.java`,
  `XDPPacketFilter.java`) sit at packet level. A "network observer" sample
  that follows OTel Network's kprobe recipe would give framework users a
  starting point for building Coroot / Pixie-style flow observers without
  reinventing the socket lifecycle kprobe set.
- **Rough effort estimate**: M (sample only, all primitives already exist).

### 2.8 Kernel-symbols module with `/proc/kallsyms` module-aware parsing

- **What it is**: Kallsyms parsing that handles modules (`[module_name]`
  suffix) and updates for hot-plugged modules.
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/kallsyms
  and https://github.com/open-telemetry/opentelemetry-network/blob/main/collector/kernel/kernel_symbols.cc
- **Why it matters for hello-ebpf**:
  `/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/StackSymbolizer.java`
  `loadKallsyms()` strips the `[module]` suffix silently (`parts[2].split("\\s")[0]`)
  and never reloads. On any system with rmmod/modprobe activity the cache
  becomes stale. This is a small polish gap but affects sample accuracy.
- **Rough effort estimate**: S.

### 2.9 Per-CPU perf_event_open with `PERF_EVENT_IOC_SET_BPF`
     and cpu-hotplug reattach

- **What it is**: The full lifecycle — reopening perf events on CPUs that
  come online, restarting the sampler after a CPU offline event, and
  correlating fd → cpu across the run.
- **Where it comes from**:
  https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/main/tracer/
  (tracer setup) and OTel network `perf_poller.cc`.
- **Why it matters for hello-ebpf**: `CPUProfiler` opens perf_event once
  per CPU at startup; a CPU coming online mid-run is silently ignored, and
  any offline event's fd is leaked. A framework-level `attachPerfEventOnAllCPUs`
  helper that handles hotplug would make the whole continuous-profiler use
  case honest.
- **Rough effort estimate**: M.

## 3. From awesome-ebpf

Grouped by category as requested.

### 3.1 Tools — patterns hello-ebpf should provide as reference samples

#### 3.1.1 AF_XDP zero-copy user-space socket sample

- **What it is**: Binding a Java userspace socket to a NIC RX/TX queue via
  the AF_XDP protocol family, with an XSKMAP redirect from an XDP program
  that filters packets and hands the remainder to userspace.
- **Where it comes from**: awesome-ebpf → "AF_XDP" section
  (https://www.kernel.org/doc/html/latest/networking/af_xdp.html) and
  `PcapPlusPlus` AF_XDP support
  (https://pcapplusplus.github.io/docs/next/features#af_xdp-support-beta).
- **Why it matters**: Java has no equivalent of the DPDK PMD; AF_XDP is the
  supported way to build a Java-based line-rate packet processor.
  Hello-ebpf lists `XSKMAP` in `MapTypeId` but has no wrapper and no sample.
- **Rough effort estimate**: L (needs `xsk_ring` Panama bindings and a
  `BPFXskMap` wrapper).

#### 3.1.2 SOCKMAP / SOCKHASH + `sk_msg` / `sk_skb` service-mesh short-circuit

- **What it is**: Redirecting socket data between two locally-connected
  sockets via SOCKMAP to bypass the network stack. This is the trick that
  powers Merbridge and Cilium's L7 acceleration.
- **Where it comes from**: awesome-ebpf → "merbridge" and the Cilium/
  Envoy-mesh references
  (https://github.com/merbridge/merbridge/).
- **Why it matters**: Service-mesh acceleration is a canonical eBPF
  headline use case; hello-ebpf cannot express it today (no attach for
  `BPF_PROG_TYPE_SK_MSG`, `BPF_PROG_TYPE_SK_SKB`, `BPF_PROG_TYPE_SOCK_OPS`;
  no SOCKMAP wrapper).
- **Rough effort estimate**: L (three new program types, new map type,
  new attach method).

#### 3.1.3 `sk_lookup` custom socket steering

- **What it is**: A program run at TCP/UDP `sk_lookup` time to redirect
  new connections to non-BIND-ed listeners (SNI-based routing, one process
  handling many ports).
- **Where it comes from**: awesome-ebpf → Cilium refs;
  `linux/tools/testing/selftests/bpf` sk_lookup tests
  (https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf).
- **Why it matters**: Wildcard listeners and dynamic port allocation
  patterns (which several Java frameworks would benefit from) are simply
  unreachable.
- **Rough effort estimate**: M.

#### 3.1.4 `SO_REUSEPORT` custom load balancer sample

- **What it is**: A `sk_reuseport` program (attached via `REUSEPORT_SOCKARRAY`)
  that steers new connections among a `SO_REUSEPORT` pool by header content.
- **Where it comes from**: awesome-ebpf tutorial
  https://cloudchirp.substack.com/p/ebpf-powered-load-balancing-for-so_reuseport
- **Why it matters**: Common pattern for Netty/undertow pools. `REUSEPORT_SOCKARRAY`
  is in `MapTypeId` but unused.
- **Rough effort estimate**: M.

#### 3.1.5 DNS / L7 protocol parsing sample

- **What it is**: A socket-filter / kprobe program that parses DNS,
  HTTP, Redis, MySQL, TLS handshake headers directly from the wire and
  exports structured events.
- **Where it comes from**: awesome-ebpf → "A Deep Dive into eBPF: Writing
  an Efficient DNS Monitoring", kyanos
  (https://github.com/hengyoush/kyanos), ptcpdump
  (https://github.com/mozillazg/ptcpdump).
- **Why it matters**: Hello-ebpf has `BasePacketParser.java` and low-level
  XDP parsers but no protocol-level parsing sample. Would round out the
  network-observability story and pairs with the OTel Network kprobe set.
- **Rough effort estimate**: M.

#### 3.1.6 BPF iterator (`BPF_LINK_TYPE_ITER`) programs and attach

- **What it is**: BPF programs of type `BPF_PROG_TYPE_TRACING` with
  attach type `BPF_TRACE_ITER` that walk kernel data (all tasks, all
  sockets, all cgroups, all bpf maps) with iteration state.
- **Where it comes from**: awesome-ebpf → "Loops and Iterators in eBPF"
  (https://cloudchirp.substack.com/p/loops-and-iterators-in-ebpf) and
  the kernel's `linux/tools/testing/selftests/bpf/progs/bpf_iter_*` tree.
- **Why it matters**: Iterators are the modern replacement for
  `/proc`/`/sys` scraping — no way to attach one from hello-ebpf today.
  Neither `attachIter` nor a `bpf_link_create(BPF_TRACE_ITER)` binding
  exists.
- **Rough effort estimate**: M.

#### 3.1.7 Uprobe SSL/TLS interception sample (OpenSSL / GoTLS)

- **What it is**: Uprobes on `SSL_read` / `SSL_write` (OpenSSL) or on
  the Go TLS routines to capture plaintext at the crypto boundary.
- **Where it comes from**: awesome-ebpf → "What Insights Can eBPF Provide
  into Real-Time SSL/TLS Encrypted Traffic and How?"
  (https://cloudchirp.substack.com/p/what-insights-can-ebpf-provide-into),
  kyanos, DeepFlow.
- **Why it matters**: A widely-cited eBPF use case; uprobe support is
  already in hello-ebpf but there is no sample covering SSL_* interception,
  so the "how do I do this" recipe would be a big carry.
- **Rough effort estimate**: S (sample only).

### 3.2 Testing / debugging tooling

#### 3.2.1 BPF verifier log capture with human-friendly rendering
     (parity with libbpf's `LIBBPF_STRICT_KERN_VERSION`)

- **What it is**: Structured verifier-log parsing (line, instruction,
  register state) with source-mapping when debug info is available.
  awesome-ebpf → PREVAIL user-space verifier
  (https://github.com/vbpf/ebpf-verifier) demonstrates the depth of
  analysis possible.
- **Why it matters**: Hello-ebpf has `VerifierLogCapture.java` but it
  returns the raw text. Line-by-line rendering plus a "highlight the
  Java expression that produced the failing insn" would materially
  reduce debug time.
- **Rough effort estimate**: M.

#### 3.2.2 Multi-kernel / multi-distro compatibility gate

- **What it is**: A CI runner that loads compiled BPF ELFs against a
  matrix of kernels in disposable VMs, classifies failures (missing BTF,
  unsupported map/program type, CO-RE relocations).
- **Where it comes from**: awesome-ebpf → `bpfcompat`
  (https://github.com/Kernel-Guard/bpfcompat).
- **Why it matters**: Hello-ebpf's tests currently target one kernel on
  the thinkstation (per project memory). A BTF/CO-RE matrix would surface
  the CO-RE relocation and helper-availability drift that Java samples
  ship with — especially valuable given that hello-ebpf generates the C.
- **Rough effort estimate**: M.

#### 3.2.3 `bpftool` feature/probe wrapper

- **What it is**: Reflecting the current kernel's supported program
  types, map types, helpers, and kfuncs via `bpftool feature probe`
  and exposing that as a Java API so samples can degrade gracefully.
- **Where it comes from**: awesome-ebpf → `bpftool`
  (https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/bpf/bpftool).
- **Why it matters**: `Requires.java` annotation exists for compile-time
  checks; a runtime probe would let samples do "if this kernel supports
  ringbuf, use it, else fall back to perf-event-array". No such API today.
- **Rough effort estimate**: S.

### 3.3 Kfunc / helper catalog gaps

#### 3.3.1 `bpf_perf_event_output` and `bpf_perf_event_read_value` helpers

- **What it is**: Emitting to a perf_event_array from a probe; reading a
  hardware perf counter (cycles, instructions, cache-miss) from within
  a probe.
- **Where it comes from**: `bpf-helpers(7)` (awesome-ebpf → manual pages).
- **Why it matters**: Hardware-counter sampling is a common performance
  investigation pattern; hello-ebpf currently has no helper binding
  (`me.bechberger.ebpf.runtime.helpers.BPFHelpers` lacks these entries).
  Even if the perf_event_array wrapper (2.6) isn't done, `read_value`
  alone would unlock IPC/miss-rate probes.
- **Rough effort estimate**: S per helper.

## 4b. awesome-ebpf repo deep-dive: what real projects actually do

This section supplements section 3 (which lists framework-level gaps derived
from awesome-ebpf) with a walk through the actual BPF sources of ~18 projects
listed in that catalog. For each repo the notes below record the `SEC(...)`
attach strings, the map types, notable helpers/kfuncs, one paragraph on the
distinctive technique, and one paragraph on what hello-ebpf can pull from it
(sample, primitive, or hardening lesson). Where a project surfaces a truly
new framework gap not already listed in section 3 or in the sibling
`research-gap-catalog-rust-go.md`, it is tagged **NEW GAP**.

Repos already covered elsewhere as gap-drivers (merbridge, kyanos, ptcpdump,
Cilium, OpenTelemetry projects, PREVAIL, bpfcompat, bpftool, DeepFlow) and
the peer libraries in the Rust/Go survey (aya, libbpf-rs, cilium/ebpf,
libbpfgo) are excluded. Repos rejected in section 4 (Coroot, Pixie, Beyla,
Parca-agent) are also skipped.

### 4b.1 Summary table

Sort: category, then approx GitHub stars. Star counts fetched 2026-07-01.

| Name | Category | Stars | Primary BPF program types | Notable |
|------|----------|-------|---------------------------|---------|
| Katran | Networking / XDP L4 LB | 5.3k | `xdp`, `xdp` tail-call chain | XDP root program tail-calls into a PROG_ARRAY of independent XDPs, per-VIP LRU inner map via HASH_OF_MAPS |
| xdp-tools | Networking / XDP toolkit | 874 | `xdp` (many variants) | `bpf_xdp_flow_lookup` kfunc queries the netfilter conntrack flowtable from XDP; `xdp-trafficgen` uses `xdp` egress-side to generate packets |
| LoxiLB | Networking / K8s LB | 1.9k | `xdp`, `tc`, `sockops`, `sk_msg`, `sk_skb/stream_parser`, `sk_skb/stream_verdict`, `cgroup/connect` | Full SOCKMAP short-circuit stack with in-cluster L4 acceleration |
| Retina | Networking / K8s observability | 3.1k | `tc classifier`, `kprobe`, `kretprobe`, `fexit`, `tracepoint/tcp/tcp_retransmit_skb`, `iter/tcp`, `iter/udp` | Windows-aware Kubernetes DPI/observer with `fexit` on `__nf_conntrack_confirm` |
| SkyWalking Rover | Observability / APM | 236 | `perf_event`, `uprobe`/`uretprobe` on `SSL_read`/`SSL_write` and Go TLS, `kprobe/tcp_connect`, tracepoints | Full uprobe menu across OpenSSL, BoringSSL, Node.js, and Go for TLS plaintext capture |
| Falco (libs) | Security / syscall audit | 312 | `tp_btf/*` (many), `iter/task`, `iter/task_file`, `raw_tp` | Modern-BPF driver uses BTF-typed tracepoints, PROG_ARRAY tail-call chains for large sched_process_exec pipelines, and `iter/task_file` to snapshot fd tables |
| Tetragon | Security / runtime enforcement | 4.8k | `lsm/*`, `kprobe/*`, `fentry`, `fexit`, `raw_tp`, `uprobe`, `usdt`, `tracepoint`, `cgroup` | "Generic" families of programs whose exact hook is patched in at load time from userspace policy JSON; enforcer uses `bpf_send_signal` and `bpf_override_return` |
| Tracee | Security / forensics | 4.5k | ~146 distinct `SEC(...)`: `kprobe`, `kretprobe`, `raw_tracepoint/*`, `lsm/file_open`, `cgroup_skb/*` | Single 12k-line `tracee.bpf.c` with dispatcher-per-event; uses ARENA maps for large per-event scratch |
| inspektor-gadget | Container / K8s | 2.9k | `tracepoint/syscalls/*`, `uprobe:libc:pthread_mutex_lock`, `uprobe:libcuda:cuMemAlloc_v2`, `iter/tcp`, `iter/udp`, `lsm/*` (auto-generated), `classifier`, `kprobe/fanotify_handle_event`, `kprobe/fsnotify_insert_event`, `kprobe/__scm_send` | OCI-packaged BPF "gadgets" per capability; LSM gadget uses a `FOR_EACH_LSM_HOOK(F)` macro to auto-generate ~50 LSM programs from a single source |
| Bombini | Security / Aya-Rust XDR | 52 | `#[lsm(hook = ...)]`, `#[btf_tracepoint(function = "io_uring_submit_req")]`, `#[kprobe]` | Rust attribute macros over Aya; monitors io_uring submissions and BPF-on-BPF policy (LSM `bpf_prog_load`) |
| ebpfkit | Security / offensive | 851 | `xdp/ingress/http_action`, `classifier/egress`, `classifier/egress_dispatch`, `kprobe/security_bprm_committed_creds`, `kprobe/do_exit` | XDP-parsed HTTP router used as a covert C2; forges HTTP replies inline with `bpf_xdp_adjust_tail` + `bpf_csum_diff` |
| Bad BPF | Security / educational | 692 | `tp/syscalls/sys_enter_read` + `sys_exit_read`, `fentry/__x64_sys_openat`, `tp/syscalls/sys_enter_getdents64` + `sys_exit_getdents64` | Uses `bpf_probe_write_user` to overwrite `/etc/sudoers` in the read buffer between syscall entry and exit; getdents pair edits directory listings mid-syscall |
| SCX | Scheduler / sched_ext | 2.1k | `struct_ops.s/sched_ext_ops` (as `SCX_OPS_DEFINE`), `tp_btf/cgroup_attach_task`, `?kprobe/nvidia_open`, `syscall` | GPU-aware scheduling: optional (`?kprobe`) NVIDIA-driver kprobes feed layer classification |
| retsnoop | Debug / tracing | 302 | `fentry`, `fexit`, `?kprobe`, `?kretprobe`, `?raw_tp`, `?tp` | Mass-attaches thousands of fentry/fexit points across a call graph; uses `bpf_get_branch_snapshot` for LBR captures |
| Katran (see above) | | | | |
| GhostScope | Debug / userspace tracer | 182 | `uprobe`, `uretprobe` (compiled from DWARF-aware DSL) | Compiles a printf-like source-line DSL through its own LLVM-backed BPF codegen; DWARF variable location resolution happens client-side, then the compiler emits `bpf_probe_read_user` chains |
| rbperf | Profiler / Ruby | 124 | `perf_event`, tail-called `perf_event` sub-programs | Ruby VM stack unwinder: per-Ruby-version offsets in ARRAY map, walks `rb_control_frame_t` chain via bounded tail-calls |
| oryx | Tool / TUI sniffer | 2.5k | `classifier` (tc) via `aya-ebpf` | Pure-Rust in-kernel L2..L4 parser with per-protocol filter Arrays and per-IPv4/IPv6 blocklist maps |
| harpoon | Tool / seccomp profiling | 177 | `uprobe/enter_function`, `uprobe/exit_function`, `tracepoint/raw_syscalls/sys_enter` | Wraps a target function in an entry/exit uprobe pair to correlate syscall traffic against a specific call frame, producing a seccomp allow-list |

### 4b.2 Per-repo entries

#### 4b.2.1 Katran — https://github.com/facebookincubator/katran

- One-line: layer-4 XDP load balancer, Meta's open-source datapath.
- Program types: `SEC("xdp")` root program in `xdp_root.c`; the real work
  lives in `balancer.bpf.c` whose SEC is set at compile time via a
  `PROG_SEC_NAME` macro (still `xdp`). `xdp_pktcntr.c` also `xdp`.
- Map types: `BPF_MAP_TYPE_PROG_ARRAY` (root dispatch), `BPF_MAP_TYPE_HASH`
  (VIPs, real-servers), `BPF_MAP_TYPE_LRU_HASH` + `BPF_MAP_TYPE_LRU_PERCPU_HASH`
  (connection tables), `BPF_MAP_TYPE_ARRAY_OF_MAPS` and
  `BPF_MAP_TYPE_HASH_OF_MAPS` for per-VIP inner LRU maps, `BPF_MAP_TYPE_LPM_TRIE`
  (prefix ACLs), `BPF_MAP_TYPE_PERCPU_ARRAY` (stats).
- Distinctive helpers: `bpf_get_smp_processor_id`, jhash from
  `linux_includes/jhash.h`, custom checksum-diff in `csum_helpers.h`, IPIP/GUE
  encap in `pckt_encap.h`.
- Distinctive technique: the root XDP program tail-calls into three
  entries in a `PROG_ARRAY` in an unrolled loop; each entry is an
  independently-managed XDP program (main balancer, health checker,
  packet counter). This is the canonical pattern for hot-swapping a
  datapath component without atomically re-attaching XDP — you just
  update one slot in the root PROG_ARRAY. The balancer itself keeps
  per-VIP inner LRU maps looked up through `HASH_OF_MAPS`, so a
  new VIP allocation is a userspace map creation plus one outer
  map update, not a program reload.
- What hello-ebpf could learn: hello-ebpf already exposes PROG_ARRAY
  and tail calls (parity), but there is no sample of the "root XDP
  dispatcher + swappable inner programs" pattern; a
  `KatranStyleRootXDP.java` sample plus a `HASH_OF_MAPS` /
  `ARRAY_OF_MAPS` map-of-maps wrapper would land two techniques.
  **NEW GAP**: framework has no `BPFMapOfMaps` wrapper class today
  (`MapTypeId` lists them but no `BPFHashOfMaps<K, InnerMap>` exists).

#### 4b.2.2 xdp-tools — https://github.com/xdp-project/xdp-tools

- One-line: reference XDP utility suite maintained by the XDP project
  (`xdp-loader`, `xdp-filter`, `xdp-forward`, `xdp-trafficgen`, `xdp-dump`).
- Program types: all `SEC("xdp")`; separate object files for each filter
  flavour (`xdpfilt_alw_tcp.c`, `xdpfilt_dny_udp.c`, ...). `xdp-forward` ships
  `xdp_forward.bpf.c` (FIB-lookup based router) plus `xdp_flowtable.bpf.c`
  (netfilter flowtable offload).
- Map types: `BPF_MAP_TYPE_DEVMAP_HASH` (for the router), `BPF_MAP_TYPE_HASH`,
  `BPF_MAP_TYPE_ARRAY`.
- Distinctive helpers/kfuncs: `bpf_fib_lookup` (FIB routing table lookup
  from XDP) and `bpf_xdp_flow_lookup` — a kfunc that consults the
  netfilter conntrack flowtable to short-circuit already-tracked flows
  in XDP. Also `bpf_ktime_get_coarse_ns`, `bpf_csum_diff`, `bpf_redirect`,
  and `bpf_spin_lock`/`bpf_spin_unlock` (used inside per-flow counters).
- Distinctive technique: `xdp_flowtable.bpf.c` calls `bpf_xdp_flow_lookup(ctx, &tuple, &opts, sizeof(opts))`,
  reads `dir` from the returned tuplehash with `BPF_CORE_READ_BITFIELD_PROBED`,
  and either fast-forwards or falls through to the normal FIB path. This
  is one of the few XDP samples that touches conntrack directly.
  `xdp-trafficgen` inverts the usual XDP direction: it uses XDP on egress
  to hand-crafted synthetic packets, a mode most tutorials never mention.
- What hello-ebpf could learn: (a) a `bpf_fib_lookup` binding and a
  "router-on-XDP" sample. (b) A `bpf_xdp_flow_lookup` binding plus a
  "flowtable-fast-path" sample. **NEW GAP**: no `bpf_fib_lookup` or
  `bpf_xdp_flow_lookup` binding in
  `/Users/i560383_1/code/experiments/hello-ebpf/bpf/src/main/java/me/bechberger/ebpf/runtime/helpers/`
  today; both are big multipliers for anyone building a real router.

#### 4b.2.3 LoxiLB — https://github.com/loxilb-io/loxilb-ebpf

- One-line: eBPF-based cloud-native L4 load-balancer for
  Kubernetes/Edge/Telco.
- Program types: `SEC("xdp")` in `llb_xdp_main.c`, `SEC("classifier")` in
  `llb_ebpf_main.c` (TC egress), plus a socket-mesh stack:
  `SEC("sockops")` (`llb_kern_sockmap.c`), `SEC("sk_msg")`
  (`llb_kern_sockdirect.c`), `SEC("sk_skb/stream_parser")` and
  `SEC("sk_skb/stream_verdict")` (`llb_kern_sockstream.c`), and
  `SEC("cgroup/connect")` (`llb_kern_sock.c`).
- Map types: `BPF_MAP_TYPE_SOCKHASH` for the socket-mesh redirect,
  `BPF_MAP_TYPE_ARRAY` for conntrack, plus various per-flow tables.
- Distinctive helpers: `bpf_sock_hash_update` (from `sockops` hook into
  SOCKHASH), byte-order helpers.
- Distinctive technique: LoxiLB is the clearest single-repo demonstration
  of the "SOCKMAP short-circuit" pattern flagged as gap 3.1.2 in the
  prior awesome-ebpf pass. It composes XDP (WAN-side), TC (LAN-side),
  and the full sockops/sk_msg/sk_skb/cgroup/connect quartet so that in-node
  service-to-service traffic bypasses the network stack. The parser is a
  `sk_skb/stream_parser` — very few open projects use that section.
- What hello-ebpf could learn: LoxiLB is the reference implementation to
  copy when the SOCKMAP gap (3.1.2) is closed. It also strengthens the
  case for `sk_skb/stream_parser`, which was not called out separately
  in section 3. **NEW GAP**: `stream_parser`/`stream_verdict` are a
  distinct attach type (`BPF_SK_SKB_STREAM_PARSER`/`_VERDICT`) not
  covered by the generic sk_skb entry in the gap list; parsers run on
  every skb and need to return a frame length. Worth a separate sample.

#### 4b.2.4 Retina — https://github.com/microsoft/retina

- One-line: Microsoft's distributed Kubernetes network observer.
- Program types: `SEC("classifier_host_ingress")` + egress and endpoint
  variants for the packet parser; `SEC("kprobe/__nf_conntrack_confirm")`
  and matching `SEC("fexit/__nf_conntrack_confirm")` for conntrack;
  `SEC("kprobe/inet_csk_accept")` + `fexit`, `SEC("kprobe/nf_hook_slow")`,
  `SEC("kprobe/nf_nat_inet_fn")`, `SEC("kprobe/tcp_v4_connect")`;
  `SEC("tracepoint/tcp/tcp_retransmit_skb")`; `SEC("iter/tcp")` and
  `SEC("iter/udp")` for socket enumeration.
- Map types: `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_PERCPU_HASH`,
  `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (retransmits), `BPF_MAP_TYPE_LRU_HASH`
  (conntrack entries), `BPF_MAP_TYPE_RINGBUF`.
- Distinctive technique: `_cprog/drop_reason.c` demonstrates the
  "kprobe + fexit on the same function" pattern — kprobe captures the
  incoming skb pointer, fexit captures the disposition. Retina then
  emits a `PERF_EVENT_ARRAY` sample keyed by drop reason. The
  `iter/tcp`/`iter/udp` programs snapshot socket state on demand.
- What hello-ebpf could learn: Retina is a Microsoft-maintained
  production-grade example of the OTel-Network kprobe recipe called out
  in section 2.7, plus the iterator use-case from 3.1.6, plus the
  perf-event-array from 2.6 — three gaps in a single repo. It's the
  canonical "network observability sample" template to port once those
  are landed.

#### 4b.2.5 SkyWalking Rover — https://github.com/apache/skywalking-rover

- One-line: Apache SkyWalking's eBPF profiler + metrics collector for
  cloud services.
- Program types: `SEC("perf_event")` for on-CPU / off-CPU sampling
  (`oncpu.c`, `offcpu.c`); `SEC("uprobe/ssl_read")`, `SEC("uprobe/ssl_write")`,
  and matching uretprobes for OpenSSL; `SEC("uprobe/go_tls_read")` +
  friends for Go TLS; `SEC("kprobe/tcp_connect")`, `SEC("kprobe/ip4_datagram_connect")`,
  `SEC("kretprobe/sock_alloc")`, and `SEC("tracepoint/syscalls/sys_enter_accept")`
  etc. for socket lifecycle.
- Map types: RINGBUF, HASH, PERCPU_ARRAY, PROG_ARRAY.
- Distinctive helpers: `bpf_get_stack` (used by the profiler for kernel
  and user stack capture).
- Distinctive technique: the TLS interception directory (`bpf/accesslog/tls/`)
  covers OpenSSL, BoringSSL (via node_tls.c), and Go all in one project,
  each with its own uprobe pair; because Go's TLS uses stack-passed
  argument conventions rather than the C ABI, `go_tls.c` reads args off
  the goroutine stack via `bpf_probe_read_user` on `sp+offset`. It is
  currently the widest open example of "TLS uprobe fingerprint per
  runtime" — a superset of Kyanos's coverage.
- What hello-ebpf could learn: a direct source to consult when landing
  the SSL/TLS uprobe sample flagged as gap 3.1.7. The Go TLS variant in
  particular shows how to handle non-C ABIs from Java bindings — a
  general lesson for uprobes on Go, Rust with panic ABI, or Swift.

#### 4b.2.6 Falco libs (modern_bpf driver) — https://github.com/falcosecurity/libs

- One-line: Falco's syscall-audit driver, in the "modern_bpf" flavour
  (CO-RE, no kernel module).
- Program types: mostly `SEC("tp_btf/sys_enter")`, `SEC("tp_btf/sys_exit")`,
  `SEC("tp_btf/sched_process_exec")`, `SEC("tp_btf/sched_process_exit")`,
  `SEC("tp_btf/sched_process_fork")`, `SEC("tp_btf/sched_switch")`,
  `SEC("tp_btf/signal_deliver")`, `SEC("tp_btf/page_fault_kernel")`,
  `SEC("tp_btf/page_fault_user")`; iterators
  `SEC("iter/task")`, `SEC("iter/task_file")`.
- Map types: RINGBUF, PROG_ARRAY (for `T1_SCHED_PROC_EXEC`,
  `T2_SCHED_PROC_EXEC` tail-call chains), ARRAY, ARRAY_OF_MAPS.
- Distinctive technique: uses BTF-typed `tp_btf` sections rather than
  raw tracepoints — the verifier gets stronger type information and
  performance is comparable to `raw_tp`. Very long argument-collection
  paths (sched_process_exec builds up argv, envp, cwd, cmdline, exe
  path, mount info) are split across three tail-called programs via
  PROG_ARRAY (`T1`, `T2` — see `extra_sched_proc_exec_calls`). Uses
  `iter/task_file` to walk a task's `fd_array` at snapshot time.
- What hello-ebpf could learn: hello-ebpf attaches raw tracepoints
  but has no first-class `tp_btf` support with the associated
  BTF-context typing. Adding `@BTFTracepoint("sched_process_exec")` and
  generating typed contexts from vmlinux BTF would give Java programs
  the same performance/safety win.
  **NEW GAP**: `tp_btf` attach type wrapper.

#### 4b.2.7 Tetragon — https://github.com/cilium/tetragon

- One-line: Cilium's Kubernetes-aware runtime security observer +
  enforcer.
- Program types: family of "generic" programs whose true attach hook is
  picked at load time from a `TracingPolicy` CRD:
  `bpf_generic_kprobe.c`, `bpf_generic_retkprobe.c`, `bpf_generic_fentry.c`,
  `bpf_generic_fexit.c`, `bpf_generic_rawtp.c`, `bpf_generic_tracepoint.c`,
  `bpf_generic_uprobe.c`, `bpf_generic_retuprobe.c`, `bpf_generic_usdt.c`,
  `bpf_generic_lsm_core.c`, `bpf_generic_lsm_ima_bprm.c`,
  `bpf_generic_lsm_ima_file.c`, `bpf_generic_lsm_output.c`. Plus fixed
  probes: `bpf_execve_event.c`, `bpf_exit.c`, `bpf_fork.c`, `bpf_cgroup.c`,
  `bpf_enforcer.c`.
- Map types: heavy use of `PROG_ARRAY`, `HASH`, `LRU_HASH`, `LPM_TRIE`
  for address filters, `HASH_OF_MAPS` for policy-scoped inner maps,
  `TASK_STORAGE`.
- Distinctive helpers: `bpf_send_signal` (kill target task on policy
  violation), `bpf_override_return` (fail syscalls without killing the
  task), IMA integration via `bpf_ima_inode_hash`.
- Distinctive technique: the "generic" model is remarkable —  a single
  BPF ELF can implement any kprobe/uprobe/LSM policy by consulting
  `argfilter_maps`, `string_maps`, `addr_lpm_maps`, and `mbset` from
  userspace-populated policy state, so tetragon reuses one program
  across many hooks without recompilation. The enforcer's terminate
  paths are the only widely-shipped example of `bpf_send_signal` +
  `bpf_override_return` combined; policy authors get "kill and fail"
  as a runtime action.
- What hello-ebpf could learn: (a) the runtime-configurable
  probe pattern — hello-ebpf currently generates one BPF program per
  Java method. A "generic probe" template driven by data would let
  policy-style users add rules without recompilation. (b) enforcement
  helper bindings: `bpf_send_signal(sig)` and `bpf_override_return(rc)`
  are absent from `me.bechberger.ebpf.runtime.helpers.BPFHelpers`. Both
  small. **NEW GAP**: no `bpf_send_signal`/`bpf_override_return`
  helper binding today.

#### 4b.2.8 Tracee — https://github.com/aquasecurity/tracee

- One-line: Aqua Security's runtime-forensics engine.
- Program types: 146 unique `SEC(...)` strings in a single 12k-line
  `tracee.bpf.c`. Dominant families: `kprobe/*` (~80 syscall entry and
  helper security hooks), `kretprobe/*`, `raw_tracepoint/*`
  (sched_process_exec/exit/fork/free/switch, cgroup_mkdir, module_load,
  send_bin_tp), `lsm/file_open`, `cgroup_skb/ingress` and `cgroup_skb/egress`.
- Map types: `HASH`, `LRU_HASH`, `PERCPU_ARRAY`, `PROG_ARRAY`,
  `PERF_EVENT_ARRAY` (kept for backwards compat with pre-ringbuf kernels),
  `LPM_TRIE`, `STACK_TRACE`, `HASH_OF_MAPS`, `ARENA`.
- Distinctive technique: single-object monolithic BPF with a
  "dispatcher-per-event" style — one raw tracepoint like
  `sched_process_exec_event_submit_tail` receives the tail-called
  continuation. Uses `BPF_MAP_TYPE_ARENA` for large per-event scratch
  space (paths, argv reconstruction) rather than the older PERCPU_ARRAY
  scratch pattern.
- What hello-ebpf could learn: hello-ebpf already has ARENA support
  (parity), but Tracee's use of ARENA for per-event scratch is a
  documented reference pattern that could feed a sample. Also: Tracee
  ships both `PERF_EVENT_ARRAY` and RINGBUF paths side-by-side selected
  at load time based on kernel version — a real-world example of the
  runtime kernel-feature probe from gap 3.2.3.

#### 4b.2.9 inspektor-gadget — https://github.com/inspektor-gadget/inspektor-gadget

- One-line: Kubernetes-native BPF tool collection where each gadget is
  packaged as an OCI image containing a compiled BPF ELF plus metadata.
- Program types (sampled across gadgets):
  `SEC("tracepoint/syscalls/sys_enter_open")` +
  `SEC("tracepoint/syscalls/sys_enter_openat")` and exit variants
  (`trace_open`); `SEC("uprobe/libc:pthread_mutex_lock")` +
  `SEC("uprobe/libc:pthread_mutex_unlock")` and
  `SEC("tracepoint/sched/sched_process_exit")` for deadlock detection;
  `SEC("uprobe/libcuda:cuMemAlloc_v2")` and ~5 sibling variants for
  CUDA memory tracking; `SEC("iter/tcp")`+`SEC("iter/udp")` for socket
  snapshots; `SEC("kprobe/fanotify_handle_event")`, `SEC("kprobe/inotify_handle_event")`,
  `SEC("kprobe/fsnotify_insert_event")` for `fsnotify`;
  `SEC("kprobe/__scm_send")` + tracepoints for the `fdpass` gadget;
  `SEC("classifier/ingress/main")` and `classifier/egress/main` for `tcpdump`;
  many `SEC("lsm/...")` from a `FOR_EACH_LSM_HOOK(F)` macro.
- Map types: `HASH`, `STACK_TRACE` (deadlock cycles), `PERCPU_ARRAY`,
  `PERF_EVENT_ARRAY`, RINGBUF.
- Distinctive technique: (a) OCI-packaged gadgets — the BPF ELF ships
  as an OCI image with a `gadget.yaml` metadata file; the runner
  loads directly from a registry. (b) The `trace_lsm` gadget expands
  `FOR_EACH_LSM_HOOK(F)` over ~50 LSM hook names to produce a program
  per hook in a single source file. (c) `fdpass` traces socket
  file-descriptor passing via `SCM_RIGHTS`, an unusual angle almost no
  other tool covers.
- What hello-ebpf could learn: (a) the OCI-image distribution model is
  the emerging standard for shipping BPF tools; hello-ebpf's samples
  are jar-embedded and cannot be pulled by non-JVM runners.
  **NEW GAP**: OCI-image packaging of compiled BPF programs +
  Java-side registry loader. (b) the `SCM_RIGHTS` fd-pass sample is a
  security-relevant edge that would round out the LSM demo set.

#### 4b.2.10 Bombini — https://github.com/bombinisecurity/bombini

- One-line: eBPF security monitor written in Rust on Aya.
- Program types (via Aya attribute macros, not raw `SEC`):
  `#[lsm(hook = "file_open")]`, `#[lsm(hook = "mmap_file")]`,
  `#[lsm(hook = "sb_mount")]`, `#[lsm(hook = "path_unlink")]`, etc.;
  `#[lsm(hook = "bpf_prog_load")]` and `#[lsm(hook = "bpf_map_create")]`
  in the `kernelmon` detector for BPF-on-BPF policy;
  `#[btf_tracepoint(function = "io_uring_submit_req")]` in `io_uringmon`.
- Map types: `LruHashMap`, `HashMap`, `LpmTrie` (per-binary prefix
  filters).
- Distinctive technique: monitoring `io_uring` submissions is rare —
  most security tools miss io_uring because it bypasses `sys_enter_*`
  tracepoints. Bombini attaches to the internal `io_uring_submit_req`
  BTF tracepoint. The BPF-on-BPF LSM detector (`kernelmon`) is the
  cleanest sample of using LSM to gate BPF program loads, which is
  itself a hardening measure against BPF rootkits.
- What hello-ebpf could learn: (a) the `io_uring_submit_req` BTF
  tracepoint is a first-order security-observability gap almost no one
  covers. (b) A "policy on BPF program loads" LSM sample would be a
  useful pair to the existing `Firewall.java` LSM sample. (c) The
  Rust attribute-macro style of `#[lsm(hook = ...)]` is a direct
  analogue of what a Java `@LSM(hook = "file_open")` annotation could
  look like — an ergonomics reference for the Java side.

#### 4b.2.11 ebpfkit — https://github.com/Gui774ume/ebpfkit

- One-line: research eBPF rootkit; last commit 2023 but the techniques
  are still cited widely.
- Program types: `SEC("xdp/ingress/http_action")` (in-XDP HTTP command
  channel), `SEC("classifier/egress")` and
  `SEC("classifier/egress_dispatch")` (TC-based exfil), plus
  `SEC("kprobe/security_bprm_committed_creds")`, `SEC("kprobe/do_exit")`
  for process lifecycle, `SEC("kprobe/do_getdents")`-family for file
  hiding.
- Map types: `LRU_HASH`, `PERCPU_ARRAY`, PROG_ARRAY (HTTP router).
- Distinctive helpers: `bpf_xdp_adjust_tail` + `bpf_csum_diff` used to
  synthesize an HTTP response inline from XDP without ever letting the
  packet reach the network stack.
- Distinctive technique: the XDP program parses inbound HTTP, matches
  a magic URL via a PROG_ARRAY-indexed router, then either rewrites the
  packet in-place (bidirectional command channel) or returns a canned
  HTTP response without any userspace involvement. Filesystem hides
  operate on the read buffer via `bpf_probe_write_user` between
  syscall entry and exit — same technique as Bad BPF but industrial.
- What hello-ebpf could learn: not a sample to ship, but a "capabilities
  and abuse" reference. `bpf_probe_write_user` is one of the reasons
  the kernel gates writable-uprobes behind CAP_SYS_ADMIN, and hello-ebpf
  should document that fact prominently. `bpf_xdp_adjust_tail` +
  `bpf_csum_diff` are both worth binding for legitimate XDP-response
  patterns (health checkers, ICMP replies).

#### 4b.2.12 Bad BPF — https://github.com/pathtofile/bad-bpf

- One-line: DEF CON 29 collection of malicious eBPF programs.
- Program types: `sudoadd.bpf.c` uses `SEC("tp/syscalls/sys_enter_openat")`
  + `sys_enter_read` + `sys_exit_read` + `sys_exit_close` +
  `sys_exit_openat`; `textreplace2.bpf.c` uses `SEC("fentry/__x64_sys_openat")`,
  `SEC("fexit/__x64_sys_openat")`, `SEC("fentry/__x64_sys_read")`,
  `SEC("fexit/__x64_sys_read")`, `SEC("fexit/__x64_sys_close")`;
  `pidhide.bpf.c` uses `SEC("tp/syscalls/sys_enter_getdents64")` +
  `sys_exit_getdents64`.
- Distinctive helpers: `bpf_probe_write_user` — writes into userspace
  memory between a syscall's entry and exit tracepoints so the calling
  process sees modified data. `sudoadd` waits for a target process to
  read `/etc/sudoers`, then overwrites the returned buffer to add a
  privileged entry; `pidhide` edits the `getdents64` linked list to
  remove a target PID from `ls /proc`; `textreplace2` rewrites content
  in arbitrary file reads.
- Distinctive technique: the whole collection is a study in "same-syscall
  entry/exit pairing", using a per-tid HASH map to correlate entry-side
  arguments with the exit-side buffer. This is a common pattern in
  observability tools but Bad BPF documents it most cleanly.
- What hello-ebpf could learn: `bpf_probe_write_user` is not currently
  bound in hello-ebpf. Given the abuse potential, the right move is
  probably an explicit "writable probes" sample under
  `bpf-samples/.../security/` with a large warning comment, mirroring
  how libbpf docs treat the helper. **NEW GAP**: `bpf_probe_write_user`
  binding, gated behind an opt-in flag.

#### 4b.2.13 sched-ext/scx — https://github.com/sched-ext/scx

- One-line: production sched_ext (BPF struct_ops) scheduler collection
  — bpfland, layered, lavd, rusty, mitosis, chaos, etc.
- Program types: `SCX_OPS_DEFINE(...)` expands to `SEC("struct_ops.s/sched_ext_ops")`
  members; plus `SEC("tp_btf/cgroup_attach_task")`,
  `SEC("tp_btf/task_rename")` for cgroup/name tracking;
  `SEC("?kprobe/nvidia_open")`, `SEC("?kprobe/nvidia_mmap")`,
  `SEC("?kprobe/nvidia_poll")` (optional kprobes, only attached if the
  NVIDIA driver is loaded); `SEC("syscall")` programs for control-plane
  interactions.
- Map types: `TASK_STORAGE` (per-task scheduler state, e.g. `task_ctxs`),
  `ARRAY` (cpu_ctxs, node_data, llc_data), `HASH`, `PERCPU_ARRAY`.
- Distinctive technique: (a) `SEC("?kprobe/...")` — the `?` prefix
  means "optional attach" via libbpf's AUTOLOAD flag; the scheduler
  quietly no-ops NVIDIA GPU accounting on systems without the driver.
  (b) scx_layered uses tp_btf on `cgroup_attach_task` to correlate
  cgroup moves with layer classification. (c) `SEC("syscall")` programs
  are called explicitly from userspace with `bpf_prog_test_run` to
  perform batched map updates atomically inside a single BPF invocation.
- What hello-ebpf could learn: hello-ebpf already ships sched_ext
  struct_ops support (parity with scx C interface). But `SEC("?...")`
  optional attach and `SEC("syscall")` programs are two attach modes
  not yet surfaced.
  **NEW GAP**: no way to mark a hello-ebpf program as
  optional-attach today; **NEW GAP**: no `SEC("syscall")` program
  type wrapper for userspace-invoked helpers.

#### 4b.2.14 retsnoop — https://github.com/anakryiko/retsnoop

- One-line: kernel error call-stack investigator (Andrii Nakryiko).
- Program types: mass-attached `SEC("fentry")` and `SEC("fexit")` (and
  `?kprobe`/`?kretprobe`/`?raw_tp`/`?tp` as fallback attach flavours) —
  hundreds of functions at once.
- Map types: `HASH` (ip_to_id), custom `.data.lbrs` / `.data.running`
  section arrays for LBR capture buffers.
- Distinctive helpers: `bpf_get_branch_snapshot` — captures the CPU's
  Last Branch Record (LBR) from within a probe, giving retsnoop
  hardware-recorded call-history without stack walking. Also
  `bpf_get_func_ip` with runtime-detected fallback for older kernels.
- Distinctive technique: at startup retsnoop calibrates whether
  `bpf_get_func_ip` and `bpf_cookie` exist on the current kernel and
  patches its BPF programs accordingly via `.data.*` sections
  (essentially "runtime feature detection through configurable
  globals"). This lets one ELF work across 5.16 through the newest
  kernels with no CO-RE fallbacks needed.
- What hello-ebpf could learn: (a) `bpf_get_branch_snapshot`
  binding — no other framework covers LBR reads.
  **NEW GAP**: LBR helper. (b) The "config-via-`.data`-globals + libbpf
  variable-substitution" pattern is a lightweight alternative to full
  CO-RE relocations; hello-ebpf's `@BuiltinBPFFunction` templating and
  its plugin's DSQ_ID placeholder are analogues but a general "runtime
  feature switch via const volatile" mechanism is not documented.

#### 4b.2.15 GhostScope — https://github.com/swananan/ghostscope

- One-line: DWARF-aware eBPF tracer that compiles a printf-style DSL
  to uprobes.
- Program types: `uprobe` and `uretprobe`, dynamically generated from a
  DWARF-informed compiler.
- Distinctive technique: GhostScope carries its own LLVM-backed BPF
  code generator (`ghostscope-compiler/src/ebpf/codegen`, alongside
  DWARF resolution in `ghostscope-dwarf`). Given a script like
  `trace file.c:120 { print req.body }` it walks DWARF to find the
  variable's location expression, then emits a bounded chain of
  `bpf_probe_read_user` and register reads at that source-line's
  uprobe offset. Supports Linux 4.4+ (very wide compatibility) and
  ships an interactive TUI plus a `--script` CLI for AI agents.
- What hello-ebpf could learn: a compelling reference for a "Java
  source-line probe" story where hello-ebpf could compile a
  Java DSL against DWARF or against JVMTI-recovered debug info to
  emit uprobes. The DWARF-location-expression side is arguably the
  hardest part; ghostscope's `dwarf_bridge.rs` and
  `expression_plan.rs` show a working design.

#### 4b.2.16 rbperf — https://github.com/javierhonduco/rbperf

- One-line: Ruby VM sampling profiler and tracer (last touched 2024
  but still the reference Ruby unwinder outside Parca).
- Program types: `SEC("perf_event")`; the entry program tail-calls a
  chain of `perf_event` sub-programs via a PROG_ARRAY.
- Map types: RINGBUF (or PERF_EVENT_ARRAY — the type field is patched
  from userspace before load), `HASH` (`pid_to_rb_thread`),
  `HASH` (`frame_table` interning `RubyFrame` structs to u32 ids),
  `ARRAY` (`version_specific_offsets` mapping Ruby version → struct
  offsets), `PROG_ARRAY` (unwinder tail-call chain), `PERCPU_ARRAY`
  (`global_state` for per-CPU sample buffer).
- Distinctive technique: (a) userspace patches the events map's `type`
  field between RINGBUF and PERF_EVENT_ARRAY at load time based on
  kernel — very neat runtime-feature-degradation pattern.
  (b) per-Ruby-version offsets are read out of `libruby` at userspace
  startup and pushed into a small ARRAY, then the BPF unwinder walks
  `rb_control_frame_t` via `bpf_probe_read_user` with `frame->pc` and
  `frame->iseq->body->location` reads.
- What hello-ebpf could learn: rbperf is a smaller-scale template for
  the interpreter-tracer gap (2.2 in the prior catalog). Even more
  practically, the "swap map type at load time" trick is a light-touch
  way to close the ringbuf vs perf-event-array gap without duplicating
  code — the map header is patched before `bpf_object__load`.
  **NEW GAP**: hello-ebpf has no API to mutate a map's declared type
  before load, so a program that wanted to fall back from RINGBUF to
  PERF_EVENT_ARRAY would need two separate `@BPFMap` declarations.

#### 4b.2.17 oryx — https://github.com/pythops/oryx

- One-line: TUI-based network sniffer with in-kernel filtering.
- Program types: `#[classifier]` TC classifier written in Rust with
  aya-ebpf.
- Map types (Aya style): `RingBuf`, `Array` (protocol filters,
  direction filter), `HashMap<u32, [u16; N]>` for IPv4 blocklist,
  `HashMap<u128, ...>` for IPv6 blocklist.
- Distinctive technique: a full L2/L3/L4 protocol parser (Ethernet,
  ARP, IPv4, IPv6, TCP, UDP, ICMP, IGMP, SCTP) implemented as
  bounded pointer-arithmetic reads inside a single TC classifier
  program, plus a per-user firewall (block ranges pushed from userspace
  via a HashMap). Uses `#[unsafe(no_mangle)] static PID_HELPER_AVAILABILITY: u8 = 0`
  as a runtime feature flag consulted from BPF.
- What hello-ebpf could learn: strong analogue to hello-ebpf's
  `BasePacketParser.java`. Notable is that oryx separates parsing from
  filtering — every packet is parsed, and only then are filter Arrays
  consulted. This "parse once, filter many" split would be a clean
  refactor for hello-ebpf's XDP samples (`XDPPacketFilter.java`,
  `Firewall.java`).

#### 4b.2.18 harpoon — https://github.com/alegrey91/harpoon

- One-line: function-scoped syscall tracer, used to build seccomp
  profiles.
- Program types: `SEC("uprobe/enter_function")` + `SEC("uprobe/exit_function")`
  (attached to a user-picked symbol), `SEC("tracepoint/raw_syscalls/sys_enter")`.
- Map types: `HASH` (per-tid in-target-function flag), `ARRAY` (target
  syscall bitmap), `PERF_EVENT_ARRAY`.
- Distinctive technique: attach uprobes at function entry and exit
  to flip a "we're inside function F" flag in a per-tid HASH, then let
  the raw_syscalls tracepoint gate its output on that flag. Result: a
  seccomp allow-list that lists only syscalls actually reached when
  the target function is on the call stack. Simple but a specific,
  common-enough pattern that most people re-invent.
- What hello-ebpf could learn: a natural sample idea —
  "function-scoped syscall tracer" — that pairs three primitives hello
  -ebpf already has (uprobe, tracepoint, hash map) but does not
  document the composition of. Small, high-signal addition to
  `bpf-samples/`.

### 4b.3 New gaps surfaced by the deep-dive

Cross-referenced back to the repo that surfaced them. None duplicate a gap
already in sections 2 or 3 of this file, or in
`research-gap-catalog-rust-go.md`.

1. **`BPFHashOfMaps` / `BPFArrayOfMaps` wrapper class** — surfaced by Katran
   (§4b.2.1) and used heavily in Tetragon (§4b.2.7) and Tracee (§4b.2.8).
   `MapTypeId` lists `HASH_OF_MAPS` and `ARRAY_OF_MAPS` but no wrapper
   exists. Blocks any "per-tenant inner map" pattern.
2. **`bpf_fib_lookup` and `bpf_xdp_flow_lookup` helper/kfunc bindings** —
   surfaced by xdp-tools (§4b.2.2). Blocks anyone building a real XDP
   router or a flowtable-fast-path in Java.
3. **`sk_skb/stream_parser` and `sk_skb/stream_verdict` attach types** —
   surfaced by LoxiLB (§4b.2.3). Distinct from the general sk_skb
   gap noted in §3.1.2 because the parser must return a frame length.
4. **`tp_btf` BTF-typed tracepoint attach type** — surfaced by Falco
   modern_bpf (§4b.2.6) and heavily used by SCX (§4b.2.13). Stronger
   verifier context than `raw_tracepoint`. Adding
   `@BTFTracepoint("sched_process_exec")` would give Java programs
   typed argument access.
5. **`bpf_send_signal` and `bpf_override_return` helper bindings** —
   surfaced by Tetragon (§4b.2.7, `bpf_enforcer.c`). Both required for
   any policy-enforcement sample beyond LSM-return-code denial.
6. **OCI-image packaging of compiled BPF programs** — surfaced by
   inspektor-gadget (§4b.2.9). hello-ebpf ships jar-embedded ELFs;
   an OCI push/pull path (using `oras-java` or similar) would open
   hello-ebpf samples to non-JVM runners.
7. **`bpf_probe_write_user` helper binding** — surfaced by Bad BPF
   (§4b.2.12) and ebpfkit (§4b.2.11). Not bound today; should be
   gated with an explicit opt-in given the abuse surface.
8. **`SEC("?...")` optional-attach mode and `SEC("syscall")` program
   type** — both surfaced by SCX (§4b.2.13). Optional-attach lets a
   single ELF degrade cleanly when hooks are absent; `syscall`
   programs let userspace batch map updates atomically inside a BPF
   invocation via `bpf_prog_test_run`.
9. **`bpf_get_branch_snapshot` (LBR) helper binding** — surfaced by
   retsnoop (§4b.2.14). Unique among BPF helpers in giving
   hardware-recorded call history from within a probe; unlocks
   root-cause debugging tools.
10. **Runtime-swappable map type (RINGBUF ↔ PERF_EVENT_ARRAY at load
    time)** — surfaced by rbperf (§4b.2.16). Would let hello-ebpf
    samples transparently fall back on kernels without ringbuf, closing
    part of gap 2.6 without requiring a new wrapper class.

## 5. Rejected candidates

Considered and dropped:

- **BCC Python DSL / bpftrace-style DSL** — awesome-ebpf lists both, but
  building yet another DSL contradicts hello-ebpf's premise of "write eBPF
  in idiomatic Java". Peer-library survey covers this at a higher level.
- **PREVAIL user-space verifier** — a useful research reference but a
  separate multi-year project; hello-ebpf can lean on the kernel verifier.
- **eBPF-for-Windows port** — real project, but out of scope for a Linux-
  first framework.
- **`bpfilter` netfilter integration** — kernel-side feature still not
  upstreamed after years; no code to point at.
- **Rust-language interpreter unwinder** — Rust uses native frames, already
  handled by the `.eh_frame` gap in 2.1; no separate tracer needed.
- **Aya / libbpf-rs / cilium-ebpf feature parity** — explicitly excluded
  by the brief (sibling agent's scope).
- **Coroot / Pixie / Beyla / Parca full-blown APM stacks** — brief says
  cover only if OTel profiler docs reference them; the profiler README does
  not reference them by name, only by lineage. Their common denominators
  (build-id, stack unwinder, off-CPU) are already covered above.
- **Blog posts and tutorials from awesome-ebpf** — brief says do not
  include as gaps, only if they surface a missing feature. Where they do,
  they are cited under the relevant gap above.
- **Suricata / Falco / Tetragon rulesets** — high-level security products
  built on primitives hello-ebpf already exposes (LSM, kprobe). Not a
  framework gap.

## 6. Retrieval provenance

Fetched 2026-07-01:

- https://github.com/qmonnet/awesome-ebpf — README.md, full text via
  `gh api repos/qmonnet/awesome-ebpf/readme` (default branch: main).
- https://github.com/open-telemetry/opentelemetry-ebpf-profiler — top-
  level contents listing and `support/ebpf/` directory via `gh api`.
  Files enumerated: `beam_tracer.ebpf.c`, `dotnet_tracer.ebpf.c`,
  `hotspot_tracer.ebpf.c`, `perl_tracer.ebpf.c`, `php_tracer.ebpf.c`,
  `python_tracer.ebpf.c`, `ruby_tracer.ebpf.c`, `v8_tracer.ebpf.c`,
  `native_stack_trace.ebpf.c`, `off_cpu.ebpf.c`, `go_labels.ebpf.c`,
  `interpreter_dispatcher.ebpf.c`, `sched_monitor.ebpf.c`,
  `system_config.ebpf.c`, `native_stack_trace.h`. Plus `reporter/`,
  `interpreter/` (with per-runtime subdirs) and `kallsyms/`.
- https://github.com/open-telemetry/opentelemetry-network — top-level and
  `collector/kernel/` and `collector/kernel/bpf_src/` directories via
  `gh api`. Full contents of `collector/kernel/bpf_src/render_bpf.c`
  grep'd for `SEC("...")` anchors (kprobe / kretprobe set on
  `__nf_conntrack_confirm`, `tcp_connect`, `inet_csk_accept`, ...).

Hello-ebpf baseline reviewed 2026-07-01 (all under
`/Users/i560383_1/code/experiments/hello-ebpf/`):

- `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java`
- `bpf/src/main/java/me/bechberger/ebpf/bpf/map/` (full listing)
- `bpf/src/main/java/me/bechberger/ebpf/bpf/map/MapTypeId.java`
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/` (full listing)
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/CPUProfiler.java`
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/StackSymbolizer.java`
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/` (full listing +
  sched/ and demo/ subdirs).

### 6.1 Repositories fetched for section 4b (deep-dive)

All fetched 2026-07-01 via `gh api repos/<owner>/<repo>/contents/...` and
Base64-decoded. Only the specific paths grep'd for `SEC(...)` /
`BPF_MAP_TYPE_*` / helper calls are listed; a repo's full tree was not
downloaded.

- https://github.com/falcosecurity/libs — `driver/modern_bpf/programs/attached/*`
  (dispatchers, events, iterators), `driver/modern_bpf/maps/maps.h`.
- https://github.com/cilium/tetragon — `bpf/process/*.c` (execve, exit,
  fork, cgroup, enforcer, and generic_* families), `bpf/process/*.h`.
- https://github.com/aquasecurity/tracee — `pkg/ebpf/c/tracee.bpf.c`
  (12k-line monolith), `pkg/ebpf/c/maps.h`.
- https://github.com/facebookincubator/katran — `katran/lib/bpf/xdp_root.c`,
  `balancer.bpf.c`, `balancer_maps.h`, `pckt_encap.h`.
- https://github.com/loxilb-io/loxilb-ebpf — `kernel/Makefile`,
  `kernel/llb_kern_sockmap.c`, `kernel/llb_kern_sockstream.c`,
  `kernel/llb_kern_sockdirect.c`, `kernel/llb_kern_sock.c`,
  `kernel/llb_kern_ct.c`.
- https://github.com/microsoft/retina — `pkg/plugin/packetparser/_cprog/packetparser.c`,
  `pkg/plugin/dropreason/_cprog/drop_reason.c`,
  `pkg/plugin/conntrack/_cprog/conntrack.c`,
  `pkg/plugin/tcpretrans/_cprog/tcpretrans.c`.
- https://github.com/apache/skywalking-rover — `bpf/profiling/oncpu.c`,
  `bpf/accesslog/tls/openssl.c`, `bpf/accesslog/tls/go_tls.c`,
  `bpf/accesslog/syscalls/connect.c`, `bpf/accesslog/accesslog.c`.
- https://github.com/inspektor-gadget/inspektor-gadget — top-level
  `gadgets/` listing plus `trace_open/program.bpf.c`,
  `trace_lsm/program.bpf.c`, `deadlock/program.bpf.c`,
  `snapshot_socket/program.bpf.c`, `profile_cuda/program.bpf.c`,
  `fsnotify/program.bpf.c`, `fdpass/program.bpf.c`,
  `tcpdump/program.bpf.c`.
- https://github.com/bombinisecurity/bombini — `bombini-detectors-ebpf/src/bin/filemon/main.rs`,
  `.../io_uringmon/main.rs`, `.../kernelmon/main.rs`.
- https://github.com/Gui774ume/ebpfkit — `ebpf/main.c`,
  `ebpf/ebpfkit/http_action.h`, `ebpf/ebpfkit/http_router.h`,
  `ebpf/ebpfkit/tc.h`, `ebpf/ebpfkit/pipe.h`, `ebpf/ebpfkit/fs.h`.
- https://github.com/pathtofile/bad-bpf — `src/pidhide.bpf.c`,
  `src/sudoadd.bpf.c`, `src/textreplace2.bpf.c`.
- https://github.com/sched-ext/scx — `scheds/rust/scx_layered/src/bpf/main.bpf.c`.
- https://github.com/anakryiko/retsnoop — `src/mass_attach.bpf.c`,
  `src/retsnoop.bpf.c`.
- https://github.com/xdp-project/xdp-tools — `xdp-filter/` listing,
  `xdp-forward/xdp_forward.bpf.c`, `xdp-forward/xdp_flowtable.bpf.c`,
  `xdp-trafficgen/xdp_trafficgen.bpf.c`.
- https://github.com/swananan/ghostscope — `README.md`,
  `ghostscope-compiler/src/ebpf/` listing, `ghostscope-loader/src/` listing.
- https://github.com/javierhonduco/rbperf — `src/bpf/rbperf.bpf.c`.
- https://github.com/pythops/oryx — `oryx-ebpf/src/main.rs`.
- https://github.com/alegrey91/harpoon — `ebpf/ebpf.c`.
