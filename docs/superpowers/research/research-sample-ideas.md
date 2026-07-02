Research: cool sample ideas for hello-ebpf
==========================================

## Preamble

This document is an ideation drop of concrete, demoable **sample programs** that could ship in `/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/`. It is deliberately not a feature-gap list — the sibling gap-catalog documents (`research-gap-catalog-rust-go.md`, `research-gap-catalog-otel-awesome.md`) cover what hello-ebpf can't yet do; the sibling design doc (`research-gap-designs.md`) covers how to add those features. Cross-reference `research-blog-series.md` for what the "Hello eBPF" blog series has already demonstrated (Parts 1–20) so we don't re-pitch samples that are effectively already in the tree.

Selection filter applied to every entry below:

- Must exercise at least one hello-ebpf feature crisply (kprobe / uprobe / XDP / TC / LSM / ring buffer / arena / cpumask / tail call / sched_ext / struct_ops / global variable / task_local storage / cgroup / perf_event).
- Must be **demoable** — a user runs it and sees an effect they didn't have before.
- Should have a **Java-native angle** (JFR event stream, JMX MBean, Swing/Web/JavaFX UI, Spring Boot introspection, JIT tracepoints, JVM internals via uprobe) — that's what makes the sample worth writing in _this_ framework versus C or Rust.
- Aim for ~300 lines of Java or less. If it needs more, it belongs in `cookbook.md` as a tutorial.
- Reject: anything that duplicates an existing sample in `/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/` (HelloWorld, HashMapSample, RingSample, XDPPacketFilter, XDPPacketFilter2, PacketLogger, PacketCountByLength, TailCallDemo, GlobalVariableSample, Firewall, FirewallSpring, BlockHTTP, CGroupBlockHTTPEgress, CPUProfiler, StackSymbolizer, FCFSScheduler, WeightedRRSample, LotteryScheduler, TaskStorageScheduler, SampleScheduler, ChaosScheduler, LogOpenAt2Calls, MapSample, SyscallCounter, SyscallProgramDemo, TCDropEveryThirdOutgoingPacket, XDPDropEveryThirdPacket, JvmGcPauseTracer, LSMDemo, TimerDemo, ForbiddenFile*, and the sched_ext family under `samples/sched/`).

Ideas requiring hello-ebpf features that don't yet exist are flagged in the "Dependencies on unshipped features" field with a cross-reference into the gap catalog. Everything without such a flag can be built today against the current framework.

## 1. Summary table

Sorted by category, then difficulty (S = small / a weekend; M = medium / a week; L = large / a fortnight or ambitious). "Framework features" is a shortlist — most samples touch a few more incidentally.

| # | Name | Category | Difficulty | Framework features exercised | One-line pitch |
|---|------|----------|------------|------------------------------|-----------------|
| 1 | ExecSnoopJfr | Observability & tracing | S | tracepoint, ring buffer, JFR emission | Stream every `execve` in the system as a JFR event so JMC replays a process-launch timeline. |
| 2 | OpenSnoopUi | Observability & tracing | S | ksyscall, ring buffer, JavaFX table | Live file-open feed with a JavaFX filterable table — pipe-friendly and demoable in 30 seconds. |
| 3 | KillSnoopJfr | Observability & tracing | S | tracepoint on `syscalls:sys_enter_kill`, ring buffer | Records who sent SIGKILL to whom, as JFR — pairs with GC/OOM investigation notebooks. |
| 4 | SignalTracer | Observability & tracing | S | tracepoint, task_storage, ring buffer | Every signal delivered anywhere in the system; per-task histograms surfaced via JMX. |
| 5 | JavaExecArgv | Observability & tracing | M | tracepoint, per-CPU array, cpumask | Captures full `argv[]` for every `java` invocation to show classpath drift across a fleet. |
| 6 | HotThreadWatcher | Observability & tracing | M | perf_event on cycles, StackSymbolizer, JFR | Continuously picks the top-N hottest Java threads and emits `HotJavaThread` JFR events. |
| 7 | ContainerRuntimeTracer | Observability & tracing | M | LSM `bprm_check_security`, cgroup awareness | Tags each executed process with its cgroup path — Docker vs systemd origin visible in Java. |
| 8 | TcpLifeJfr | Networking & security | M | fentry on `tcp_v4_do_rcv`, sockops-style key, ring buffer | Per-connection RTT / bytes / lifetime emitted as JFR — replay in JMC alongside JVM metrics. |
| 9 | DnsLatency | Networking & security | S | XDP + tail call, ring buffer | Measures kernel-observed DNS RTT and pushes buckets to a Micrometer Prometheus registry. |
| 10 | HostSslSniffer | Networking & security | M | uprobe on `SSL_read`/`SSL_write` in libssl, ring buffer | Dumps decrypted HTTP request lines from any process using system libssl. Reads with JavaFX viewer. |
| 11 | JdkTlsSniffer | Networking & security | L | uprobe on OpenJDK `sun.security.ssl.SSLSocketImpl.write0`, ring buffer | Same idea for pure-Java TLS: bind uprobes into `libjvm`/JIT-compiled Java. Flagged as speculative. |
| 12 | LatencyMap | Networking & security | S | LPM_TRIE, XDP | XDP program keys packets by CIDR block, publishes per-CIDR latency to a Swing heat-grid. |
| 13 | SshBruteBlocker | Networking & security | M | XDP, LRU hash map, cgroup | Counts failed sshd auth (uprobe on `PAM authenticate`) and pushes offender IPs into an XDP drop map. |
| 14 | JavaContentionMap | Performance & profiling | M | uprobe on `ObjectMonitor::enter_internal`, task_storage | Every JVM lock contention event bucketed by monitor address and stack; live table via HTTP. |
| 15 | JitCompilationTracer | Performance & profiling | M | uprobe on HotSpot `Compile::Compile`, ring buffer | Shows every C1/C2 compile with duration, method name, tier. Emits JFR `JitCompileTrace` events. |
| 16 | GcRootScanTimings | Performance & profiling | L | uprobe on multiple HotSpot GC internals (`GenCollectedHeap::do_collection`), ring buffer | Sub-phase GC timings without `-XX:+PrintGCDetails` overhead. |
| 17 | JmxBackedBiolatency | Performance & profiling | S | tracepoint on block IO, JMX MBean | Classic biolatency, but the histogram is a JMX bean so any JMX dashboard picks it up. |
| 18 | JavaMallocInspector | Performance & profiling | M | uprobe on `mmap`/`munmap`, per-CPU counter | Correlates native-heap growth with Java threads to find leaks in Panama/JNI code. |
| 19 | ReadaheadStats | Performance & profiling | S | fentry on `readahead`, hash map | Ports the classic bcc `readahead` tool. Renders result as Micrometer gauges. |
| 20 | GcAwareScheduler | Scheduling & concurrency | L | sched_ext, uprobe on `libjvm`, task_local | A scheduler that de-prioritises GC threads outside of STW and boosts them during STW — auto-detects from `notify_gc_begin`. |
| 21 | JvmSafepointFairness | Scheduling & concurrency | L | sched_ext, uprobe on `SafepointSynchronize::begin` | Scheduler that grants short priority boosts to threads still spinning to reach a safepoint. |
| 22 | TypingScheduler | Scheduling & concurrency, playful | M | sched_ext, tracepoint on input events | Priority scales with keystroke rate at `input:input_report` — foreground editor stays snappy under load. |
| 23 | MusicalScheduler | Scheduling & concurrency, playful | M | sched_ext, uprobe on ALSA `snd_pcm_writei` | Chooses time slice from the tempo of currently playing audio (BPM detected in Java). |
| 24 | SprinklerScheduler | Playful / demo | S | sched_ext, JFR | Rotates 100% CPU access among cores in a fixed pattern; visualise the "sprinkler" in a Swing grid. |
| 25 | KeystrokeTimer | Playful / demo | S | tracepoint on `input:input_report`, ring buffer, Swing | Draws inter-keystroke intervals as a scrolling waveform — "shows you your typing rhythm". |
| 26 | GitHookBooster | Developer tooling | S | cgroup, uprobe, priority setter | Watches for `git` and `mvn` processes and quietly gives them nice=-5 via a task_storage flag. |
| 27 | MavenBuildProfiler | Developer tooling | M | fentry on file ops, tracepoint on process fork, JFR | Turns any `mvn install` into an interactive JFR flamegraph of "where the build actually spent time". |
| 28 | JavaHeapDumpTrigger | Developer tooling | M | LSM `file_open`, ring buffer, JMX | When any process opens `/proc/<pid>/gc.log`, kick a `HotSpotDiagnosticMXBean` heap dump. |
| 29 | ClassLoadTracer | Developer tooling / JVM introspection | M | uprobe on `SystemDictionary::resolve_or_null`, ring buffer | Every class load, from any JVM, streamed to JFR — spot classloader leaks across children. |
| 30 | JniCrossingCounter | Developer tooling / JVM introspection | S | uprobe on `JNIEnv->CallXxxMethod` symbols, per-CPU hash | Counts JNI up-calls per method-signature, flags hot boundaries. |
| 31 | JfrLiveTail | Developer tooling / JVM introspection | M | uprobe on JFR's `Recording::write`, ring buffer | Streams JFR chunks off any JVM in real time to a stdout tail — no `-XX:StartFlightRecording` needed. |
| 32 | TapWithFilter | Playful / demo | S | XDP, arena, Swing scope | Live-scope of packet arrival rate as an oscilloscope trace; arena shared with Java for the plot buffer. |

## 2. Sample ideas by category

### Observability & tracing

#### 1. ExecSnoopJfr

**Pitch.** Attach a raw tracepoint to `sched:sched_process_exec` and push each event (PID, PPID, comm, argv[0..N], cgroup id) into a ring buffer. The Java loop translates each event into a JFR `ProcessExec` event with `@Category("System")` and `@Label("Process launched")`. Result: a running system generates a JFR recording that JDK Mission Control can open, timeline-scrub, and correlate with Java events already present in the same JFR file.

**Framework features exercised.**
- Raw tracepoint (`sched:sched_process_exec`)
- Ring buffer read loop
- JFR emission from userspace Java

**Java angle.** JFR is the killer differentiator: no C-side tool emits into the same file the JVM is writing, so this sample lets you see "process X spawned at the exact ms the GC pause started". Two lines of `jdk.jfr.Event` gives professional-grade instrumentation.

**Sketch.**
```java
@BPF public abstract class ExecSnoopJfr extends BPFProgram {
    @BPFMapDefinition(maxEntries=16) BPFRingBuffer<ExecEvent> events;
    @BPFFunction(section="raw_tp/sched_process_exec")
    int on_exec(Ptr<bpf_raw_tracepoint_args> ctx) { ... events.push(e); return 0; }

    public static void main(String[] a) {
        try (var p = BPFProgram.load(ExecSnoopJfr.class)) {
            p.autoAttachPrograms();
            p.events.pollLoop(e -> new ProcessExecEvent(e).commit());
        }
    }
}
```

**Dependencies on unshipped features.** None.

**Inspiration.** bcc `execsnoop` — https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py

---

#### 2. OpenSnoopUi

**Pitch.** Ports bcc's `opensnoop`, but with a JavaFX table on top. Each row is `time, pid, comm, filename, err`. A filter box narrows by regex; a "Watch" mode highlights fresh rows. The kernel side is the same 30 lines as `LogOpenAt2Calls`, but the sample is about the desktop experience.

**Framework features exercised.**
- ksyscall / `SystemCallHooks.enterOpenat2` (already documented)
- Ring buffer
- JavaFX `TableView`

**Java angle.** Nobody expects a graphical tail of file opens with sub-millisecond timestamps. Feels like Wireshark for file IO. Reads absurdly little code in Java once the ring buffer plumbing is inherited.

**Sketch.**
```java
@BPF public abstract class OpenSnoopUi extends BPFProgram implements SystemCallHooks {
    @BPFMapDefinition(maxEntries=16) BPFRingBuffer<OpenEvent> events;
    @Override public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) { events.push(...); }
}
class Ui extends Application { /* TableView bound to observable list, thread pushes rows */ }
```

**Dependencies on unshipped features.** None.

**Inspiration.** bcc `opensnoop`; bpftrace one-liner `bpftrace -e 't:syscalls:sys_enter_openat { printf(...) }'`.

---

#### 3. KillSnoopJfr

**Pitch.** Tracepoint on `syscalls:sys_enter_kill` and `syscalls:sys_enter_tgkill`. Each event yields sender PID/comm, target PID, signal number. Emit as JFR `SignalSent` events labelled with a decoded signal name. Correlate in JMC with GC pauses to prove/disprove "did the OOM killer really strike us?".

**Framework features.** tracepoint, ring buffer, JFR.

**Java angle.** JFR again — but this one is a canonical answer to the "was I OOM-killed?" question inside a Java shop. It reveals SIGKILL sources that JVM logs never see because the JVM was dead when they arrived.

**Sketch.**
```java
@Override public void enterKill(int pid, int sig) { events.push(new KillEvent(pid, sig, bpf_get_current_pid_tgid())); }
```

**Dependencies on unshipped features.** None.

**Inspiration.** bcc `killsnoop` — https://github.com/iovisor/bcc/blob/master/tools/killsnoop.py

---

#### 4. SignalTracer

**Pitch.** Broader cousin of KillSnoopJfr — tracepoint on `signal:signal_generate` and `signal:signal_deliver`. Uses `task_storage` to accumulate a per-target-task histogram of delivered signals. Exposes the map through a JMX MBean; `jconsole` shows a live 2D matrix of (task, signal). Handy for debugging misbehaving JNI code that eats SIGSEGV.

**Framework features.** tracepoint (two of them), task_storage map, MBean binding on the Java side.

**Java angle.** The MBean surface makes it consumable from any JMX-aware tool with zero extra glue. Show the reader that BPF map data can flow into standard Java observability plumbing.

**Sketch.**
```java
@BPFMapDefinition(maxEntries=8192) BPFTaskStorage<SigHisto> perTask;
@BPFFunction(section="tp/signal/signal_deliver")
int on_deliver(Ptr<TracepointCtx> c) { perTask.getOrCreate(...).inc(c->sig); return 0; }
```

**Dependencies on unshipped features.** None.

**Inspiration.** bpftrace tools/signals.bt.

---

#### 5. JavaExecArgv

**Pitch.** When someone runs `java -Xmx4g -Dfoo=bar Main`, the whole `argv[]` is invisible to standard monitoring (`comm` truncates to 16 chars). Attach to `sched:sched_process_exec` and reconstruct the full argv from `mm->arg_start..arg_end` using a small per-CPU scratch array. Send each string chunk into a ring buffer. Filter Java-side for `comm=="java"` and print or emit to Prometheus.

**Framework features.** tracepoint, per-CPU array scratch, CO-RE reads (`BPF_CORE_READ` on `mm_struct`), ring buffer, cpumask usage for filtering (optional).

**Java angle.** Answers a real production question — "what JVM flags is that pod actually launching with?" — in a single small binary. Ship-worthy for platform teams that manage 10 000-JVM fleets.

**Sketch.**
```java
@BPFFunction(section="raw_tp/sched_process_exec")
int cap(Ptr<bpf_raw_tracepoint_args> ctx) {
    var task = bpf_get_current_task_btf();
    var mm = BPF_CORE_READ(task, "mm");
    var start = BPF_CORE_READ(mm, "arg_start"); ...
}
```

**Dependencies on unshipped features.** None (uses existing CO-RE plus scratch pattern).

**Inspiration.** Brendan Gregg's argdist idea and bcc `execsnoop -x`.

---

#### 6. HotThreadWatcher

**Pitch.** Sample the running task at 99Hz via a `perf_event` cycles counter, capture user-stack via `StackSymbolizer`. Every second, aggregate the top-N Java threads by sample count and emit a JFR `HotJavaThread` event with the demangled Java method name at the top of stack. Result: a lightweight "top -H" that JMC can replay retroactively.

**Framework features.** perf_event program, stack trace map, StackSymbolizer utility, JFR.

**Java angle.** Combines the existing `CPUProfiler` and `StackSymbolizer` samples with a JFR emitter. Turns 99Hz kernel sampling into first-class JVM observability without JVMTI overhead.

**Sketch.**
```java
@BPFMapDefinition BPFStackTrace stacks;
@BPFFunction(section="perf_event") int sample(...) { record pid+ustack_id; }
// user: every 1s -> pick top 5 pids, symbolize, emit JFR
```

**Dependencies on unshipped features.** None.

**Inspiration.** Netflix's flamescope / `perf top`, `jattach`-based tools.

---

#### 7. ContainerRuntimeTracer

**Pitch.** LSM hook `bprm_check_security`. For each exec, read the invoking task's cgroup v2 path via `bpf_get_current_cgroup_id()` + a small hashmap that maps cgid → path (populated on cgroup creation via `tracepoint:cgroup:cgroup_mkdir`). Emit a "Process X launched in cgroup /system.slice/docker-abc.scope". Instantly reveals which container spawned a suspicious binary — no `crictl`, no `docker ps`.

**Framework features.** LSM hook, cgroup id, hash map, tracepoint.

**Java angle.** The Java side is a small Micrometer bridge — one gauge per cgroup with a counter of processes launched. Fits into existing Prometheus stacks.

**Sketch.**
```java
@BPFFunction(section="lsm/bprm_check_security")
int check(Ptr<linux_binprm> b) {
    long id = bpf_get_current_cgroup_id();
    var path = cgidToPath.lookup(id);
    events.push(new ExecEvent(b, path)); return 0;
}
```

**Dependencies on unshipped features.** None (LSM hook + cgroup map already supported).

**Inspiration.** Falco's process-exec rules; Cilium Tetragon.

---

### Networking & security

#### 8. TcpLifeJfr

**Pitch.** Attach fentry to `tcp_v4_do_rcv` and fexit to `tcp_close` (or fentry on `inet_csk_accept`). Track per-connection state in an LRU hash keyed by `(saddr, sport, daddr, dport)`. On close, emit `TcpLifeEvent` with duration, bytes, retransmits. JFR event carries all fields as typed attributes.

**Framework features.** fentry/fexit, LRU hash, ring buffer, JFR emission.

**Java angle.** JMC users get a timeline of every TCP flow overlaid with GC pauses and thread-park events. The pitch to backend engineers: "figure out which HTTP client is holding your last connection open".

**Sketch.**
```java
record TcpKey(int saddr, int daddr, short sport, short dport) {}
@BPFMapDefinition(...) BPFLruHashMap<TcpKey, TcpState> flows;
```

**Dependencies on unshipped features.** None.

**Inspiration.** bcc `tcplife.py`; SolarWinds/Datadog "socket latency" panels.

---

#### 9. DnsLatency

**Pitch.** XDP program parses UDP/53 packets, timestamps queries by (pid=0 dummy, txid) in a hash, and on the response computes RTT. Uses tail calls to split the parse (Ethernet/IP/UDP/DNS) into cleanly staged sections — a natural teaching sample for tail-calls beyond `TailCallDemo`. Publishes RTT into a Micrometer histogram.

**Framework features.** XDP, tail call chain, hash map.

**Java angle.** Micrometer is the de-facto Java metrics registry. Wire DNS latency directly to a Prometheus scrape endpoint hosted by the same JVM that loaded the BPF program. Show that BPF + Java can replace 5 lines of grafana-agent config.

**Sketch.**
```java
@BPFFunction(section="xdp") int stage_udp(...) { bpf_tail_call(ctx, PROG_ARRAY, PARSE_DNS); ... }
```

**Dependencies on unshipped features.** None.

**Inspiration.** Cloudflare's XDP DNS RTT article — https://blog.cloudflare.com/how-to-drop-10-million-packets/

---

#### 10. HostSslSniffer

**Pitch.** Attach uprobe/uretprobe pairs to `SSL_read` / `SSL_write` in `libssl.so.3`. The uprobe captures the buffer address, the uretprobe reads the plaintext once the syscall has filled it. Publishes to a ring buffer; Java UI shows decrypted HTTP request lines as they fly by. Works on curl, python-requests, node — anything using system OpenSSL.

**Framework features.** uprobe + uretprobe pair, task_storage to carry the buffer pointer between them, ring buffer.

**Java angle.** JavaFX viewer. Also demonstrates that hello-ebpf can trace non-JVM userspace — countering the perception that it's a JVM-only tool.

**Sketch.**
```java
@BPFFunction(section="uprobe//lib/libssl.so.3:SSL_read")
int enter(Ptr<pt_regs> r) { perTask.set(new Buf(PT_REGS_PARM2(r), PT_REGS_PARM3(r))); return 0; }
@BPFFunction(section="uretprobe//lib/libssl.so.3:SSL_read")
int ret(Ptr<pt_regs> r) { events.push(perTask.get().withLen(PT_REGS_RC(r))); return 0; }
```

**Dependencies on unshipped features.** None.

**Inspiration.** bcc `sslsniff.py`; Kris Nova's talks on eBPF for SSL introspection.

---

#### 11. JdkTlsSniffer

**Pitch.** Same as HostSslSniffer but for pure-Java TLS: attach uprobe to `sun.security.ssl.SSLSocketImpl.write` after it's JIT-compiled and disassembled, then walk the on-stack `byte[]` reference. Practical trick: attach an uprobe to a JNI-side helper method exposed via JVMTI, or use a JVMTI agent (invoked from the Java-side of the sample) to publish stable symbols the uprobe can bind to.

**Framework features.** uprobe, ring buffer, JVMTI cooperation.

**Java angle.** The differentiator sample of the whole framework — "eBPF can read Java memory". Marketing gold.

**Sketch.** (See "Speculative / far-out ideas" for full treatment.)

**Dependencies on unshipped features.** Needs a JVMTI symbol-publishing helper — see design gap for "uprobe attach cookies" in `research-gap-catalog-rust-go.md`. Also potentially needs stable-address JIT code, which HotSpot provides via `-XX:+PreserveFramePointer`.

**Inspiration.** Andrei Pangin's async-profiler + eBPF integration.

---

#### 12. LatencyMap

**Pitch.** XDP program does per-CIDR bucketing using an LPM_TRIE. For each incoming packet, records the current timestamp; on the matching TX (tracked via a second hash), computes per-CIDR average RTT. Renders a Swing heat-grid painted from the userspace snapshot — each cell an /24, colour = median RTT.

**Framework features.** XDP, LPM_TRIE map, hash map, Swing rendering.

**Java angle.** LPM_TRIE is a great feature to showcase; Java-side rendering is 20 lines. The "heat map" makes CDN engineers salivate.

**Sketch.**
```java
@BPFMapDefinition BPFLpmTrieMap<CidrKey, Bucket> cidr;
```

**Dependencies on unshipped features.** None (LPM_TRIE already wrapped per the gap catalog baseline).

**Inspiration.** Cloudflare "unimog" load balancer overview.

---

#### 13. SshBruteBlocker

**Pitch.** A two-piece sample. Piece one: uprobe on `sshd`'s `auth_password` returning failure, incrementing an LRU hash keyed by remote IPv4 (obtained from a small helper written in Java that reads the SSH_CONNECTION env variable at start; per-connection state loaded via task_storage). Piece two: XDP program that drops packets whose src IP appears in an "offender" LRU map with counter ≥ N. Java side promotes offenders after 3 fails/60s.

**Framework features.** uprobe on binary path, task_storage, LRU hash, XDP drop.

**Java angle.** Demonstrates the "userspace decides, kernel enforces" pattern — arguably the most idiomatic eBPF use case. And it's a real tool: replaces sshguard.

**Sketch.**
```java
if (offenders.lookup(saddr) != null) return XDP_DROP;
```

**Dependencies on unshipped features.** None.

**Inspiration.** Cloudflare's rate-limit-in-XDP pattern; every "fail2ban but faster" blog post.

---

### Performance & profiling (Java-specific)

#### 14. JavaContentionMap

**Pitch.** Uprobe `ObjectMonitor::enter_internal` and uretprobe the same (or `ObjectMonitor::exit`). Track spin/park time per monitor address. Task_storage stores the entry timestamp per thread. Live table maps monitor address → most contended Java class (via a small heuristic that walks the JVM's oop metadata on entry).

**Framework features.** uprobe/uretprobe, task_storage, ring buffer.

**Java angle.** JVM lock introspection is a chronic pain — this sample reveals it without JVMTI's `MonitorContendedEnter` overhead, and with a live HTTP endpoint that pretty-prints the top offenders.

**Sketch.**
```java
@BPFFunction(section="uprobe//.../libjvm.so:_ZN13ObjectMonitor14enter_internalEP10JavaThread")
int enter(...) { perTask.set(...); return 0; }
```

**Dependencies on unshipped features.** None (per the memory note, `enter_internal` is the correct target on JDK 21+; `exit` has a bool tail parameter on JDK 25 — code needs a JDK-version check).

**Inspiration.** JMH people would kill for this. Also bcc `jvm-alloc` sketches.

---

#### 15. JitCompilationTracer

**Pitch.** Uprobe on HotSpot's `CompileBroker::invoke_compiler_on_method` (entry + return). Each event carries the Java method name (extracted from the `Method*` argument by CO-RE-reading `Method->_constMethod->_constants->_pool_holder->_name`), compile tier, and duration.

**Framework features.** uprobe, CO-RE reads on JVM structs (would need vmlinux-like BTF harvest from libjvm — see "unshipped features" note), ring buffer.

**Java angle.** Every performance engineer wants to know which methods are being recompiled and how long the compiler takes. Currently done via `-XX:+PrintCompilation` — this sample streams the same data to JFR.

**Sketch.**
```java
@BPFFunction(section="uprobe//.../libjvm.so:_ZN13CompileBroker...")
int on_compile(Ptr<pt_regs> r) { ... }
```

**Dependencies on unshipped features.** Currently hello-ebpf's CO-RE walks are limited to kernel BTF; walking user-space DWARF (libjvm) would either require dwarves-generated BTF for libjvm (which hello-ebpf could ship as an artefact) or `bpf_probe_read_user` chains. This is a stretch — flag it. Also see the "USDT" gap in the catalog: HotSpot exposes USDT probes (`hotspot__compiled__method__load`) that would be a cleaner attach point.

**Inspiration.** async-profiler's `-e wall`+ compilation attribution.

---

#### 16. GcRootScanTimings

**Pitch.** Uprobe on multiple HotSpot GC internals: `G1CollectedHeap::do_collection_pause_at_safepoint`, `G1RootProcessor::evacuate_roots`, `G1ConcurrentMark::mark_from_roots`. Emit sub-phase timings per collection. Java side aggregates into a JFR `G1SubPhase` event; view in JMC's built-in timeline.

**Framework features.** many uprobes, ring buffer, JFR.

**Java angle.** GC nerds already love `-Xlog:gc*=debug`, but the log is expensive at scale. This gives them the same data cheaper and correlatable with the rest of JFR.

**Sketch.**
```java
@BPFFunction(section="uprobe//.../libjvm.so:_ZN15G1CollectedHeap34do_collection_pause_at_safepointE...")
int enter(...) { perCpu.startNs = bpf_ktime_get_ns(); ...}
```

**Dependencies on unshipped features.** Multiple uprobes on many mangled symbols is currently one-attach-per-symbol. Would benefit greatly from **uprobe.multi** — see gap catalog `research-gap-catalog-rust-go.md` §"kprobe.multi and uprobe.multi".

**Inspiration.** JEP 425 diagnostics; `jfr view gc` output.

---

#### 17. JmxBackedBiolatency

**Pitch.** Ports bcc `biolatency` (tracepoints `block:block_rq_issue` / `block:block_rq_complete`, log2 histogram in a per-CPU array). Exposes the histogram as a `javax.management.DynamicMBean` with one attribute per bucket. Register with `ManagementFactory.getPlatformMBeanServer()`.

**Framework features.** tracepoint, per-CPU array (histogram pattern), MBean binding.

**Java angle.** JMX is the industry standard for "make my metric visible to a dashboard". Adds Java framework proof that BPF maps → JMX is trivial.

**Sketch.**
```java
public class Mbean implements DynamicMBean {
    public Object getAttribute(String name) { return histogram.get(Integer.parseInt(name)); }
}
```

**Dependencies on unshipped features.** None.

**Inspiration.** bcc `biolatency.py`.

---

#### 18. JavaMallocInspector

**Pitch.** Uprobes on glibc `malloc` and `free` (attached to `libc.so.6`), keyed by target PID = JVM PID. Emits allocation/free events with size and stack. Correlates with the Java thread via `bpf_get_current_pid_tgid()` and matches back to JVM thread name (which the Java side already knows). Reveals JNI leaks that JFR doesn't see (JFR only tracks Java heap).

**Framework features.** uprobe, stack trace, ring buffer, StackSymbolizer.

**Java angle.** Answers "which Java thread is leaking native memory in my Panama code?" — a question the JVM cannot answer alone.

**Sketch.**
```java
@BPFFunction(section="uprobe//lib/libc.so.6:malloc") int on_malloc(...) { events.push(...); return 0; }
```

**Dependencies on unshipped features.** None. (Would benefit from **uprobe.multi** to also catch `calloc`, `realloc`, `posix_memalign`, `aligned_alloc`.)

**Inspiration.** bcc `memleak.py`.

---

#### 19. ReadaheadStats

**Pitch.** Textbook port of bcc `readahead`, but produces its output as Micrometer gauges so it's directly Prometheus-scrapable from the same JVM. fentry `__do_page_cache_readahead` + kprobe on `mark_page_accessed`; histogram of "unread-but-prefetched pages".

**Framework features.** fentry, kprobe, per-CPU array histogram.

**Java angle.** Simple, ~120 lines. Great for the docs cookbook to prove that "any bcc tool can be a small Java class".

**Sketch.**
```java
@BPFFunction(section="fentry/__do_page_cache_readahead") ...
```

**Dependencies on unshipped features.** None.

**Inspiration.** bcc `readahead.py`.

---

### Scheduling & concurrency (sched_ext)

#### 20. GcAwareScheduler

**Pitch.** Combines JvmGcPauseTracer with the sched_ext runtime: the scheduler de-prioritises threads named `GC Thread#*` outside of STW pauses (they should yield to app threads), then during STW ranks them at the top so the pause finishes faster. Auto-detects entering STW via the same `notify_gc_begin` uprobe — the tracer publishes into a `GlobalVariable<Boolean> inStw` that the scheduler reads.

**Framework features.** sched_ext (struct_ops), uprobe, global variable, task_storage.

**Java angle.** The JVM-aware scheduler is the natural progression of the "Sound of Scheduling" line — a scheduler that _knows_ Java internals. Reveals what's possible if you write your scheduler in the same language as your runtime.

**Sketch.**
```java
@Override public void enqueue(Ptr<task_struct> t, long enq_flags) {
    if (inStw.get() && isGcThread(t)) dsq.dispatchTop(t); else dsq.dispatchTail(t);
}
```

**Dependencies on unshipped features.** None (all pieces exist). Non-trivial correctness — flag as L.

**Inspiration.** Meta's sched_ext blog series on AI/database-aware policies; discussion in Part 15 of the mostly-nerdless series.

---

#### 21. JvmSafepointFairness

**Pitch.** Custom scheduler that watches `SafepointSynchronize::begin`. When a safepoint is armed, all Java threads except the last-few-not-yet-at-safepoint are throttled (short slice), and the stragglers get an inflated slice so they can reach the polling point. Cuts time-to-safepoint on contended systems.

**Framework features.** sched_ext, uprobe, task_storage.

**Java angle.** Solves a genuine JVM annoyance ("time to safepoint" outliers) that ordinary Linux schedulers can't help with. Combines JVM knowledge with scheduling — pure hello-ebpf.

**Sketch.**
```java
@Override public void enqueue(Ptr<task_struct> t, long ef) {
    if (safepointArmed.get() && !atSafepoint(t)) t.dispatchSliceNs(20_000_000);
}
```

**Dependencies on unshipped features.** None.

**Inspiration.** JDK-8258192 "time to safepoint" issues; Jean-Philippe Bempel's talks.

---

#### 22. TypingScheduler

**Pitch.** Tracepoint on `input:input_report` increments a per-CPU counter. The scheduler reads a decaying moving average and, if keystrokes are frequent, boosts the foreground GUI process (identifiable via task_storage tag written from a userspace listener that reads `_NET_ACTIVE_WINDOW`). Typing feels snappy even under a full compile.

**Framework features.** sched_ext, tracepoint on input events, task_storage.

**Java angle.** Java-side interacts with X11/Wayland via `java.awt` to figure out the focused window — a rare cross-stack demo. Shows that "hello-ebpf can also cheat and use standard Java libraries when it wants".

**Sketch.**
```java
@BPFFunction(section="tp/input/input_report") int on_key(...) { keyCounter.inc(); }
```

**Dependencies on unshipped features.** None. Depends on hello-ebpf's existing scheduler API and tracepoints.

**Inspiration.** Con Kolivas's BFS scheduler goals; classic "responsive desktop" tuning.

---

#### 23. MusicalScheduler

**Pitch.** Cousin of the existing "Sound of Scheduling" but the other direction: the ambient music dictates policy. Java side uses the Web Audio API (via a small embedded browser or `TarsosDSP`) to detect BPM; publishes to a `GlobalVariable<Integer> bpm`. Scheduler chooses time slice = 60_000ms / bpm — slow ballads give calm long slices, drum'n'bass makes the machine feel snappy.

**Framework features.** sched_ext, global variable, uprobe on ALSA is optional.

**Java angle.** TarsosDSP is a Java DSP library — one more reminder that hello-ebpf sits in a rich Java ecosystem no C/Rust tool can match.

**Sketch.**
```java
new BpmDetector().onBpm(b -> program.bpm.set(b));
```

**Dependencies on unshipped features.** None.

**Inspiration.** Chemnitzer Linux-Tage 2025 Sound Scheduler talk (blog Part 20).

---

### Playful / demo

#### 24. SprinklerScheduler

**Pitch.** Every 250ms rotate which CPU is "hot" — that CPU accepts all runnable tasks, the rest idle. Swing UI renders a top-down view of the CPU array like a lawn sprinkler. Useless for real workloads; incredibly memorable at conferences.

**Framework features.** sched_ext, cpumask, Swing rendering from map snapshot.

**Java angle.** Java Swing gives instant visualisation without npm-ing anything; a demo you can run in five minutes on a talk.

**Sketch.**
```java
@Override public void enqueue(Ptr<task_struct> t, long f) { dsq.dispatchCpu(hotCpu.get(), t); }
```

**Dependencies on unshipped features.** None.

**Inspiration.** Original "Sound of Scheduling" playful line.

---

#### 25. KeystrokeTimer

**Pitch.** Tracepoint on `input:input_report`, ring buffer to Java. Java draws a scrolling waveform whose x-axis is real time, y-axis is 1/interval. Users see their typing rhythm; teachers use it in a talk to demo ring buffer streaming.

**Framework features.** tracepoint, ring buffer, `javafx.scene.canvas`.

**Java angle.** Beautiful, standalone GUI in ~50 lines.

**Sketch.**
```java
long last=0;
@BPFFunction(section="tp/input/input_report") int on(...) { long now=bpf_ktime_get_ns(); events.push(now-last); last=now; return 0; }
```

**Dependencies on unshipped features.** None.

**Inspiration.** Every "type faster" gamification app.

---

### Developer tooling / JVM introspection

#### 26. GitHookBooster

**Pitch.** Watches `sched:sched_process_exec` for `comm == "git"`, `comm == "mvn"`, `comm == "gradle"`. When one is seen, mark that PID (and children) in a task_storage flag. A companion sched_ext boost policy — or a plain `nice(-5)` from Java via `sched_setattr` — gives them priority. Compiles and tests feel faster on a loaded laptop.

**Framework features.** tracepoint, task_storage, cgroup (optional), sched_ext (optional).

**Java angle.** Ergonomic developer daemon that runs in the tray. `com.formdev.flatlaf` tray icon shows which processes were boosted last.

**Sketch.**
```java
@BPFFunction(section="raw_tp/sched_process_exec") int hit(...) { if (str_eq(comm, "git")) boosted.set(pid, true); return 0; }
```

**Dependencies on unshipped features.** None.

**Inspiration.** ananicy; systemd's cgroup slices for interactive tasks.

---

#### 27. MavenBuildProfiler

**Pitch.** Attach to `sched:sched_process_fork` and `sched:sched_process_exit` on descendants of a `mvn` PID. Cross-track file-open times per stage (`compile`, `test`, `install`) using an LRU hash keyed by pid. Java side reads the flame-graph-style totals and emits a JFR file plus a static HTML flamegraph.

**Framework features.** tracepoint, hash map, JFR emission, HTML/SVG rendering in Java.

**Java angle.** Maven is Java. Nobody but hello-ebpf can ship an eBPF-native `mvn install` profiler in Java. Excellent demo for the "why not just C?" crowd.

**Sketch.**
```java
@BPFFunction(section="tp/sched/sched_process_fork") int on_fork(...) { if (isDescendant(ppid)) mark(pid); }
```

**Dependencies on unshipped features.** None.

**Inspiration.** Gradle's build scans; `jdk.tools.jfr.consumer`.

---

#### 28. JavaHeapDumpTrigger

**Pitch.** LSM `file_open` hook checks whether the opened path matches `/proc/*/gc.log`. When it does, look up the PID's cgroup, and if the invoker is the same user as the JVM, kick a heap dump via `HotSpotDiagnosticMXBean.dumpHeap()`. Handy hook for on-demand diagnostics — "just tail your GC log to trigger a snapshot".

**Framework features.** LSM hook, ring buffer, JMX bridge.

**Java angle.** Combines LSM (an underused feature; only LSMDemo exists) with JVM standard MBeans. Two ecosystems talking to each other in ~150 lines.

**Sketch.**
```java
@BPFFunction(section="lsm/file_open") int open(Ptr<file> f) {
    if (path_matches(f, "/proc/*/gc.log")) events.push(new TriggerEvent(bpf_get_current_pid_tgid()));
    return 0;
}
```

**Dependencies on unshipped features.** None.

**Inspiration.** The "kill -3 to dump threads" hack, upgraded.

---

#### 29. ClassLoadTracer

**Pitch.** Uprobe on `SystemDictionary::resolve_or_null` (or the JDK 21+ successor `ClassLoaderData::add_class`). Each event carries the class name (read as a C-string from the constant pool via CO-RE). Emit to JFR as `ClassLoad` events with the loader name. Detects classloader leaks visible only as slowly growing metaspace.

**Framework features.** uprobe, string reads, ring buffer, JFR.

**Java angle.** JFR's built-in `jdk.ClassLoad` event is per-JVM and expensive. This sample gives you cross-JVM class load streaming — one process observing every JVM on the host.

**Sketch.**
```java
@BPFFunction(section="uprobe//.../libjvm.so:_ZN16SystemDictionary14resolve_or_null...")
int cl(Ptr<pt_regs> r) { bpf_probe_read_user_str(name, sizeof(name), PT_REGS_PARM1(r)); events.push(name); return 0; }
```

**Dependencies on unshipped features.** Best served by USDT probes on HotSpot (`hotspot__class__loaded`) — see USDT gap in `research-gap-catalog-rust-go.md`. Works without USDT if the sample specifies libjvm build with symbols.

**Inspiration.** BTrace's class-load agents; async-profiler `-e ClassLoad`.

---

#### 30. JniCrossingCounter

**Pitch.** Uprobe on the JNI native-method dispatch stubs (`JavaCalls::call_static`, `CompilationPolicy::stack_trace_helper`). Increment per-`(callee_symbol)` counters in a per-CPU hash. Java side dumps top-10 hot JNI crossings — usually surprising ("wait, why is `getContextClassLoader` called a million times?").

**Framework features.** uprobe, per-CPU hash.

**Java angle.** JIT + JNI cost accounting from a completely different vantage point than JVMTI. Very small sample (~120 lines) — good cookbook fit.

**Sketch.**
```java
@BPFFunction(section="uprobe//.../libjvm.so:_ZN10JavaCalls11call_staticE...")
int cross(...) { counts.inc(sym); return 0; }
```

**Dependencies on unshipped features.** None (works today, but ideal with uprobe.multi to attach to _all_ JNI dispatch symbols at once).

**Inspiration.** Cliff Click's JVM performance talks; Aleksey Shipilev's JMH nano-optimisations.

---

#### 31. JfrLiveTail

**Pitch.** Uprobe on the JFR write path (`JfrChunkWriter::write_bytes` or `Recording::flush`). Each event carries the chunk address + length; Java side reads the buffer via `bpf_probe_read_user` and pipes bytes into `jdk.jfr.consumer.RecordingStream`. Result: parse any running JVM's JFR stream in real time, with no `-XX:StartFlightRecording` flag, no JMX, no jcmd.

**Framework features.** uprobe, ring buffer.

**Java angle.** Only Java can decode JFR chunks. Combines eBPF's ability to see any process with the JVM's own event decoder. Feels magical.

**Sketch.**
```java
@BPFFunction(section="uprobe//.../libjvm.so:_ZN15JfrChunkWriter11write_bytes...")
int tap(...) { events.push(new Chunk(addr, len)); return 0; }
```

**Dependencies on unshipped features.** Full solution needs both uprobe on JVM internals _and_ a stable JFR-symbol source. Achievable today with symbol lookup.

**Inspiration.** async-profiler's ability to attach into a running JVM and drive JFR; `-XX:StartFlightRecordingOnMethodDeoptimization`.

---

#### 32. TapWithFilter

**Pitch.** XDP program updates a ring counter of packets per 10ms into an **arena** shared with Java. Java side reads directly from arena memory (no ring buffer needed) and renders an oscilloscope trace. First sample where the arena replaces a ring buffer for high-frequency dense counters.

**Framework features.** XDP, BPF arena (VA-shared mmap), Swing/JavaFX rendering.

**Java angle.** Arenas are the most exciting recent kernel BPF feature; hello-ebpf already supports them. A visible sample makes them approachable. Java-side is `MemorySegment.of(arenaAddress, size)` — Panama meets BPF.

**Sketch.**
```java
@BPFMapDefinition(mapType=ARENA, maxEntries=1<<20) BPFArena arena;
@BPFFunction(section="xdp") int tap(Ptr<xdp_md> c) {
    long slot = (bpf_ktime_get_ns() >> 24) & 0xFFF;
    ((Ptr<Long>) arena.at(slot*8)).inc();
    return XDP_PASS;
}
```

**Dependencies on unshipped features.** None (arenas supported; note the memory pin about `map_extra` from `project_arena_mmap_map_extra.md`).

**Inspiration.** Alexei Starovoitov's LPC 2024 talk on arenas; the existing arena code in `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArena.java`.

---

## 3. Speculative / far-out ideas

These need work in hello-ebpf itself or combine several advanced features that don't yet fit together cleanly. Kept short — pitch, missing pieces, why worth doing.

### F1. JdkTlsSniffer (fully speculative version)

Attach uprobe to _JIT-compiled_ `sun.security.ssl.SSLSocketImpl.write0`. Requires: (a) stable JIT symbol publication via a JVMTI agent that emits `perf-<pid>.map` and hello-ebpf's uprobe manager reading it; (b) the ability to hold on to Java `byte[]` references by reading OOP metadata under `bpf_probe_read_user`. The payoff is that hello-ebpf can decrypt _any_ JVM's TLS traffic without touching the JVM's code. Missing pieces: JIT-symbol integration, safe OOP walking. Cross-ref: gap catalog "uprobe.multi" + "USDT" families.

### F2. NoisyNeighbourAutoBalancer

Combine `cgroup_skb` (measure per-cgroup PPS), a userspace policy engine in Java, and a `sched_ext` scheduler that pins noisy pods to a subset of cores away from latency-sensitive ones. Missing pieces: cgroup socket rate-limiting BPF program type (see gap catalog "cgroup_sock*" families), plus first-class Kubernetes integration in Java. Killer demo for cloud-native Java.

### F3. LivePatchMyOwnBpf

Once **freplace / Extension** (BPF_PROG_TYPE_EXT) lands (see gap catalog §"freplace"), build a sample where the Java program reloads only the `enqueue()` method of a running scheduler — no unload/reload cycle. Demoably swap policies mid-flight while a workload runs.

### F4. BpfIterTaskTable

Once BPF iterator programs are supported (see gap catalog §"BPF iterator programs"), write a `SEC("iter/task")` in Java that streams every task_struct's state into a Swing table with live search. Effectively a "top" whose backend is a BPF program you compiled in Java.

### F5. AiInfraSchedulerReplica

Reproduce the Meta AI-fleet sched_ext ideas from public LPC talks (bias toward memory-locality-aware placement) in Java, but drive the policy from a Deep Java Library `ai.djl` model that watches recent DSQ latencies. Not a small sample; but a compelling story for "AI-driven scheduling in Java, powered by eBPF". Would need `research-gap-designs.md` picks like DSQ statistics helpers to land.

## 5. Ideas surfaced from awesome-ebpf repo deep-dive

Each entry below was triggered by a specific real-world BPF project inspected in `research-gap-catalog-otel-awesome.md` §4b. They exist here because they have a genuine Java angle beyond "port bcc-tool X to Java" — usually because the userspace half becomes a Spring, JFR, JMX, JavaFX, or JVMTI-cooperating consumer that a C or Rust tool would need extra scaffolding to write.

Sorted by category matching section 2. Difficulty tags (S/M/L) match section 1.

### Networking & security

#### 33. KatranMiniLb

**Pitch.** A tiny Katran-style L4 load balancer: a root `SEC("xdp")` program tail-calls into one of several balancer programs stored in a `PROG_ARRAY`, one per "logical service". Each balancer looks up its per-VIP LRU connection table via `HASH_OF_MAPS`. The Java side exposes a Spring Boot REST admin (`POST /vip {ip, backends[]}`) that (a) mints a new inner LRU map, (b) inserts it into the outer HASH_OF_MAPS, and (c) points a new PROG_ARRAY slot at the balancer program — all without an XDP re-attach. Zero-downtime datapath reconfiguration in ~250 lines.

**Framework features exercised.**
- XDP root program with PROG_ARRAY tail calls
- HASH_OF_MAPS (map-of-maps) for per-VIP inner LRU tables
- Spring Boot HTTP admin control plane
- Runtime map creation from Java

**Java angle.** The Spring Boot admin console is the differentiator — a REST API that live-reconfigures a kernel datapath. C/Rust equivalents (Katran itself) ship a bespoke gRPC binary. Java gets you the same functionality with `@RestController`, in a fraction of the code.

**Sketch.**
```java
@BPFMapDefinition(mapType=HASH_OF_MAPS, maxEntries=1024)
BPFHashOfMaps<Ipv4, BPFLruHashMap<TcpKey, Backend>> vipTables;
@BPFMapDefinition(mapType=PROG_ARRAY, maxEntries=64) BPFProgArray balancers;

@RestController class Admin {
  @PostMapping("/vip") ResponseEntity<?> addVip(@RequestBody VipReq r) {
    var inner = program.newInnerMap(BPFMapType.LRU_HASH, TcpKey.class, Backend.class);
    program.vipTables.put(r.ip(), inner);
    program.balancers.put(r.slot(), program.findProgram("balance_" + r.kind()));
    return ResponseEntity.ok().build();
  }
}
```

**Dependencies on unshipped features.** Needs `BPFHashOfMaps` / `BPFArrayOfMaps` wrapper (see `research-gap-catalog-otel-awesome.md` §4b.3 gap #1). Runtime inner-map minting also depends on the map-of-maps machinery.

**Inspiration.** Katran — https://github.com/facebookincubator/katran (§4b.2.1 in the gap catalog).

---

#### 34. XdpHealthResponder

**Pitch.** An XDP program that recognises `GET /healthz HTTP/1.1` on an inbound TCP/80 or TCP/8080 SYN+ACK-established connection, synthesises the response inline via `bpf_xdp_adjust_tail` + `bpf_csum_diff`, and returns `XDP_TX`. The response body is a snapshot of a `GlobalVariable<HealthState> health` that the Java side updates every second from `HealthEndpoint.health()` (Spring Boot Actuator). Result: your Spring Boot app's `/healthz` is served by the NIC, in a few microseconds, even while the JVM is in a stop-the-world pause.

**Framework features exercised.**
- XDP with packet mutation (`bpf_xdp_adjust_tail`, `bpf_csum_diff`)
- Global variable read from XDP
- Spring Boot Actuator integration

**Java angle.** Spring Boot Actuator is a Java-ecosystem staple, and "your health check survives GC pauses" is a headline pitch that no C tool can make credibly. Demonstrates that BPF can carry a chunk of Java-app responsibility down into the NIC.

**Sketch.**
```java
@BPFGlobalVariable HealthState health;
@BPFFunction(section="xdp") int respond(Ptr<xdp_md> ctx) {
    if (isHealthzGet(ctx)) { writeHttpOk(ctx, health.get()); return XDP_TX; }
    return XDP_PASS;
}
// user side: @Scheduled(fixedRate=1000) void refresh() { health.set(actuator.health()); }
```

**Dependencies on unshipped features.** Needs `bpf_xdp_adjust_tail` + `bpf_csum_diff` helper bindings (see `research-gap-catalog-otel-awesome.md` §4b.2.11 discussion). Otherwise workable.

**Inspiration.** ebpfkit's inline HTTP responder — https://github.com/Gui774ume/ebpfkit (§4b.2.11), reframed for legitimate use.

---

#### 35. DropReasonJfr

**Pitch.** Attach kprobe on `kfree_skb_reason` and fexit on `nf_hook_slow`. The kprobe captures the `enum skb_drop_reason` argument (added in 5.17); the fexit correlates back with the ingress skb. Emit a JFR `PacketDropped` event carrying `(interface, 5-tuple, drop_reason_name)`. Java-side decodes `skb_drop_reason` values via a compile-time-generated enum. JMC users see packet-drop reasons alongside GC pauses and thread contention.

**Framework features exercised.**
- kprobe + fexit pair on kernel functions
- Ring buffer
- JFR emission
- Generated Java enum from kernel BTF

**Java angle.** Nobody currently correlates kernel-level packet drops with JVM events. This sample turns "the request timed out" into "the kernel dropped it because `SKB_DROP_REASON_TCP_CSUM`" — visible in the same JMC recording as the JVM's thread-park events. Also proves the `kprobe+fexit-on-same-function` pattern Retina uses.

**Sketch.**
```java
@BPFFunction(section="kprobe/kfree_skb_reason")
int on_drop(Ptr<pt_regs> r) {
    events.push(new DropEvent(bpf_ktime_get_ns(), PT_REGS_PARM1(r), PT_REGS_PARM2(r)));
    return 0;
}
// user: DropEvent -> JFR PacketDroppedEvent with @Category("Network")
```

**Dependencies on unshipped features.** None. `enum skb_drop_reason` is present in vmlinux BTF on any 5.17+ kernel.

**Inspiration.** Retina's `drop_reason.c` — https://github.com/microsoft/retina (§4b.2.4).

---

#### 36. IoUringSubmitAudit

**Pitch.** Attach a `btf_tracepoint` to `io_uring_submit_req` (available since 5.19). Each submitted io_uring op emits `(pid, opcode, fd, offset, len)` to a ring buffer. Java side filters for JVMs (matching PID against `java.lang.management.RuntimeMXBean` snapshot) and correlates each op with the submitting thread name via `/proc/pid/task/tid/comm`. Result: a per-Java-thread heatmap of io_uring ops — the only way to observe async IO that bypasses `sys_enter_*` tracepoints.

**Framework features exercised.**
- `btf_tracepoint` (BTF-typed tracepoint) attach
- Ring buffer
- JMX / Micrometer bridge for per-thread heatmap

**Java angle.** JDK 21+ Panama and Netty 5's `IoUringIoHandler` (`io.netty.channel.uring.IoUring`) both funnel through io_uring, and no existing Java observability tool sees those submissions. The sample answers "what is my Netty pipeline actually doing?" — a question `strace` can't touch because io_uring bypasses syscall tracepoints.

**Sketch.**
```java
@BTFTracepoint("io_uring_submit_req")
int on_submit(Ptr<io_uring_submit_req_args> a) {
    events.push(new SqeEvent(a->req->opcode, a->req->fd, a->req->offset));
    return 0;
}
```

**Dependencies on unshipped features.** Needs `tp_btf` / `btf_tracepoint` attach type (see `research-gap-catalog-otel-awesome.md` §4b.3 gap #4).

**Inspiration.** Bombini's `io_uringmon` — https://github.com/bombinisecurity/bombini (§4b.2.10).

---

### Performance & profiling (Java-specific)

#### 37. ScopedSyscallProfile

**Pitch.** The harpoon pattern, applied to a specific Java method. The user picks a Java method (e.g. `com.example.RequestHandler.serve`). A JVMTI helper publishes its JIT-compiled entry/exit addresses to `/tmp/perf-<pid>.map`; hello-ebpf attaches a uprobe pair that flips a per-tid "inside serve()" flag in a HASH; `tracepoint/raw_syscalls/sys_enter` records syscall numbers gated on the flag. Output: exactly the syscalls invoked while `serve()` was on the stack, per invocation. Feeds a `.seccomp.json` file for the app.

**Framework features exercised.**
- uprobe pair (entry + exit) on JIT-compiled Java method
- tracepoint on `raw_syscalls/sys_enter`
- HASH keyed by tid
- JVMTI symbol publishing helper

**Java angle.** Harpoon works on C symbols; making it work per-Java-method needs JVMTI cooperation. The output — a per-method seccomp profile — is exactly what Java shops using Distroless containers want. No comparable tool exists in the Java world.

**Sketch.**
```java
@BPFMapDefinition BPFHashMap<Long, Boolean> inScope; // key = tgid<<32|tid
@BPFFunction(section="uprobe/serve") int enter(...) { inScope.put(tid(), true); return 0; }
@BPFFunction(section="uretprobe/serve") int leave(...) { inScope.delete(tid()); return 0; }
@BPFFunction(section="tp/raw_syscalls/sys_enter")
int syscall(Ptr<sys_enter> c) { if (inScope.get(tid())) syscallBitmap.set(c->id); return 0; }
```

**Dependencies on unshipped features.** JVMTI-published symbols via `perf-<pid>.map` (same requirement as speculative F1 JdkTlsSniffer). Base uprobe machinery works today for statically-symboled Java methods (e.g. `native` methods).

**Inspiration.** harpoon — https://github.com/alegrey91/harpoon (§4b.2.18).

---

#### 38. NettyLockDeadlockMap

**Pitch.** Attach uprobes to glibc `pthread_mutex_lock` and `pthread_mutex_unlock` (Netty and JDK internals hold plain pthread mutexes for native resource pools — direct-buffer allocators, EventLoop group state). Build a lock-order graph in a `STACK_TRACE`-keyed HASH. On any inconsistent edge (i.e. a cycle), push a `PotentialDeadlockEvent` with both stacks. Java side symbolises the stacks with `StackSymbolizer` and pretty-prints them, then also cross-references JVM `ThreadMXBean.findMonitorDeadlockedThreads()` to see whether the JVM's own deadlock detector already caught it.

**Framework features exercised.**
- uprobe on libc + libnetty native lib
- STACK_TRACE map
- Ring buffer
- JMX `ThreadMXBean` cross-check on Java side

**Java angle.** JVM's built-in `ThreadMXBean` deadlock detector only finds `synchronized` and `ReentrantLock` cycles — it is blind to native mutexes held via JNI. Netty's off-heap pool famously has both. This sample bridges the two views.

**Sketch.**
```java
@BPFFunction(section="uprobe//lib/libc.so.6:pthread_mutex_lock")
int on_lock(Ptr<pt_regs> r) {
    long mutex = PT_REGS_PARM1(r); long tid = bpf_get_current_pid_tgid();
    graph.recordEdge(currentHeld(tid), mutex); currentHeld(tid).push(mutex); return 0;
}
```

**Dependencies on unshipped features.** None. Cycle detection lives in Java.

**Inspiration.** inspektor-gadget's `deadlock` gadget — https://github.com/inspektor-gadget/inspektor-gadget (§4b.2.9).

---

### Developer tooling / JVM introspection

#### 39. FdPassAudit

**Pitch.** Attach kprobe on `__scm_send` (the kernel entry for `SCM_RIGHTS` fd-passing over unix domain sockets). Each event captures `(sender_pid, receiver_pid, fd_type_via_lookup, cgroup_id)`. Java side maintains a JMX MBean `FdPassAuditMXBean` with attributes per active JVM process — "which fds has this JVM handed to which peer this hour". Catches JNI leaks-by-fd-share, container escape via socket relay, and misbehaving `ProcessBuilder.redirect*` combinations.

**Framework features exercised.**
- kprobe on `__scm_send`
- Ring buffer
- JMX MBean
- Cgroup id → container name resolution

**Java angle.** JVMs launched from `ProcessBuilder` or via `jshell.remote` sometimes pass fds inadvertently; the JVM has no visibility into this. Making it a first-class JMX attribute makes it discoverable from the standard JDK Mission Control workflow.

**Sketch.**
```java
@BPFFunction(section="kprobe/__scm_send")
int on_send(Ptr<pt_regs> r) {
    var msg = (Ptr<msghdr>) PT_REGS_PARM2(r);
    events.push(new FdPassEvent(bpf_get_current_pid_tgid(), msg->msg_iov->iov_len));
    return 0;
}
```

**Dependencies on unshipped features.** None.

**Inspiration.** inspektor-gadget's `fdpass` gadget — https://github.com/inspektor-gadget/inspektor-gadget (§4b.2.9).

---

#### 40. LbrErrorPathSnap

**Pitch.** Fentry on a small set of "we returned an error" kernel functions (`__sys_openat` return value < 0, `security_bprm_check` return != 0, `tcp_v4_do_rcv` returning drop reason). On entry, capture the Last Branch Record via `bpf_get_branch_snapshot` — the CPU's hardware-recorded 32-entry call history. Emit as a JFR `KernelErrorPath` event; JMC users see the exact kernel-side branch trail that led to the failure.

**Framework features exercised.**
- fentry on multiple functions
- `bpf_get_branch_snapshot` helper (LBR)
- JFR emission

**Java angle.** JFR already has kernel-adjacent events (`jdk.SocketRead`, `jdk.FileRead`); overlaying LBR-informed kernel error paths onto the same timeline reveals _why_ the syscall failed without turning on `ftrace`. Uniquely-Java packaging via JFR — no C tool emits into JMC-compatible chunks.

**Sketch.**
```java
@BPFFunction(section="fexit/__sys_openat")
int on_openat_ret(Ptr<pt_regs> r) {
    if (PT_REGS_RC(r) >= 0) return 0;
    lbr_entries[64];
    long n = bpf_get_branch_snapshot(lbr_entries, sizeof(lbr_entries), 0);
    events.push(new ErrEvent(PT_REGS_RC(r), lbr_entries, n));
    return 0;
}
```

**Dependencies on unshipped features.** Needs `bpf_get_branch_snapshot` helper binding (see `research-gap-catalog-otel-awesome.md` §4b.3 gap #9).

**Inspiration.** retsnoop — https://github.com/anakryiko/retsnoop (§4b.2.14).

---

#### 41. GadgetOciPublisher

**Pitch.** Not a runtime BPF sample but a build-tooling one. A `mvn hello-ebpf:publish-gadget` goal that takes any hello-ebpf `@BPF`-annotated sample, extracts the compiled BPF ELF and its `@BPFMap` metadata, and pushes it as an OCI artifact (using `oras-java`) to a container registry, with a `gadget.yaml` sidecar compatible with inspektor-gadget's runner. Result: Java-authored gadgets can be `ig run oci://ghcr.io/mycorp/exec-snoop-jfr:v1` from any Kubernetes cluster with `ig` installed — no JVM needed on the target.

**Framework features exercised.**
- Maven plugin authoring
- OCI artifact push via `oras-java`
- Metadata generation from `@BPF*` annotations

**Java angle.** The Java ecosystem has strong Maven/Gradle tooling; leveraging that to produce container-ecosystem-native artifacts is a natural bridge that Rust/Go tools have to hand-roll. Elevates hello-ebpf from "Java framework" to "producer of ecosystem-standard BPF artifacts".

**Sketch.**
```java
@Mojo(name="publish-gadget") class PublishMojo extends AbstractMojo {
  public void execute() {
    var elf = compileWithHelloEbpf(sample); var yaml = renderGadgetYaml(sample);
    OciClient.push(registry, name, tag, elf, yaml);
  }
}
```

**Dependencies on unshipped features.** Needs OCI-image packaging of compiled BPF programs (see `research-gap-catalog-otel-awesome.md` §4b.3 gap #6). Plus a stable metadata model — likely a small extension of the annotation system.

**Inspiration.** inspektor-gadget — https://github.com/inspektor-gadget/inspektor-gadget (§4b.2.9).

---

### Playful / demo

#### 42. XdpFibRouterHeatmap

**Pitch.** An XDP program that, for every packet, calls `bpf_fib_lookup` and records the `(nexthop_ifindex, verdict)` in a HASH. Java side renders a live heat-grid: rows = incoming interfaces, columns = outgoing interfaces, colour = flow rate. Shows the kernel routing table _in action_ at packet rate — a visualisation you can't get from `ip route` or `nstat`.

**Framework features exercised.**
- XDP with `bpf_fib_lookup` kfunc
- HASH map
- JavaFX heat-grid rendering

**Java angle.** JavaFX makes the "live routing decisions" visual demoable in five minutes. This is where hello-ebpf's rich JVM ecosystem pays off — a native tool would ship a TUI at best.

**Sketch.**
```java
@BPFFunction(section="xdp") int route(Ptr<xdp_md> ctx) {
    bpf_fib_lookup_t p; fillFromPacket(ctx, &p);
    long rc = bpf_fib_lookup(ctx, &p, sizeof(p), 0);
    fibCounts.inc(new FibKey(p.ifindex, p.ifindex_out, rc));
    return XDP_PASS;
}
```

**Dependencies on unshipped features.** Needs `bpf_fib_lookup` kfunc binding (see `research-gap-catalog-otel-awesome.md` §4b.3 gap #2).

**Inspiration.** xdp-tools' `xdp_forward` — https://github.com/xdp-project/xdp-tools (§4b.2.2).

---

## 6. Retrieval provenance

Existing hello-ebpf files scanned to avoid duplication:

- `/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/` (all top-level files, `demo/`, `sched/`)
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/JvmGcPauseTracer.java` (peeked to gauge JVM-uprobe shape)
- `/Users/i560383_1/code/experiments/hello-ebpf/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloWorld.java` (peeked for framework shape)

Sibling research consulted:

- `/Users/i560383_1/code/experiments/hello-ebpf/docs/superpowers/research/research-blog-series.md` — the 22-post blog inventory; Parts 1–20 map to existing samples and served as the "do not re-pitch" baseline.
- `/Users/i560383_1/code/experiments/hello-ebpf/docs/superpowers/research/research-gap-catalog-rust-go.md` — used to flag samples that need unshipped features (uprobe.multi, USDT, freplace, BPF iterators, sockmap).
- `/Users/i560383_1/code/experiments/hello-ebpf/docs/superpowers/research/research-talks.md` (not read line-by-line but referenced as the companion talks catalog).

External inspiration sources (URLs preserved verbatim, including known typos per project convention):

- awesome-ebpf: https://github.com/qmonnet/awesome-ebpf
- bcc tools directory: https://github.com/iovisor/bcc/tree/master/tools (individual tools cited inline).
- bpftrace tools directory: https://github.com/bpftrace/bpftrace/tree/master/tools
- Linux kernel BPF selftests: https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf/progs
- Cloudflare "How to drop 10 million packets": https://blog.cloudflare.com/how-to-drop-10-million-packets/
- mostly-nerdless blog series, Parts 1–20 (see `research-blog-series.md` for full list; note Part 19 URL contains the canonical typo `helle-ebpf`).
- Meta sched_ext AI training talks (LPC 2024/2025 sched_ext microconference agenda).
- HotSpot USDT probe list (`java` binary shipped with `-XX:+ExtendedDTraceProbes`).
- Netflix flame graph / Brendan Gregg's blog (https://www.brendangregg.com/).

No builds were run. No sources under `bpf-samples/` or `docs/superpowers/research/research-gap-*.md` were modified.
