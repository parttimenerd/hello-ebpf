# Samples Index

All samples live under
`bpf-samples/src/main/java/me/bechberger/ebpf/samples/`.
Samples marked **Y** in the reference-quality column below are ≤ ~80 lines,
cover a single concept, and are suitable as starting points or `--8<--` doc
includes.

## Selection guide

| I want to… | Start with |
|---|---|
| Observe syscalls | [HelloWorld](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloWorld.java) |
| Drop / pass packets at the driver | [XDPDropEveryThirdPacket](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPDropEveryThirdPacket.java) |
| Log network events (XDP + TC) | [PacketLogger](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/PacketLogger.java) |
| Filter by IP address | [demo/BlockHTTP](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/BlockHTTP.java) |
| Block egress by cgroup | [CGroupBlockHTTPEgress](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CGroupBlockHTTPEgress.java) |
| Use a hash map | [HashMapSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HashMapSample.java) |
| Stream events to userspace | [RingSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/RingSample.java) |
| Attach to multiple kernel functions | [KProbeMultiCounter](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java) |
| Intercept / redirect file opens | [demo/ForbiddenFile](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/ForbiddenFile.java) |
| Deny access via LSM | [demo/ForbiddenFile2](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/ForbiddenFile2.java) |
| Profile CPU with stack traces | [CPUProfiler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CPUProfiler.java) |
| Write a kernel-side scheduler | [sched/MinimalScheduler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java) |
| Write a userspace scheduler | [sched/RustlandFifoSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandFifoSample.java) |
| Register a TCP congestion algorithm | [HelloCubicSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java) |

## Reference-quality samples

| Sample | Hook | What it demonstrates | Blog post |
|---|---|---|---|
| [HelloWorld](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloWorld.java) | SystemCallHooks (openat2) | Minimal hello-world tracepoint logging filename on openat2 | |
| [LogOpenAt2Calls](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/LogOpenAt2Calls.java) | SystemCallHooks (openat2) | Reads openat2 args with bpf_probe_read_kernel and getCurrentComm | |
| [SyscallCounter](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/SyscallCounter.java) | raw_tracepoint (sys_enter) | Counts all syscalls over 5 s using a global variable | |
| [SyscallProgramDemo](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/SyscallProgramDemo.java) | SEC("syscall") / BPF_PROG_TEST_RUN | Invokes a BPF_PROG_TEST_RUN syscall program to add two integers | |
| [HashMapSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HashMapSample.java) | SystemCallHooks (openat2) | Counts openat2 calls per process name using BPFHashMap | |
| [RingSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/RingSample.java) | SystemCallHooks (openat2) | Streams filename+pid events to userspace via BPFRingBuffer | |
| [HelloArrayOfMaps](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloArrayOfMaps.java) | raw_tracepoint (sys_enter) | ARRAY_OF_MAPS with per-slot syscall count inner hash maps | |
| [PerCpuInnerMapSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/PerCpuInnerMapSample.java) | raw_tracepoint (sys_enter) | HASH_OF_MAPS keyed by CPU id for contention-free syscall counting | |
| [PacketCountByLength](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/PacketCountByLength.java) | XDPHook | Counts XDP packets by length using XDPContext ergonomic API | |
| [XDPDropEveryThirdPacket](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPDropEveryThirdPacket.java) | XDPHook | Drops every third incoming packet with a BPFFunction helper | |
| [TCDropEveryThirdOutgoingPacket](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TCDropEveryThirdOutgoingPacket.java) | TCHook | Drops ~1/3 of outgoing packets using TC egress with Park-Miller RNG | |
| [CGroupBlockHTTPEgress](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CGroupBlockHTTPEgress.java) | CGroupHook | Blocks all cgroup egress HTTP traffic | |
| [LSMDemo](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/LSMDemo.java) | @LSM (file_open, bpf, socket_create) | Observes three LSM hooks and counts events with global variables | |
| [KProbeMultiCounter](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java) | @KProbeMulti | Attaches one program to 20 syscall entries using kprobe.multi | |
| [TailCallDemo](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TailCallDemo.java) | XDPHook, BPFProgArray | XDP tail calls with manual BPFProgArray slot registration | |
| [HelloCubicSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java) | struct_ops (TcpCongestionControl) | Minimal TCP congestion control algorithm registered as struct_ops | |
| [FeatureProbeSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/FeatureProbeSample.java) | none (pure Java) | Prints kernel version and feature-probe table using Features API | |
| [TimerDemo](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TimerDemo.java) | XDPHook, @BPFTimer | Self-rearming 1-second BPF timer armed on first incoming XDP packet | |
| [demo/HelloWorld](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/HelloWorld.java) | SystemCallHooks (openat2) | Minimal hello-world openat2 tracepoint (tutorial version) | |
| [demo/Sample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/Sample.java) | SystemCallHooks (openat2) | Prints filename argument on every openat2 call | |
| [demo/MapSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/MapSample.java) | SystemCallHooks (openat2) | Counts opens per process with BPFHashMap storing name+count struct | |
| [demo/RingSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/RingSample.java) | SystemCallHooks (openat2) | Logs filenames to ring buffer via BPFRingBuffer | |
| [demo/GlobalVariableSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/GlobalVariableSample.java) | SystemCallHooks (openat2) | Counts openat2 calls using a single GlobalVariable counter | |
| [demo/BlockHTTP](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/BlockHTTP.java) | XDPHook | Drops incoming packets on HTTP port using BasePacketParser helper | |
| [demo/ForbiddenFile](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/ForbiddenFile.java) | SystemCallHooks (openat2) | Redirects /tmp/forbidden opens to empty path via bpf_probe_write_user | |
| [demo/ForbiddenFile2](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/ForbiddenFile2.java) | @LSM (file_open) | Denies opens of /tmp/forbidden with EACCES using @LSM annotation | |
| [demo/XDPDropEveryThirdPacket](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/XDPDropEveryThirdPacket.java) | XDPHook | Drops every third packet with a BPFFunction helper and GlobalVariable | |
| [sched/MinimalScheduler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java) | sched_ext (SchedulerBase) | Absolute-minimum FIFO sched_ext scheduler using SchedulerBase | |
| [sched/FCFSScheduler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/FCFSScheduler.java) | sched_ext (SchedulerBase) | First-come-first-served scheduler with no preemption (slice=-1) | |
| [sched/RunnableScheduler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RunnableScheduler.java) | sched_ext (SchedulerBase) | FIFO scheduler demonstrating runnable() callback and extra_flags | |
| [sched/PrevCpuScheduler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/PrevCpuScheduler.java) | sched_ext (Scheduler) | Cache-warmth scheduler preferring task's previous CPU | |
| [sched/PerCpuSchedulerSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/PerCpuSchedulerSample.java) | sched_ext (PerCpuSchedulerBase) | Minimal PerCpuSchedulerBase demo with per-CPU and shared fallback DSQs | |
| [sched/TaskStorageScheduler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/TaskStorageScheduler.java) | sched_ext (SchedulerBase), BPFTaskStorage | FIFO scheduler tracking per-task wakeup counts with BPFTaskStorage | |
| [sched/RustlandFifoSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandFifoSample.java) | UserspaceScheduler | Minimal FIFO userspace scheduler baseline | |
| [HttpUtil](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HttpUtil.java) | none (pure Java utility) | URL query-string parser used by FirewallSpring controller | |

## All samples

### Tracepoint / syscall

| Sample | Purpose |
|---|---|
| HelloWorld | Minimal openat2 tracepoint; prints filename |
| LogOpenAt2Calls | Reads openat2 args; logs comm and filename |
| SyscallCounter | Counts all syscalls over 5 s |
| SyscallProgramDemo | Invokes a BPF_PROG_TEST_RUN syscall program |
| HashMapSample | Counts openat2 calls per process name with BPFHashMap |
| RingSample | Streams filename+pid events via BPFRingBuffer |
| HelloArrayOfMaps | ARRAY_OF_MAPS with per-slot inner hash maps |
| PerCpuInnerMapSample | HASH_OF_MAPS for contention-free per-CPU syscall counting |
| demo/HelloWorld | Minimal openat2 tracepoint (tutorial version) |
| demo/Sample | Prints filename on every openat2 call |
| demo/MapSample | Counts opens per process with BPFHashMap |
| demo/RingSample | Logs filenames to ring buffer |
| demo/GlobalVariableSample | Counts openat2 calls using GlobalVariable |
| demo/ForbiddenFile | Redirects /tmp/forbidden via bpf_probe_write_user |

### XDP

| Sample | Purpose |
|---|---|
| PacketLogger | Logs incoming packets (XDP) and outgoing (TC) to ring buffer |
| PacketCountByLength | Counts packets by length using XDPContext API |
| XDPDropEveryThirdPacket | Drops every third incoming packet |
| XDPPacketFilter | Blocks packets from specified IPs (legacy C-string version) |
| XDPPacketFilter2 | Blocks packets from specified IPs (compiler-plugin version) |
| Firewall | Full firewall with per-IP rules, LRU log, and ring-buffer events |
| FirewallSpring | Spring Boot REST front-end managing the Firewall BPF program |
| HelloTailCall | 3-stage XDP tail-call chain via @BPFTailCallTable |
| TailCallDemo | XDP tail calls with manual BPFProgArray slot registration |
| TimerDemo | Self-rearming 1-second BPF timer on first XDP packet |
| demo/BlockHTTP | Drops incoming packets on HTTP port |
| demo/XDPDropEveryThirdPacket | Drops every third packet with BPFFunction and GlobalVariable |

### TC / CGroup

| Sample | Purpose |
|---|---|
| TCDropEveryThirdOutgoingPacket | Drops ~1/3 of outgoing packets via TC egress with Park-Miller RNG |
| CGroupBlockHTTPEgress | Blocks all cgroup egress HTTP traffic |

### kprobe / uprobe

| Sample | Purpose |
|---|---|
| KProbeMultiCounter | Attaches one program to 20 syscall entries using kprobe.multi |
| JvmGcPauseTracer | Traces JVM GC pauses via uprobes on libjvm.so |
| sched/LockHolderBoostUprobes | Uprobe companion for LockHolderBoostScheduler |

### LSM

| Sample | Purpose |
|---|---|
| LSMDemo | Observes file_open, bpf, socket_create hooks; counts events |
| demo/ForbiddenFile2 | Denies opens of /tmp/forbidden with EACCES |

### struct_ops

| Sample | Purpose |
|---|---|
| HelloCubicSample | Minimal TCP congestion control algorithm as struct_ops |

### sched_ext (kernel-side)

| Sample | Purpose |
|---|---|
| sched/MinimalScheduler | Absolute-minimum FIFO scheduler (SchedulerBase) |
| sched/FCFSScheduler | First-come-first-served, no preemption |
| sched/SimpleScheduler | scx_simple port with FIFO and weighted vtime modes |
| sched/VTimeScheduler | Weighted virtual-time fair scheduler |
| sched/PriorityScheduler | 5-queue weight-based priority scheduler (scx_qmap port) |
| sched/LotteryScheduler | Lottery scheduler with random time-slice dispatch bias |
| sched/BoostedScheduler | Priority-boost for shared-cache-hot tasks |
| sched/ChaosScheduler | Concurrency-fuzzing chaos scheduler for stress-testing |
| sched/CPU0Scheduler | Pins all tasks to CPU 0 |
| sched/CentralScheduler | Central-CPU dispatcher with shared global DSQ |
| sched/DeadlineScheduler | Earliest-Deadline-First with per-task virtual deadlines |
| sched/FlowScheduler | Budget-driven starvation-free tier scheduler (scx_flow port) |
| sched/NestScheduler | CPU-nesting topology-aware scheduler |
| sched/RunnableScheduler | FIFO demonstrating runnable() callback |
| sched/PrevCpuScheduler | Cache-warmth scheduler preferring previous CPU |
| sched/PerCpuSchedulerSample | Minimal PerCpuSchedulerBase demo |
| sched/TaskStorageScheduler | FIFO with per-task wakeup counts via BPFTaskStorage |
| sched/SMTPairScheduler | SMT-pair topology-aware scheduler |
| sched/LockHolderBoostScheduler | Priority-inheritance scheduler using shared BPF maps |
| SampleScheduler | Full scx_simple port with vtime and FIFO modes plus stats |

### Userspace scheduler

| Sample | Purpose |
|---|---|
| sched/RustlandFifoSample | Minimal FIFO userspace scheduler baseline |
| sched/WeightedRRSample | Weighted round-robin with per-pid debt tracking |
| sched/LotterySample | Lottery scheduler with weight-proportional CPU placement |

### Diagnostics / utilities

| Sample | Purpose |
|---|---|
| CPUProfiler | CPU profiler using perf-event sampling and stack-trace symbolisation |
| StackSymbolizer | Translates raw instruction pointers to symbols via kallsyms and ELF |
| FeatureProbeSample | Prints kernel version and feature-probe table |
| HttpUtil | URL query-string parser used by FirewallSpring |
