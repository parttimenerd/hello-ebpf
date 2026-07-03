# Audit: Runtime API

Point-in-time snapshot, 2026-07-03. Rows derived from `grep -rln 'public.*class' bpf/src/main/java/me/bechberger/ebpf/bpf/`.

Gap definitions: **OK** = named on target page with working example. **Partial** = named or in a table, no dedicated coverage. **Missing** = not mentioned in any page. **Rewrite** = coverage violates style guide.

| Symbol | Source path | Purpose (≤ 12 words) | Documented in | Gap | Target page |
|--------|-------------|----------------------|---------------|-----|-------------|
| `BasePacketParser` | `bpf/src/main/java/me/bechberger/ebpf/bpf/BasePacketParser.java` | Parse helpers for IP packets in XDP/TC programs | — | Missing | `xdp.md` |
| `BPFError` | `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFError.java` | Base runtime exception for BPF-related errors | — | Missing | `diagnostics.md` |
| `BPFJ` | `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFJ.java` | Java-friendly wrappers for BPF helper functions | `attach-cookies-multi.md`, `cheatsheet.md`, `global-variables.md`, `diagnostics.md`, `kprobes.md`, `cookbook.md`, `lsm.md`, `helpers.md`, `maps.md`, `sched_ext.md`, `tracepoints.md`, `tc.md` | Partial | `helpers.md` |
| `BPFProgram` | `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` | Base class for all eBPF programs | `attach-cookies-multi.md`, `cheatsheet.md`, `changelog.md`, `diagnostics.md`, `global-variables.md`, `feature-matrix.md`, `index.md`, `lsm.md`, `maps.md`, `sched_ext.md`, `kprobes.md`, `scheduler-article.md`, `profiling.md`, `tail-calls.md`, `shared-maps.md`, `tc.md`, `struct-ops.md`, `tracepoints.md`, `xdp.md`, `uprobes.md` | Partial | `getting-started/how-it-works.md` |
| `BPFProgramGroup` | `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgramGroup.java` | Bundle of cooperating BPFPrograms sharing pinned maps | `changelog.md` | Partial | `shared-maps.md` |
| `BPFVerifierException` | `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFVerifierException.java` | Exception wrapping BPF verifier failure with structured output | — | Missing | `diagnostics.md` |
| `CGroupHook` | `bpf/src/main/java/me/bechberger/ebpf/bpf/CGroupHook.java` | Mix-in interface for cgroup-based packet filtering hooks | `cheatsheet.md`, `lsm.md` | Partial | `samples/index.md` |
| `GlobalVariable` | `bpf/src/main/java/me/bechberger/ebpf/bpf/GlobalVariable.java` | Shared read/write variable between Java and eBPF program | `cheatsheet.md`, `feature-matrix.md`, `global-variables.md`, `kprobes.md`, `index.md`, `scheduler-article.md`, `sched_ext.md`, `shared-maps.md`, `tc.md`, `xdp.md` | Partial | `getting-started/how-it-works.md` |
| `LSMHook` | `bpf/src/main/java/me/bechberger/ebpf/bpf/LSMHook.java` | Mix-in interface providing Linux Security Module hooks | `cheatsheet.md`, `lsm.md` | Partial | `lsm.md` |
| `NetworkUtil` | `bpf/src/main/java/me/bechberger/ebpf/bpf/NetworkUtil.java` | Utility functions for XDP and TC network programs | — | Missing | `xdp.md` |
| `PerCpuSchedulerBase` | `bpf/src/main/java/me/bechberger/ebpf/bpf/PerCpuSchedulerBase.java` | Base class for per-CPU DSQ plus shared fallback schedulers | `changelog.md`, `sched_ext.md`, `scheduler-article.md` | Partial | `sched-ext/kernel-side.md` |
| `Scheduler` | `bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java` | Interface defining sched-ext BPF scheduler callbacks | `changelog.md`, `cheatsheet.md`, `scheduler-article.md`, `sched_ext.md`, `struct-ops.md`, `shared-maps.md`, `userspace-scheduler.md` | Partial | `sched-ext/kernel-side.md` |
| `SchedulerBase` | `bpf/src/main/java/me/bechberger/ebpf/bpf/SchedulerBase.java` | Convenience base with shared FIFO DSQ for sched-ext schedulers | `changelog.md`, `scheduler-article.md`, `sched_ext.md`, `shared-maps.md` | Partial | `sched-ext/kernel-side.md` |
| `SchedulerHelpers` | `bpf/src/main/java/me/bechberger/ebpf/bpf/SchedulerHelpers.java` | BPF-side DSQ/CPU/weight helper methods for scheduler classes | — | Missing | `sched-ext/kernel-side.md` |
| `SchedulerStats` | `bpf/src/main/java/me/bechberger/ebpf/bpf/SchedulerStats.java` | Mixin adding per-CPU enqueue/dispatch counters to schedulers | `sched_ext.md`, `scheduler-article.md` | Partial | `sched-ext/kernel-side.md` |
| `TCHook` | `bpf/src/main/java/me/bechberger/ebpf/bpf/TCHook.java` | Interface for Traffic Control classifier programs | `cheatsheet.md`, `tc.md` | Partial | `tc.md` |
| `TriFunction` | `bpf/src/main/java/me/bechberger/ebpf/bpf/TriFunction.java` | Three-argument functional interface for typed BPF callbacks | — | Missing | `maps.md` |
| `UserspaceSchedulerBase` | `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java` | BPF half of the Java userspace scheduler transport | — | Missing | `sched-ext/userspace.md` |
| `Util` | `bpf/src/main/java/me/bechberger/ebpf/bpf/Util.java` | Internal utilities: errno formatting, base64 decoding, bytecode loading | — | Missing | `samples/index.md` |
| `XDPHook` | `bpf/src/main/java/me/bechberger/ebpf/bpf/XDPHook.java` | Interface for XDP incoming-packet hook programs | `cheatsheet.md`, `index.md`, `xdp.md`, `tail-calls.md` | Partial | `xdp.md` |
| `HidBpfOps` | `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/HidBpfOps.java` | Interface for HID device report interception via struct_ops | `struct-ops.md` | Partial | `struct-ops.md` |
| `QdiscOps` | `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/QdiscOps.java` | Interface for BPF-driven queueing discipline registration | `struct-ops.md` | Partial | `struct-ops.md` |
| `SchedExtOps` | `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/SchedExtOps.java` | Raw sched_ext_ops interface without SchedulerBase conveniences | `struct-ops.md` | Partial | `struct-ops.md` |
| `TcpCongestionControl` | `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/TcpCongestionControl.java` | Interface for registering a BPF TCP congestion algorithm | `struct-ops.md` | Partial | `struct-ops.md` |
| `UserspaceScheduler` | `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceScheduler.java` | Base class for schedulers whose policy runs in Java | `userspace-scheduler.md` | Partial | `sched-ext/userspace.md` |
| `UserspaceSchedulerStartupException` | `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/UserspaceSchedulerStartupException.java` | Exception thrown when userspace scheduler fails to attach | `userspace-scheduler.md` | Partial | `sched-ext/userspace.md` |
| `BatchEvent` | `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/jfr/BatchEvent.java` | JFR event recording one slow batch drain in the scheduler | — | Missing | `sched-ext/userspace.md` |
| `DispatchEvent` | `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/jfr/DispatchEvent.java` | JFR event recording one slow individual task dispatch | — | Missing | `sched-ext/userspace.md` |
| `TickEvent` | `bpf/src/main/java/me/bechberger/ebpf/bpf/userspace/jfr/TickEvent.java` | JFR event recording one slow heartbeat tick invocation | — | Missing | `sched-ext/userspace.md` |
| `AddressCallback` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/AddressCallback.java` | Low-level ring-buffer callback receiving raw address and length | — | Missing | `maps.md` |
| `BPFArena` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArena.java` | Shared BPF+userspace page-granular memory arena map | `cookbook.md` | Partial | `arenas.md` |
| `BPFArray` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArray.java` | Fixed-size integer-keyed eBPF array map | `cheatsheet.md`, `global-variables.md`, `map-of-maps.md`, `maps.md` | Partial | `maps.md` |
| `BPFArrayOfMaps` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArrayOfMaps.java` | Outer array map whose values are inner BPF map file descriptors | `map-of-maps.md` | Partial | `map-of-maps.md` |
| `BPFBaseMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFBaseMap.java` | Abstract base providing get/put/delete/iterate for hash maps | — | Missing | `maps.md` |
| `BPFBloomFilter` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFBloomFilter.java` | Space-efficient probabilistic set-membership map | `cheatsheet.md`, `maps.md` | Partial | `maps.md` |
| `BPFCpuMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFCpuMap.java` | CPU redirect map for XDP packet steering to a target CPU | — | Missing | `maps.md` |
| `BPFDevMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFDevMap.java` | Array of output network-device indices for XDP bulk redirect | — | Missing | `maps.md` |
| `BPFHashMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHashMap.java` | Hash map with optional LRU eviction support | `changelog.md`, `cheatsheet.md`, `cookbook.md`, `lsm.md`, `map-of-maps.md`, `maps.md`, `sched_ext.md`, `shared-maps.md`, `tc.md`, `tracepoints.md`, `uprobes.md` | Partial | `maps.md` |
| `BPFHashOfMaps` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHashOfMaps.java` | Outer hash map whose values are inner BPF map file descriptors | `map-of-maps.md` | Partial | `map-of-maps.md` |
| `BPFHistogram` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHistogram.java` | Power-of-2 log2 histogram backed by a hash map | — | Missing | `maps.md` |
| `BPFInodeStorage` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFInodeStorage.java` | Per-inode key-value store freed automatically on inode eviction | — | Missing | `maps.md` |
| `BPFLpmTrie` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFLpmTrie.java` | Longest-prefix-match trie for CIDR-based packet classification | — | Missing | `maps.md` |
| `BPFLRUHashMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFLRUHashMap.java` | Hash map with automatic LRU eviction when full | `cheatsheet.md`, `maps.md`, `shared-maps.md` | Partial | `maps.md` |
| `BPFLRUPerCpuHashMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFLRUPerCpuHashMap.java` | LRU eviction combined with per-CPU storage per value slot | — | Missing | `maps.md` |
| `BPFMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFMap.java` | Root wrapper for any BPF map file descriptor | `changelog.md`, `cookbook.md`, `cheatsheet.md`, `kprobes.md`, `global-variables.md`, `maps.md`, `profiling.md`, `map-of-maps.md`, `lsm.md`, `shared-maps.md`, `scheduler-article.md`, `tracepoints.md`, `sched_ext.md`, `uprobes.md`, `tc.md`, `tail-calls.md` | Partial | `maps.md` |
| `BPFPerCpuArray` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFPerCpuArray.java` | Fixed-size array where each CPU holds an independent value copy | `cheatsheet.md`, `cookbook.md`, `maps.md`, `sched_ext.md`, `scheduler-article.md`, `xdp.md` | Partial | `maps.md` |
| `BPFPerCpuHashMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFPerCpuHashMap.java` | Hash map where each CPU holds an independent value copy | — | Missing | `maps.md` |
| `BPFPerCpuVar` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFPerCpuVar.java` | Single-slot per-CPU variable for lock-free BPF accumulators | — | Missing | `maps.md` |
| `BPFProgArray` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java` | Program array map for BPF tail calls | `cheatsheet.md`, `cookbook.md`, `helpers.md`, `maps.md`, `tail-calls.md` | Partial | `tail-calls.md` |
| `BPFQueue` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFQueue.java` | FIFO queue map with push/pop/peek operations | `cheatsheet.md`, `maps.md` | Partial | `maps.md` |
| `BPFQueueAndStack` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFQueueAndStack.java` | Abstract base for FIFO queue and LIFO stack maps | — | Missing | `maps.md` |
| `BPFRingBuffer` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFRingBuffer.java` | BPF ring buffer for efficient kernel-to-userspace event delivery | `cheatsheet.md`, `kprobes.md`, `profiling.md`, `maps.md`, `uprobes.md` | Partial | `maps.md` |
| `BPFSkStorage` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFSkStorage.java` | Per-socket key-value store freed automatically on socket close | — | Missing | `maps.md` |
| `BPFStack` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFStack.java` | LIFO stack map with push/pop/peek operations | `cheatsheet.md`, `maps.md`, `profiling.md` | Partial | `maps.md` |
| `BPFStackTraceMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFStackTraceMap.java` | Stack-trace map for kernel/userspace call-stack capture | `profiling.md` | Partial | `profiling.md` |
| `BPFTaskStorage` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFTaskStorage.java` | Per-task key-value store freed automatically on task exit | `scheduler-article.md`, `sched_ext.md` | Partial | `maps.md` |
| `BPFTimerMap` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFTimerMap.java` | Hash map bundling bpf_timer with one-shot init flag | — | Missing | `maps.md` |
| `BPFTypedArena` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFTypedArena.java` | Typed arena map with record-shaped slot accessors | — | Missing | `arenas.md` |
| `BPFUserRingBuffer` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFUserRingBuffer.java` | User-to-kernel ring buffer for userspace-producer events | — | Missing | `maps.md` |
| `BPFUserRingbufCallback` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFUserRingbufCallback.java` | Typed drain callback interface for BPFUserRingBuffer | — | Missing | `maps.md` |
| `SegmentCallback` | `bpf/src/main/java/me/bechberger/ebpf/bpf/map/SegmentCallback.java` | Zero-allocation ring-buffer callback receiving raw MemorySegment | — | Missing | `maps.md` |
