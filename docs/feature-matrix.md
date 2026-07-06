# Feature Matrix

Minimum kernel versions for hello-ebpf features. The project requires kernel 6.14.

## Hook types

| Feature | Min kernel | Notes |
|---------|-----------|-------|
| XDP | 4.8 | |
| XDP native mode | 4.8 | Requires driver support |
| XDP hardware offload | 4.16 | Requires NIC firmware support |
| TC (SCHED_CLS) | 4.1 | |
| TC direct-action | 4.4 | `return TC_ACT_*` directly |
| kprobes | 4.1 | |
| kretprobes | 4.1 | |
| fentry/fexit | 5.5 | BTF required |
| Tracepoints | 4.7 | |
| Raw tracepoints | 4.17 | |
| ksyscall | 5.11 | Arch-portable syscall probes |
| perf_event | 4.9 | `SEC("perf_event")`; attach via `perf_event_open(2)` |
| uprobes | 4.1 | `SEC("uprobe/...")` — user-space function entry probe |
| uretprobes | 4.1 | `SEC("uretprobe/...")` — user-space function return probe |
| BPF LSM | 5.7 | CONFIG_BPF_LSM=y; lsm=bpf kernel param |
| sched_ext | 6.11 | CONFIG_SCHED_CLASS_EXT=y; hello-ebpf requires 6.14 |
| struct_ops (general) | 5.6 | TCP congestion control; sched_ext requires 6.11 |
| struct_ops qdisc | 6.10 | `Qdisc_ops` via `BPF_MAP_TYPE_STRUCT_OPS` |
| struct_ops HID BPF | 6.11 | `hid_bpf_ops` |
| cgroup ingress/egress | 4.10 | cgroup v2 required |
| cgroup socket create | 4.17 | |

## Map types

| Map type | Min kernel | Notes |
|---------|-----------|-------|
| Hash map | 3.19 | BPF_MAP_TYPE_HASH |
| Array map | 3.19 | BPF_MAP_TYPE_ARRAY |
| Per-CPU hash | 4.6 | BPF_MAP_TYPE_PERCPU_HASH |
| Per-CPU array | 4.6 | BPF_MAP_TYPE_PERCPU_ARRAY |
| LRU hash map | 4.10 | BPF_MAP_TYPE_LRU_HASH |
| LRU per-CPU hash | 4.10 | |
| Perf event array | 4.3 | BPF_MAP_TYPE_PERF_EVENT_ARRAY |
| Stack trace map | 4.6 | BPF_MAP_TYPE_STACK_TRACE |
| Array of maps | 4.12 | BPF_MAP_TYPE_ARRAY_OF_MAPS |
| Hash of maps | 4.12 | |
| Prog array (tail calls) | 4.2 | BPF_MAP_TYPE_PROG_ARRAY |
| Ring buffer | 5.8 | BPF_MAP_TYPE_RINGBUF |
| Bloom filter | 5.16 | BPF_MAP_TYPE_BLOOM_FILTER |
| Queue | 4.20 | BPF_MAP_TYPE_QUEUE |
| Stack | 4.20 | BPF_MAP_TYPE_STACK |
| BPF arenas | 6.9 | BPF_MAP_TYPE_ARENA |

## Language features

| Feature | Min kernel | Notes |
|---------|-----------|-------|
| GlobalVariable | 3.19 | Backed by BPF_MAP_TYPE_ARRAY |
| BPF timers | 5.15 | bpf_timer_* helpers |
| Tail calls | 4.2 | BPF_MAP_TYPE_PROG_ARRAY |
| BPF-to-BPF function calls | 4.16 | |
| Bounded loops | 5.3 | BPF verifier support |
| bpf_loop helper | 5.17 | Unbounded-count loop |
| CO-RE / BTF | 5.2 | Compile Once – Run Everywhere |
| Atomics (BPF_ATOMIC) | 5.12 | Proper atomic instructions |
| `__sync_fetch_and_add` | 3.19 | Older atomic form |
| Sleepable BPF programs | 5.10 | BPF_F_SLEEPABLE flag |
| kfunc calls | 5.13 | Kernel function calls from BPF; kfunc set must be registered |
| kprobe.multi | 5.18 | Attach one program to N symbols atomically |
| uprobe.multi | 6.6 | User-space multi-attach |
| Attach cookies (kprobe) | 5.15 | bpf_get_attach_cookie() |
| Attach cookies (uprobe) | 5.15 | |
| BPF arenas (language) | 6.9 | @InArena Ptr<T>; auto-association via compiler plugin |

## Verifier and security

| Feature | Min kernel | Notes |
|---------|-----------|-------|
| Unprivileged BPF | 3.19 | sysctl net.core.bpf_jit_harden |
| BPF JIT | 3.16 | x86-64 JIT available |
| BPF JIT always on | 4.15 | Many distros default |
| Verifier pointer arithmetic | 4.14 | |
| BTF type checking | 5.2 | |

## Checking at runtime

```java
// Check kernel version
try (var prog = BPFProgram.load(MyProg.class)) {
    // If loading succeeds, all required features are available
} catch (BPFProgram.BPFLoadError e) {
    System.err.println("Failed to load: " + e.getMessage());
}
```

```bash
# Check kernel version
uname -r

# Check BTF availability
ls /sys/kernel/btf/vmlinux

# Check available BPF program types
sudo bpftool feature | grep "program type"

# Check available map types
sudo bpftool feature | grep "map type"
```

## Distribution support

| Distribution | Default kernel | XDP | fentry | Ring buf | sched_ext |
|-------------|---------------|-----|--------|---------|-----------|
| Ubuntu 22.04 | 5.15 | Yes | Yes | Yes | No |
| Ubuntu 24.04 | 6.8 | Yes | Yes | Yes | No |
| Debian 12 | 6.1 | Yes | Yes | Yes | No |
| Fedora 40 | 6.8 | Yes | Yes | Yes | No |
| RHEL 9 | 5.14 | Yes | Yes | Yes | No |
| RHEL 10 | 6.11 | Yes | Yes | Yes | No (kernel 6.11 < hello-ebpf floor 6.14) |
| Arch Linux | rolling | Yes | Yes | Yes | Yes (6.14+) |

---

## See also

- [Install & Prerequisites](getting-started/install.md) — setting up the build environment
- [Diagnostics](diagnostics.md) — feature probes and load-time error messages
- [XDP](xdp.md) · [TC](tc.md) · [LSM & Cgroup](lsm.md) · [sched_ext](sched-ext/index.md)
