# Tracepoints

Tracepoints are stable, versioned hook points compiled into the kernel at strategic locations.
Unlike kprobes they survive kernel version changes because their argument layout is guaranteed.

## Types of tracepoint hooks

| Annotation | Section | Notes |
|-----------|---------|-------|
| `@Tracepoint(category, name)` | `tp/category/name` | Typed context struct per tracepoint |
| `@RawTracepoint(name)` | `raw_tp/name` | Raw args array; more flexible, less safe |
| `@Ksyscall(name)` | arch-specific kprobe | Architecture-portable syscall probe |
| `implements SystemCallHooks` | multiple sections | Convenience interface for common syscalls |

## `@Tracepoint`

Each tracepoint has a dedicated context struct that the kernel fills in. The struct layout
matches `/sys/kernel/debug/tracing/events/<category>/<name>/format`.

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.Tracepoint;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.type.Ptr;

@BPF(license = "GPL")
public abstract class CountSyscalls extends BPFProgram {

    @BPFMapDefinition(maxEntries = 1024)
    final BPFHashMap<Integer, Long> pidCounts = BPFHashMap.newInstance();

    @Tracepoint(category = "syscalls", name = "sys_enter_openat")
    @BPFFunction
    public void onOpenAt(Ptr<syscalls_sys_enter_openat> ctx) {
        int pid = BPFJ.currentPid();
        Ptr<Long> val = pidCounts.bpf_get(pid);
        if (val != null) {
            val.set(val.val() + 1);
        } else {
            long one = 1;
            pidCounts.bpf_put(pid, one);
        }
    }
}
```

The compiler plugin generates `SEC("tp/syscalls/sys_enter_openat")` and calls
`bpf_program__attach_tracepoint` at load time.

### Discovering tracepoint context structs

List available tracepoints:
```bash
sudo ls /sys/kernel/debug/tracing/events/syscalls/ | head -20
```

View a tracepoint's field layout:
```bash
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
```

The corresponding Java context type is named after the tracepoint path with `/` replaced by `_`.

## `@RawTracepoint`

Raw tracepoints pass a `bpf_raw_tracepoint_args` context containing raw kernel arguments.
They have lower overhead than regular tracepoints but require manual argument extraction.

```java
@RawTracepoint("sys_enter")
@BPFFunction
public void onSysEnter(Ptr<bpf_raw_tracepoint_args> ctx) {
    // ctx->args[1] is the syscall number for sys_enter
    long syscallNr = ctx.val().args[1];
    BPFJ.bpf_trace_printk("syscall %ld\n", syscallNr);
}
```

## `@Ksyscall`

`@Ksyscall` provides architecture-portable probes on system call entry. It handles the
architecture-specific argument convention (e.g., `pt_regs` vs syscall-specific structs on arm64).

```java
@Ksyscall("openat")
@BPFFunction
public int onOpenAt(Ptr<pt_regs> ctx) {
    int dfd    = (int) PT_REGS_PARM1_CORE_SYSCALL(ctx);
    Ptr<Byte> filename = Ptr.cast(PT_REGS_PARM2_CORE_SYSCALL(ctx));
    // ...
    return 0;
}
```

## Example — count syscalls per process

```java
@BPF(license = "GPL")
public abstract class SyscallCounter extends BPFProgram {

    @Type
    record SyscallStat(int pid, long count, @Size(16) String comm) {}

    @BPFMapDefinition(maxEntries = 4096)
    final BPFHashMap<Integer, SyscallStat> stats = BPFHashMap.newInstance();

    @Tracepoint(category = "raw_syscalls", name = "sys_enter")
    @BPFFunction
    public void onSysEnter(Ptr<raw_syscalls_sys_enter> ctx) {
        int pid = BPFJ.currentPid();
        Ptr<SyscallStat> s = stats.bpf_get(pid);
        if (s != null) {
            Ptr.of(s.val().count).set(s.val().count + 1);
        } else {
            SyscallStat fresh = new SyscallStat();
            fresh.pid = pid;
            fresh.count = 1;
            BPFJ.getCurrentComm(BPFJ.charBuf(16));   // fills comm
            stats.bpf_put(pid, fresh);
        }
    }

    public static void main(String[] args) throws Exception {
        try (SyscallCounter prog = BPFProgram.load(SyscallCounter.class)) {
            prog.autoAttachPrograms();
            while (true) {
                Thread.sleep(2000);
                prog.stats.forEach((pid, stat) ->
                    System.out.printf("pid=%-6d comm=%-16s count=%d%n",
                        pid, stat.comm, stat.count));
            }
        }
    }
}
```

## Auto-attach

When you call `prog.autoAttachPrograms()`, hello-ebpf automatically attaches all programs
annotated with `@Tracepoint`, `@RawTracepoint`, `@Ksyscall`, `@Kprobe`, `@Kretprobe`,
`@Fentry`, and `@Fexit` — no manual attach calls needed.

## Available syscall tracepoints

Some commonly useful tracepoint categories:

| Category | Examples |
|----------|---------|
| `syscalls` | `sys_enter_openat`, `sys_exit_read`, `sys_enter_execve` |
| `raw_syscalls` | `sys_enter`, `sys_exit` (all syscalls) |
| `sched` | `sched_switch`, `sched_wakeup`, `sched_process_fork` |
| `net` | `net_dev_xmit`, `netif_receive_skb` |
| `block` | `block_rq_insert`, `block_rq_complete` |
| `kmem` | `kmalloc`, `kfree`, `mm_page_alloc` |
| `signal` | `signal_generate`, `signal_deliver` |
