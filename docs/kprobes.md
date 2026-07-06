# Kprobes, Kretprobes, Fentry & Fexit

**Blog series:** [Part 5 — First steps with libbpf](https://mostlynerdless.de/blog/2024/02/26/hello-ebpf-first-steps-with-libbpf-5/) (introduces kprobe-style attachment)  
**Javadoc:** [`@Kprobe`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/Kprobe.html) · [`@Fentry`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/Fentry.html)  
**Source:** [`Kprobe.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/Kprobe.java) · [`Fentry.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/Fentry.java)  
**See also:** [Tracepoints](tracepoints.md) · [Uprobes](uprobes.md) · [Attach Cookies & Multi](attach-cookies-multi.md) · [BPF Maps](maps.md)

![eBPF hooks across the full Linux network stack: XDP, TC, socket, tracepoints, kprobes](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_32.jpg)

Kprobes let you attach BPF programs to almost any kernel function. They are flexible
but depend on kernel internals that can change between versions. For stable interfaces
prefer tracepoints; use kprobes when no tracepoint covers the function you need.

## Hook types

| Annotation | When it fires | Context type | Notes |
|-----------|--------------|-------------|-------|
| `@Kprobe("fn")` | Entry of kernel function `fn` | `Ptr<pt_regs>` | Works on any kernel function |
| `@Kretprobe("fn")` | Return of kernel function `fn` | `Ptr<pt_regs>` | Can read return value |
| `@Fentry("fn")` | Entry (BTF-based) | Function-specific typed args | Requires BTF, kernel ≥5.5 |
| `@Fexit("fn")` | Return (BTF-based, with args) | Function-specific typed args + retval | Requires BTF |

**Prefer `@Fentry` / `@Fexit` over `@Kprobe` when possible.** They are faster (no int3 breakpoint),
safer, and receive typed arguments via BTF instead of raw register values.

## `@Kprobe` — entry probe

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.Kprobe;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.bpf.raw.Lib_1.*;

@BPF(license = "GPL")
public abstract class OpenAtTracer extends BPFProgram {

    @BPFMapDefinition(maxEntries = 256)
    final BPFRingBuffer<OpenEvent> events = BPFRingBuffer.newInstance(OpenEvent.class);

    @Type
    record OpenEvent(int pid, int tgid, long fd, @Size(256) String filename) {}

    @Kprobe("do_sys_openat2")
    @BPFFunction
    public int onOpenAt2(Ptr<PtDefinitions.pt_regs> ctx) {
        Ptr<OpenEvent> e = events.reserve();
        if (e == null) return 0;

        e.val().pid  = BPFJ.currentPid();
        e.val().tgid = BPFJ.currentTgid();

        // First arg (filename) is in PT_REGS_PARM2
        Ptr<Byte> filenamePtr = Ptr.cast(PT_REGS_PARM2_CORE(ctx));
        BPFJ.bpf_probe_read_user_str(
            Ptr.cast(e.val().filename), 256, filenamePtr);

        events.submit(e);
        return 0;
    }
}
```

### Reading arguments from `pt_regs`

On x86-64, arguments are passed in registers:

| Argument | Macro | Register |
|----------|-------|---------|
| 1st | `PT_REGS_PARM1_CORE(ctx)` | rdi |
| 2nd | `PT_REGS_PARM2_CORE(ctx)` | rsi |
| 3rd | `PT_REGS_PARM3_CORE(ctx)` | rdx |
| 4th | `PT_REGS_PARM4_CORE(ctx)` | rcx |
| 5th | `PT_REGS_PARM5_CORE(ctx)` | r8 |
| Return | `PT_REGS_RC_CORE(ctx)` | rax (kretprobe only) |

Use the `_CORE` variants which work correctly with CO-RE BPF (kernel ≥5.5).

## `@Kretprobe` — return probe

```java
@Kretprobe("do_sys_openat2")
@BPFFunction
public int onOpenAt2Return(Ptr<PtDefinitions.pt_regs> ctx) {
    long retval = PT_REGS_RC_CORE(ctx);
    if (retval < 0) {
        BPFJ.bpf_trace_printk("openat2 failed: %ld\n", retval);
    }
    return 0;
}
```

## `@Fentry` — fast entry probe (BTF-based)

```java
@Fentry("do_sys_openat2")
@BPFFunction
public int onFentryOpenAt2(int dfd, Ptr<Byte> filename, Ptr<open_how> how, long usize) {
    // Arguments are typed directly — no pt_regs needed
    int pid = BPFJ.currentPid();
    BPFJ.bpf_trace_printk("openat2 dfd=%d pid=%d\n", dfd, pid);
    return 0;
}
```

The compiler plugin reads BTF to determine the function signature and generates the correct
`SEC("fentry/do_sys_openat2")` section.

## `@Fexit` — fast exit probe (BTF-based, has return value)

```java
@Fexit("do_sys_openat2")
@BPFFunction
public int onFexitOpenAt2(int dfd, Ptr<Byte> filename, Ptr<open_how> how, long usize, long ret) {
    // Last parameter is the return value
    if (ret >= 0) {
        BPFJ.bpf_trace_printk("opened fd=%ld\n", ret);
    }
    return 0;
}
```

## Auto-attach

```java
public static void main(String[] args) throws Exception {
    try (OpenAtTracer prog = BPFProgram.load(OpenAtTracer.class)) {
        prog.autoAttachPrograms();   // attaches all @Kprobe / @Fentry / etc.
        prog.events.setCallback(e ->
            System.out.printf("pid=%-6d file=%s%n", e.pid, e.filename));
        while (true) {
            prog.consumeAndSleep(100);
        }
    }
}
```

## One-shot kprobes with GlobalVariable gate

To fire a kprobe only once (useful in tests), gate it with a `GlobalVariable<Boolean>`:

```java
final GlobalVariable<Boolean> armed = new GlobalVariable<>(true);

@Kprobe("do_sys_openat2")
@BPFFunction
public int onOpenAt2(Ptr<PtDefinitions.pt_regs> ctx) {
    if (!armed.get()) return 0;
    armed.set(false);
    // ... capture event ...
    return 0;
}
```

Set `armed.set(true)` from Java whenever you want the next probe to fire.

## Finding kernel function names

```bash
# Search for functions related to "openat"
sudo grep openat /proc/kallsyms | grep " T " | head -20

# Check if a function is kprobe-able
sudo bpftool feature | grep kprobe
```

Not all kernel functions can be probed — inlined functions, `__init` functions, and functions
on the kprobe blacklist (`/sys/kernel/debug/kprobes/blacklist`) cannot be used.

---

## Examples

- [`LogOpenAt2Calls.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/LogOpenAt2Calls.java) — kprobe on `openat2`, logs file paths via ring buffer
- [`KProbeMultiCounter.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java) — multi-kprobe with attach cookies
- [`CPUProfiler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CPUProfiler.java) — fentry-based CPU profiler

---

## Further reading

- [kprobe program type — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)
- [fentry/fexit program type — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACING/)
- [Tracepoints](tracepoints.md) (includes hook-type comparison table) · [Uprobes](uprobes.md) · [Attach Cookies & Multi](attach-cookies-multi.md)
