# User-space Probes (uprobes / uretprobes)

Uprobes let you attach BPF programs to arbitrary user-space function entry and
return points, without modifying the target binary. hello-ebpf provides both a
dynamic attachment API and a typed context abstraction.

## Declaring a uprobe BPF program

Use `@BPFFunction` with `section = "uprobe/<name>"` or `section = "uretprobe/<name>"`.
The `autoAttach = false` flag is required because the target binary path must be
supplied at runtime:

```java
@BPF(license = "GPL")
public abstract class MyTracer extends BPFProgram {

    @BPFFunction(section = "uprobe/malloc", autoAttach = false)
    public void onMalloc(Ptr<pt_regs> ctx) {
        // ctx is the raw register context at the probe site
        long size = ctx.val().di;   // first argument (rdi on x86-64)
        // ...
    }

    @BPFFunction(section = "uretprobe/malloc", autoAttach = false)
    public void onMallocReturn(Ptr<pt_regs> ctx) {
        long retval = ctx.val().ax; // return value (rax on x86-64)
        // ...
    }
}
```

The `section` name after the slash is arbitrary — it identifies the program
handle when calling `getProgramByName`.

## Attaching at runtime

```java
try (MyTracer program = BPFProgram.load(MyTracer.class)) {

    // attach entry probe to all processes
    program.attachUprobe(
        program.getProgramByName("onMalloc"),
        "/lib/x86_64-linux-gnu/libc.so.6",
        "malloc");

    // attach return probe to all processes
    program.attachUretprobe(
        program.getProgramByName("onMallocReturn"),
        "/lib/x86_64-linux-gnu/libc.so.6",
        "malloc");

    // attach entry probe to a single PID
    program.attachUprobe(
        program.getProgramByName("onMalloc"),
        /*retprobe=*/ false,
        /*pid=*/ targetPid,
        "/lib/x86_64-linux-gnu/libc.so.6",
        "malloc");

    // run event loop
    while (true) program.consumeAndThrow();
}
```

### API reference

```java
// Full signature — entry or return, specific pid (-1 = all processes)
BPFLink attachUprobe(ProgramHandle prog, boolean retprobe, int pid,
                     String binaryPath, String funcName)

// Convenience: entry probe, all processes
BPFLink attachUprobe(ProgramHandle prog, String binaryPath, String funcName)

// Convenience: return probe, all processes
BPFLink attachUretprobe(ProgramHandle prog, String binaryPath, String funcName)
```

Symbol resolution (name → file offset) is handled by libbpf internally — no
manual ELF parsing is needed in the caller.

## Reading probe arguments

Use the `pt_regs` fields directly for architecture-specific register access, or
use `ProbeContext` for portable code.

### Direct `pt_regs` access (x86-64)

| Argument | Register | `pt_regs` field |
|----------|----------|-----------------|
| 1st | rdi | `ctx.val().di` |
| 2nd | rsi | `ctx.val().si` |
| 3rd | rdx | `ctx.val().dx` |
| 4th | rcx | `ctx.val().cx` |
| 5th | r8  | `ctx.val().r8` |
| 6th | r9  | `ctx.val().r9` |
| Return | rax | `ctx.val().ax` |

### `ProbeContext` (architecture-portable)

`ProbeContext` is a `@BPFAbstraction` that wraps `struct pt_regs *` and expands
to architecture-portable macros at BPF compile time:

```java
import me.bechberger.ebpf.bpf.probe.ProbeContext;

@BPFFunction(section = "uprobe/my_func", autoAttach = false)
public void onMyFunc(Ptr<pt_regs> ctx) {
    ProbeContext pc = ProbeContext.of(ctx);

    long arg0 = pc.arg0();   // PT_REGS_PARM1 — first argument
    long arg1 = pc.arg1();   // PT_REGS_PARM2
    long ip   = pc.ip();     // instruction pointer
    long sp   = pc.sp();     // stack pointer
}

@BPFFunction(section = "uretprobe/my_func", autoAttach = false)
public void onMyFuncReturn(Ptr<pt_regs> ctx) {
    ProbeContext pc = ProbeContext.of(ctx);
    long retval = pc.retval(); // PT_REGS_RC — return value
}
```

`ProbeContext` generates no runtime object — every method call is inlined as C
via its `@BuiltinBPFFunction` template.

### Safe memory reads

`ProbeContext` also provides static helpers for reading kernel and user-space
memory from a uprobe handler:

```java
// Read kernel memory
ProbeContext.probeRead(dstPtr, size, srcPtr);
ProbeContext.probeReadStr(dstPtr, maxSize, srcPtr);

// Read user-space memory
ProbeContext.probeReadUser(dstPtr, size, srcPtr);
ProbeContext.probeReadUserStr(dstPtr, maxSize, srcPtr);
```

These wrap `bpf_probe_read_kernel` / `bpf_probe_read_user` and return 0 on
success or a negative errno on failure.

## Example: tracing `malloc` size and return address

```java
@BPF(license = "GPL")
public abstract class MallocTracer extends BPFProgram {

    static final int MAX_ENTRIES = 4096;

    @Type
    static class AllocEvent {
        @Unsigned long size;
        @Unsigned long addr;
        @Unsigned int  tid;
    }

    @BPFMapDefinition(maxEntries = 4096)
    BPFHashMap<Integer, Long> startSize; // tid -> requested size

    @BPFMapDefinition(maxEntries = MAX_ENTRIES * 64)
    BPFRingBuffer<AllocEvent> events;

    @BPFFunction(section = "uprobe/malloc", autoAttach = false)
    public void onMalloc(Ptr<pt_regs> ctx) {
        ProbeContext pc = ProbeContext.of(ctx);
        @Unsigned int tid = (int) bpf_get_current_pid_tgid();
        long size = (long) pc.arg0();
        startSize.bpf_put(tid, size);
    }

    @BPFFunction(section = "uretprobe/malloc", autoAttach = false)
    public void onMallocReturn(Ptr<pt_regs> ctx) {
        ProbeContext pc = ProbeContext.of(ctx);
        @Unsigned int tid = (int) bpf_get_current_pid_tgid();
        Ptr<Long> sp = startSize.bpf_get(tid);
        if (sp == null) return;

        Ptr<AllocEvent> evt = events.reserve();
        if (evt == null) return;
        evt.val().size = sp.val();
        evt.val().addr = pc.retval();
        evt.val().tid  = tid;
        startSize.bpf_delete(tid);
        events.submit(evt);
    }

    public static void main(String[] args) {
        String libc = "/lib/x86_64-linux-gnu/libc.so.6";
        try (MallocTracer program = BPFProgram.load(MallocTracer.class)) {
            program.attachUprobe(program.getProgramByName("onMalloc"), libc, "malloc");
            program.attachUretprobe(program.getProgramByName("onMallocReturn"), libc, "malloc");
            program.events.setCallback((buf, evt) ->
                System.out.printf("malloc(%d) = 0x%x  tid=%d%n",
                    evt.size, evt.addr, evt.tid));
            while (true) program.consumeAndThrow();
        }
    }
}
```

## Finding the binary path at runtime

For JVM processes, `libjvm.so` can be located by scanning `/proc/pid/maps`:

```java
static String findLibjvm(int pid) throws IOException {
    for (var line : Files.readAllLines(Path.of("/proc/" + pid + "/maps"))) {
        var parts = line.split("\\s+");
        if (parts.length >= 6 && parts[5].endsWith("/libjvm.so"))
            return parts[5];
    }
    throw new RuntimeException("libjvm.so not found for pid " + pid);
}
```

For system libraries, the path can usually be derived from `ldconfig -p` output
or by looking up `/proc/self/maps` for a known symbol.

## Mangled C++ symbol names

When attaching to C++ functions (e.g. in `libjvm.so`), pass the mangled symbol
name as `funcName`. Use `nm` or `objdump` to find it:

```bash
nm /path/to/libjvm.so | grep notify_gc_begin
# 000000000095d370 t _ZN15VM_GC_Operation15notify_gc_beginEb
```

```java
program.attachUprobe(prog, false, pid, libjvmPath,
    "_ZN15VM_GC_Operation15notify_gc_beginEb");
```
