# Your First BPF Program

`HelloWorld` attaches a kprobe to the `openat2` syscall and writes `"Hello, World!"` to the kernel trace pipe every time any process opens a file. A kprobe fires in kernel context on every invocation from any process — no sampling, no polling — which makes it the simplest attach point for observing real kernel activity from Java.

## The program

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;

@BPF(license = "GPL")                                          // (1)
public abstract class HelloWorld
        extends BPFProgram                                     // (2)
        implements SystemCallHooks {                           // (3)

    @Override
    public void enterOpenat2(                                  // (4)
            int dfd, String filename, Ptr<open_how> how) {
        bpf_trace_printk("Hello, World!");                     // (5)
    }

    public static void main(String[] args) {
        try (HelloWorld program = BPFProgram.load(HelloWorld.class)) { // (6)
            program.autoAttachPrograms();                      // (7)
            program.tracePrintLoop(                            // (8)
                f -> String.format("%d: %s: %s",
                        (int) f.ts(), f.task(), f.msg()));
        }
    }
}
```

| Marker | Meaning |
|--------|---------|
| (1) `@BPF(license = "GPL")` | Marks the class as a BPF program container. The license string is written into the `.o` and required by GPL-gated helpers such as `bpf_trace_printk`. |
| (2) `extends BPFProgram` | Base class that owns the libbpf lifecycle. `load()`, `autoAttachPrograms()`, and `tracePrintLoop()` are defined here. |
| (3) `implements SystemCallHooks` | Provides the `enterOpenat2` hook signature so the compiler plugin knows which kprobe section to emit. |
| (4) `enterOpenat2(...)` | The BPF method body. The compiler plugin translates this to C and compiles it with clang at build time. It runs in kernel context. |
| (5) `bpf_trace_printk(...)` | Writes a line to `/sys/kernel/debug/tracing/trace_pipe`. Readable with `sudo cat` or via `tracePrintLoop`. |
| (6) `BPFProgram.load(HelloWorld.class)` | Locates the `.o` bundled in the jar and loads it into the kernel via libbpf. Returns `AutoCloseable`; the `try`-with-resources unloads on exit. |
| (7) `autoAttachPrograms()` | Iterates every BPF program in the object and attaches it using the section name inferred from the hook interface — here `kprobe/openat2`. |
| (8) `tracePrintLoop(...)` | Reads `/sys/kernel/debug/tracing/trace_pipe` in a loop and formats each `TraceEvent` with the supplied lambda. |

## Build and run

From the `bpf-samples` module root:

```sh
mvn package
sudo java -cp target/bpf-samples.jar me.bechberger.ebpf.samples.HelloWorld
```

Expected output (one line per `openat2` call from any process):

```
4321: cat: Hello, World!
8910: java: Hello, World!
```

The fields are `pid: task-name: message` as formatted by the `tracePrintLoop` lambda.

!!! warning "Root required"
    Loading BPF programs requires `root` or the `CAP_BPF` + `CAP_PERFMON` capabilities. The `sudo` prefix is the simplest path.

## What happened

1. At build time the javac compiler plugin extracted the body of `enterOpenat2`, translated it to C, and invoked clang to produce a BPF `.o` file.
2. The Maven build embedded that `.o` as a jar resource alongside the compiled Java classes.
3. At runtime `BPFProgram.load()` read the bundled `.o` and called libbpf to push the program into the kernel.
4. `autoAttachPrograms()` wired the kprobe: the kernel now calls the BPF program on every `openat2` syscall.
5. `tracePrintLoop` reads the kernel trace pipe and prints each formatted event to stdout.

## Next steps

- [How the Plugin Works](how-it-works.md) — the full Java-to-C-to-`.o` pipeline in depth.
- [Maps](../maps.md) — share typed data between BPF programs and Java at runtime.

---

This sample is the subject of [Part 1 of the hello-ebpf blog series](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/).
