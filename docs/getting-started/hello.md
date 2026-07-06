# Your First BPF Program

This guide walks through two short programs: one that **prints filenames** as they are opened, and one that **blocks network ports** using a TC hook. Both are complete, runnable Java programs — no C, no Makefile.

## Print opened filenames

The `openat2` syscall is called every time a process opens a file. The program below hooks into it and prints the filename to the kernel trace pipe.

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
        bpf_trace_printk("opening: %s", filename);             // (5)
    }

    public static void main(String[] args) {
        try (HelloWorld program = BPFProgram.load(HelloWorld.class)) { // (6)
            program.autoAttachPrograms();                      // (7)
            program.tracePrintLoop(                            // (8)
                f -> String.format("%s: %s", f.task(), f.msg()));
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
| (5) `bpf_trace_printk(...)` | Writes a line to `/sys/kernel/debug/tracing/trace_pipe`. Readable with `sudo cat` or via `tracePrintLoop`. The `%s` format string prints the `filename` argument. |
| (6) `BPFProgram.load(HelloWorld.class)` | Locates the `.o` bundled in the jar and loads it into the kernel via libbpf. Returns `AutoCloseable`; the `try`-with-resources unloads on exit. |
| (7) `autoAttachPrograms()` | Iterates every BPF program in the object and attaches it using the section name inferred from the hook interface — here `kprobe/openat2`. |
| (8) `tracePrintLoop(...)` | Reads `/sys/kernel/debug/tracing/trace_pipe` in a loop and formats each `TraceEvent` with the supplied lambda. |

### Build and run

From the `bpf-samples` module root:

```sh
mvn package
sudo java --enable-native-access=ALL-UNNAMED \
     -cp target/bpf-samples.jar me.bechberger.ebpf.samples.HelloWorld
```

Expected output (one line per `openat2` call from any process):

```
cat: opening: /etc/hosts
java: opening: /proc/self/status
bash: opening: /usr/share/bash-completion/bash_completion
```

!!! warning "Root required"
    Loading BPF programs requires `root` or the `CAP_BPF` + `CAP_PERFMON` capabilities. The `sudo` prefix is the simplest path.

!!! note "--enable-native-access"
    hello-ebpf uses the Panama foreign-function API to call libbpf. Pass
    `--enable-native-access=ALL-UNNAMED` on every `java` invocation to suppress the
    module-system warning. Without it the JVM prints a `WARNING: Using incubator modules`
    message on JDK 22 and throws on JDK 24+.

## Block network ports (TC firewall)

The second program uses a TC ingress hook to drop packets whose destination port is in a map populated from Java.

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.*;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.runtime.SkDefinitions.__sk_action;

@BPF(license = "GPL")
public abstract class TCFirewall extends BPFProgram implements TCHook, BasePacketParser {

    /** Ports to block: key = destination port, value = 1. */
    @BPFMapDefinition(maxEntries = 256)
    BPFHashMap<Integer, Integer> blockedPorts;

    @Override
    public __sk_action tcHandleIngress(TCContext skb) {
        PacketInfo info = new PacketInfo();
        if (parsePacket(skb, Ptr.of(info))) {
            Ptr<Integer> blocked = blockedPorts.bpf_get(info.destinationPort);
            if (blocked != null) {
                return __sk_action.__SK_DROP;
            }
        }
        return __sk_action.__SK_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (TCFirewall program = BPFProgram.load(TCFirewall.class)) {
            for (String arg : args) {
                int port = Integer.parseInt(arg);
                program.blockedPorts.put(port, 1);
                System.out.println("Blocking destination port " + port);
            }
            program.tcAttachIngress();
            System.out.println("TC firewall running. Ctrl-C to stop.");
            while (true) Thread.sleep(1000);
        }
    }
}
```

Run it, passing port numbers to block:

```sh
sudo java --enable-native-access=ALL-UNNAMED \
     -cp target/bpf-samples.jar me.bechberger.ebpf.samples.TCFirewall 80 443
```

This drops all incoming HTTP and HTTPS traffic on every network interface. Unblocked ports pass through unchanged. The program detaches automatically when you press Ctrl-C because `BPFProgram` implements `AutoCloseable`.

For a full-featured firewall with per-IP rules, LRU caching, and ring-buffer event logging, see [`Firewall.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/Firewall.java).

## What happened (both programs)

1. At build time the javac compiler plugin extracted the annotated method bodies, translated them to C, and invoked clang to produce a BPF `.o` file.
2. The Maven build embedded that `.o` as a jar resource alongside the compiled Java classes.
3. At runtime `BPFProgram.load()` read the bundled `.o` and called libbpf to push the programs into the kernel.
4. `autoAttachPrograms()` / `tcAttachIngress()` wired the hook points.
5. Map updates (`blockedPorts.put(...)`) are reflected immediately in the running BPF program.

## Next steps

- [How the Plugin Works](how-it-works.md) — the full Java-to-C-to-`.o` pipeline in depth.
- [Maps](../maps.md) — share typed data between BPF programs and Java at runtime.
- [TC](../tc.md) — full TC hook documentation.
- [XDP](../xdp.md) — driver-level packet hook for maximum throughput.

---

The HelloWorld program is the subject of [Part 1 of the hello-ebpf blog series](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/).
