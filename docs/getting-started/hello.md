# Your First BPF Program

**Javadoc:** [`BPFProgram`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/BPFProgram.html) · [`SystemCallHooks`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/runtime/interfaces/SystemCallHooks.html) · [`TCHook`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/TCHook.html) · [`BasePacketParser`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/BasePacketParser.html) · [`BPFHashMap`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFHashMap.html)

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
    Loading BPF programs requires `root` or `CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN`. The `sudo` prefix is the simplest path.

!!! note "--enable-native-access"
    hello-ebpf uses the Panama foreign-function API to call libbpf. Pass
    `--enable-native-access=ALL-UNNAMED` on every `java` invocation to suppress the
    module-system warning. Without it the JVM prints a `WARNING: Using incubator modules`
    message on JDK 22 and throws on JDK 24+.

## Block network ports (TC firewall)

The Linux network stack has two natural BPF hook points for packet filtering:

- **XDP** runs at the network driver, before the kernel allocates a socket buffer. It is the fastest option but only covers ingress and is not available on all drivers.
- **TC** (Traffic Control) runs after the kernel has allocated a socket buffer (`sk_buff`). It supports both ingress and egress, works on every interface including loopback and virtual interfaces, and gives you access to more packet metadata.

This program attaches a **TC ingress** hook: the kernel calls `tcHandleIngress` for every packet arriving on any interface, before the packet is handed to the local network stack.

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.*;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.runtime.SkDefinitions.__sk_action;

@BPF(license = "GPL")
public abstract class TCFirewall extends BPFProgram
        implements TCHook,          // (1)
                   BasePacketParser { // (2)

    @BPFMapDefinition(maxEntries = 256)
    BPFHashMap<Integer, Integer> blockedPorts; // (3)

    @Override
    public __sk_action tcHandleIngress(TCContext skb) { // (4)
        PacketInfo info = new PacketInfo();
        if (parsePacket(skb, Ptr.of(info))) {           // (5)
            Ptr<Integer> blocked = blockedPorts.bpf_get(info.destinationPort); // (6)
            if (blocked != null) {
                return __sk_action.__SK_DROP;           // (7)
            }
        }
        return __sk_action.__SK_PASS;                   // (8)
    }

    public static void main(String[] args) throws InterruptedException {
        try (TCFirewall program = BPFProgram.load(TCFirewall.class)) {
            for (String arg : args) {
                int port = Integer.parseInt(arg);
                program.blockedPorts.put(port, 1);      // (9)
                System.out.println("Blocking destination port " + port);
            }
            program.tcAttachIngress();                  // (10)
            System.out.println("TC firewall running. Ctrl-C to stop.");
            while (true) Thread.sleep(1000);
        }
    }
}
```

| Marker | Meaning |
|--------|---------|
| (1) `implements TCHook` | Tells the compiler plugin to emit a `SEC("tc/ingress")` program for `tcHandleIngress` and a `SEC("tc/egress")` program for `tcHandleEgress` (if overridden). |
| (2) `implements BasePacketParser` | Mixin that provides `parsePacket()` — a BPF-side helper that walks the raw bytes (Ethernet → IP → TCP/UDP) and fills a `PacketInfo` struct with source IP, destination IP, source port, destination port, and protocol. |
| (3) `BPFHashMap<Integer, Integer> blockedPorts` | A BPF hash map shared between the kernel program and Java. The key is a destination port number; the value is unused (just `1`). The map lives in kernel memory; both sides can read and write it concurrently. `@BPFMapDefinition` instructs the compiler plugin to emit the map definition and the loader to pin it. |
| (4) `tcHandleIngress(TCContext skb)` | Called by the kernel for every ingress packet. `TCContext` wraps the raw `__sk_buff` and adds ergonomic helpers (`length()`, `byteAt()`, …). Runs in softirq context — no sleeping, no allocation. |
| (5) `parsePacket(skb, Ptr.of(info))` | Parses the packet in-place. Returns `false` if the packet is malformed, too short, or not IP. The `Ptr.of(info)` trick passes a pointer to the stack-allocated `PacketInfo` struct to the BPF helper — required because BPF programs cannot take addresses of local variables directly. |
| (6) `blockedPorts.bpf_get(info.destinationPort)` | Hash-map lookup inside the BPF program. Returns a pointer to the map value (never a copy), or `null` if the key is absent. The pointer is valid only for the duration of the current BPF invocation. |
| (7) `__SK_DROP` | Tells the TC subsystem to discard the packet. The `sk_buff` is freed and the packet never reaches the socket layer. |
| (8) `__SK_PASS` | Tells TC to continue normal processing. Equivalent to `TC_ACT_OK`. |
| (9) `program.blockedPorts.put(port, 1)` | Java-side map write. This takes effect immediately — the next packet that arrives after this line will see the new entry in the BPF program. No program reload, no restart needed. |
| (10) `program.tcAttachIngress()` | Attaches the TC ingress program to every non-loopback network interface. Under the hood this creates a clsact qdisc (if not already present) and a BPF classifier on the ingress hook. |

### Run it

```sh
sudo ./run.sh TCFirewall 80 443
```

Or with plain java:

```sh
sudo java --enable-native-access=ALL-UNNAMED \
     -cp target/bpf-samples.jar me.bechberger.ebpf.samples.TCFirewall 80 443
```

This drops all incoming HTTP (port 80) and HTTPS (port 443) traffic on every network interface. You can verify it works by opening a second terminal and running `curl http://example.com` — the connection will time out.

Unblocked ports pass through unchanged. When you press Ctrl-C, the `try`-with-resources calls `BPFProgram.close()`, which removes the TC classifier and deletes the clsact qdisc — the interface is left exactly as it was before.

### How the map bridges kernel and Java

```
Java side                            BPF side (kernel)
─────────────────────────────────    ────────────────────────────────
program.blockedPorts.put(80, 1)  →   blockedPorts.bpf_get(destPort)
program.blockedPorts.put(443, 1) →   returns non-null → __SK_DROP
program.blockedPorts.remove(80)  →   next packet on port 80 passes
```

Both sides share the same kernel memory. The Java API translates `put`/`get`/`remove` into `bpf()` syscalls; the BPF side uses direct memory lookups with no syscall overhead.

For a full-featured firewall with per-IP CIDR rules, LRU caching, and ring-buffer event logging streamed to Java, see [`Firewall.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/Firewall.java).

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

### Run more samples

The repo ships a `run.sh` helper that builds the samples jar once and runs any sample by short name:

```sh
# build once
cd bpf-samples && mvn package && cd ..

# run any sample — no need to type the full class name or java flags
sudo ./run.sh HelloWorld
sudo ./run.sh TCFirewall 80 443
sudo ./run.sh XDPDropEveryThirdPacket
sudo ./run.sh KProbeMultiCounter
sudo ./run.sh TimerDemo

# check prerequisites
./run.sh doctor

# tail bpf_trace_printk output in a separate terminal
./run.sh trace
```

`run.sh` automatically passes `--enable-native-access=ALL-UNNAMED` and sets the classpath. See the [full samples index](../samples/index.md) for everything available.

---

## Further reading

- [How the Plugin Works](how-it-works.md) — the full Java-to-C-to-`.o` pipeline in depth
- [BPF Maps](../maps.md) — share typed data between BPF programs and Java at runtime
- [TC](../tc.md) · [XDP](../xdp.md) — full hook documentation
- [Cookbook](../cookbook.md) — verifier-safe patterns and common idioms

The HelloWorld program is the subject of [Part 1 of the hello-ebpf blog series](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/).
