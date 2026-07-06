# XDP — Express Data Path

**Blog series:** [Part 9 — XDP-based packet filter](https://mostlynerdless.de/blog/2024/04/22/hello-ebpf-xdp-based-packet-filter-9/) · [Part 13 — Packet logger with TC and XDP](https://mostlynerdless.de/blog/2024/08/13/hello-ebpf-a-packet-logger-in-pure-java-using-tc-and-xdp-hooks-13/) · [Part 14 — Firewall with Java & eBPF](https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/)  
**Talk:** [Building a Lightning Fast Firewall with Java & eBPF (JavaZone 2024)](https://speakerdeck.com/parttimenerd/building-a-lightning-fast-firewall-with-java-and-ebpf-javazone-2024)  
**Javadoc:** [`XDPHook`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/XDPHook.html)
**Source:** [`XDPHook.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/XDPHook.java)
**See also:** [TC Hook](tc.md) · [BPF Maps](maps.md) · [Global Variables](global-variables.md)

![Java config/log component talking to the XDP kernel program](https://mostlynerdless.de/wp-content/uploads/2024/04/xdp_filter-1-2000x1005.png)

![XDP hook position: NIC → XDP (red arrow) before Linux Network Stack → Application](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_50.jpg)

XDP (eXpress Data Path) is the fastest hook point in the Linux network stack. BPF programs run
directly in the network driver, before any SKB allocation, achieving multi-million-packets-per-second
rates on commodity hardware.

## When to use XDP

- Line-rate packet filtering (DDoS mitigation, firewalls)
- Load balancing with direct server return
- Packet sampling and monitoring
- Dropping unwanted traffic before it reaches the kernel network stack

## Implementing XDPHook

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.bpf.raw.Lib_1.*;

@BPF(license = "GPL")
public abstract class MyXDPProg extends BPFProgram implements XDPHook {

    @Override
    @BPFFunction
    public int xdpHandlePacket(Ptr<xdp_md> ctx) {
        return XDP_PASS;
    }
}
```

`XDPHook` requires you to implement `xdpHandlePacket`. The compiler plugin generates the
`SEC("xdp")` section automatically.

## The `xdp_md` context

| Field | Type | Description |
|-------|------|-------------|
| `data` | `int` | Pointer to start of packet data (as u32) |
| `data_end` | `int` | Pointer to end of packet data (exclusive) |
| `data_meta` | `int` | Pointer to metadata area (before `data`) |
| `ingress_ifindex` | `int` | Interface index the packet arrived on |
| `rx_queue_index` | `int` | RX queue index |

Access packet bytes by casting `data` to a typed pointer:

```java
@BPFFunction
public int xdpHandlePacket(Ptr<xdp_md> ctx) {
    // Cast data offset to pointer
    Ptr<ethhdr> eth = Ptr.cast(Ptr.of(ctx.val().data));
    // Bounds check required by verifier
    if ((long)(eth + 1) > ctx.val().data_end) {
        return XDP_PASS;
    }
    if (eth.val().h_proto == bpf_htons(ETH_P_IP)) {
        return handleIPv4(ctx, eth);
    }
    return XDP_PASS;
}
```

## Return values

| Constant | Value | Meaning |
|----------|-------|---------|
| `XDP_ABORTED` | 0 | Drop with error (increments counter) |
| `XDP_DROP` | 1 | Drop silently |
| `XDP_PASS` | 2 | Pass to normal kernel network stack |
| `XDP_TX` | 3 | Hairpin — transmit back out on the same interface |
| `XDP_REDIRECT` | 4 | Redirect to another interface / CPU / socket |

## Attaching the program

```java
public static void main(String[] args) throws Exception {
    try (MyXDPProg prog = BPFProgram.load(MyXDPProg.class)) {
        // Attach in SKB mode (works everywhere, slower)
        prog.xdpAttach("eth0", XDPHook.XDPMode.SKB);

        // Or native mode (requires driver support, fastest)
        prog.xdpAttach("eth0", XDPHook.XDPMode.NATIVE);

        // Default (tries native, falls back to SKB)
        prog.xdpAttach("eth0");

        System.out.println("Running. Ctrl-C to stop.");
        Thread.currentThread().join();
    }
    // Program is detached automatically on close()
}
```

## Byte-order helpers

Network headers are big-endian; x86 is little-endian. Use the kernel macros (available as
static constants in the generated C):

```java
// In @BPFFunction
short ethProto = bpf_ntohs(eth.val().h_proto);
int dstIp      = bpf_ntohl(ip.val().daddr);
```

On the Java side use `Short.reverseBytes()` / `Integer.reverseBytes()` or `ByteBuffer` with
`ByteOrder.BIG_ENDIAN`.

## Full example — block a specific source IP

```java
@BPF(license = "GPL")
public abstract class BlockIP extends BPFProgram implements XDPHook {

    /** IP to block in network byte order, set from Java. */
    final GlobalVariable<Integer> blockedIp = new GlobalVariable<>(0);

    @Override
    @BPFFunction
    public int xdpHandlePacket(Ptr<xdp_md> ctx) {
        Ptr<ethhdr> eth = Ptr.cast(Ptr.of(ctx.val().data));
        if ((long)(eth + 1) > ctx.val().data_end) return XDP_PASS;
        if (eth.val().h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

        Ptr<iphdr> ip = Ptr.cast(eth + 1);
        if ((long)(ip + 1) > ctx.val().data_end) return XDP_PASS;

        if (ip.val().saddr == blockedIp.get()) {
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    public static void main(String[] args) throws Exception {
        try (BlockIP prog = BPFProgram.load(BlockIP.class)) {
            // Block 192.168.1.100 — store in network byte order
            prog.blockedIp.set(Integer.reverseBytes(0xC0A80164));
            prog.xdpAttach("eth0");
            System.out.println("Blocking 192.168.1.100");
            Thread.currentThread().join();
        }
    }
}
```

## Performance tips

- Use `XDPMode.NATIVE` when the driver supports it (most modern NICs and virtio).
- Process as much as possible inside the BPF program. Passing packets up to the kernel incurs SKB allocation overhead.
- Use `BPFPerCpuArray` for counters to avoid inter-CPU synchronisation.
- Return `XDP_DROP` as early as possible after the bounds checks.

### Benchmark: XDP vs iptables

These charts are from the JavaZone 2024 talk using Cloudflare's published data.
XDP reaches ~10 Mpps — roughly 10× faster than iptables in PREROUTING, and even
faster with NIC offloading.

![Packet-dropping performance: iptables PREROUTING baseline (Cloudflare data)](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_10.jpg)

![Same chart extended with XDP at ~10 Mpps — dramatic speed advantage over iptables](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_12.jpg)

![XDP chart with "even faster with offloading" annotation for NIC-offloaded XDP](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_14.jpg)

### Talk: Building a Lightning Fast Firewall with Java & eBPF

<iframe width="560" height="315" src="https://www.youtube.com/embed/16Rv7IWGoDk" title="Building a Lightning Fast Firewall with Java & eBPF — JavaZone 2024" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

---

## Examples

- [`XDPDropEveryThirdPacket.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPDropEveryThirdPacket.java) — XDP_DROP based packet filter
- [`XDPPacketFilter.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPPacketFilter.java) — IP-based firewall
- [`PacketCountByLength.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/PacketCountByLength.java) — packet length histogram
- [`Firewall.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/Firewall.java) — stateful firewall with blocklist map

---

## Further reading

- [XDP program type — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/)
- [XDP actions — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/#return-values)
- [TC Hook](tc.md) · [BPF Maps](maps.md) · [Global Variables](global-variables.md)
