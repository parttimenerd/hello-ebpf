# Attach cookies and multi-attach (kprobe.multi / uprobe.multi)

**Blog series:** [Part 5 — First steps with libbpf](https://mostlynerdless.de/blog/2024/02/26/hello-ebpf-first-steps-with-libbpf-5/) (kprobe fundamentals) · [Part 12 — Write eBPF in pure Java](https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/) (compiler plugin enabling multi-attach)  
**Javadoc:** [`@KProbeMulti`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/KProbeMulti.html) · [`@UProbeMulti`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/UProbeMulti.html)  
**Source:** [`KProbeMulti.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/KProbeMulti.java) · [`UProbeMulti.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/UProbeMulti.java) · [`BPFProgram.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java)  
**See also:** [Kprobes / Fentry](kprobes.md) · [Uprobes](uprobes.md) · [BPF Maps](maps.md)

Without attach cookies, a single BPF program attached to two different kernel
functions cannot determine at runtime which entry point fired — all context
pointers look the same. Attach cookies solve this: each attachment carries a
`u64` that the BPF side reads via `bpf_get_attach_cookie(ctx)`, giving
zero-cost disambiguation with no extra map lookups. Multi-attach compounds the
benefit: instead of N separate `attachKProbe` calls (N syscalls, N BPF links),
one `attachKProbeMulti` call wires the program to all N symbols atomically and
returns a single `BPFLink` handle.

Two related capabilities landed in `BPFProgram`:

- Attach cookies - a `u64` value bound to each attachment. Retrievable from
  BPF-side code via `BPFJ.bpf_get_attach_cookie(ctx)`. Lets one BPF program
  disambiguate multiple attachments of itself.
- Multi-attach - a single syscall attaches one BPF program to N kernel
  symbols (`kprobe.multi`, kernel >= 5.18) or N user-space functions
  (`uprobe.multi`, kernel >= 6.6). Each attachment gets its own cookie.

## Cookie-only

```java
prog.attachKProbe(handle, "__x64_sys_openat",  false, 0xAAAAL);
prog.attachKProbe(handle, "__x64_sys_openat2", false, 0xBBBBL);
```

Inside the BPF program:

```java
long cookie = BPFJ.bpf_get_attach_cookie(ctx);
```

The `long cookie` parameter is optional - existing cookie-less overloads
still work (they pass `cookie = 0L`).

## kprobe.multi

```java
--8<-- "bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java:kprobe_multi_handler"
```

Feature gate: `Features.hasAttachType(BPFAttachType.TRACE_KPROBE_MULTI)`
must return true. On older kernels the call throws
`BPFLoadError.UnsupportedKernel("attach_type TRACE_KPROBE_MULTI", "5.18")`
before touching libbpf.

## uprobe.multi

```java
prog.attachUprobeMulti(
        prog.getProgramByName("onMany"),
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        new String[]{"malloc", "free", "getenv"},
        new long[]{1L, 2L, 3L},
        false /* not retprobe */);
```

Feature gate: `Features.hasAttachType(BPFAttachType.TRACE_UPROBE_MULTI)`
(kernel >= 6.6).

## Choosing between single-attach and multi-attach

| | Single-attach | Multi-attach |
|---|---|---|
| BPF link handles | One per symbol | One for all N symbols |
| Independent detach | Yes — detach any subset | No — all detach together |
| Syscall cost | N `bpf(BPF_LINK_CREATE)` calls | 1 `bpf(BPF_LINK_CREATE)` call |

Use single-attach when you need to detach individual symbols at different
points in the program's lifetime. Use multi-attach when all N attachment
points share the same lifecycle and you want the lower syscall overhead.

## Auto-attach interaction

`autoAttachPrograms()` and `attachAllUprobes(pid, path)` deliberately SKIP
programs whose section starts with `kprobe.multi/`, `kretprobe.multi/`,
`uprobe.multi/`, or `uretprobe.multi/`. Multi-attach needs the symbol
array - you must call `attachKProbeMulti` / `attachUprobeMulti` explicitly.

## Sample

`bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java`
attaches one BPF program to 20 x86_64 syscall entry points via
`attachKProbeMulti`. Each symbol receives a cookie equal to its index in the
array. The BPF handler reads the cookie and increments a per-cookie counter in
a `BPFHashMap`. After 5 seconds the Java side reads the map, sorts by count,
and prints the top 10.

Run (kernel ≥ 5.18 required):

```
sudo java -cp bpf-samples.jar me.bechberger.ebpf.samples.KProbeMultiCounter
```

Expected output:

```
Sampling for 5s...
Top 10:
  __x64_sys_read                   1482
  __x64_sys_write                  1203
  __x64_sys_poll                    847
  ...
```

Each line shows the symbol name and the number of calls observed during the
5-second window.

---

## Further reading

- [kprobe.multi — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)
- [bpf_get_attach_cookie — docs.ebpf.io](https://docs.ebpf.io/linux/helper-function/bpf_get_attach_cookie/)
- [Kprobes / Fentry](kprobes.md) · [Uprobes](uprobes.md)
