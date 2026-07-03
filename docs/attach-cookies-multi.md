# Attach cookies and multi-attach (kprobe.multi / uprobe.multi)

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

## Auto-attach interaction

`autoAttachPrograms()` and `attachAllUprobes(pid, path)` deliberately SKIP
programs whose section starts with `kprobe.multi/`, `kretprobe.multi/`,
`uprobe.multi/`, or `uretprobe.multi/`. Multi-attach needs the symbol
array - you must call `attachKProbeMulti` / `attachUprobeMulti` explicitly.

## Sample

See `bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java`
- attaches to 20 syscall entries and prints the top-10 by call count.
