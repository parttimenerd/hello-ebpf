# hello-ebpf

hello-ebpf is the first and only Java library for eBPF.
It lets you write Linux kernel BPF programs directly in Java.
Annotate a class with `@BPF`, extend `BPFProgram`, mark methods with `@BPFFunction`,
and the build toolchain takes care of the rest: it translates your Java method bodies to C,
compiles them with clang, and bundles the resulting `.o` into your jar.
At runtime, `BPFProgram.load(MyClass.class)` loads the program via libbpf.

No C files, no Makefiles, no separate build step. Just Java.

<iframe width="560" height="315" src="https://www.youtube.com/embed/bWs5GHYpYxg" title="hello-ebpf demo" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## Features

- **XDP and TC hooks** -- attach packet filters and packet loggers to network interfaces
- **kprobes, kretprobes, fentry, fexit** -- trace any kernel function entry or return
- **Tracepoints and raw tracepoints** -- stable kernel hook points with typed context structs
- **Uprobes and uretprobes** -- trace user-space function entry and return in any binary
- **BPF LSM hooks** -- attach programmable security policies to LSM hook points
- **sched_ext** -- write a complete Linux CPU scheduler in Java (kernel 6.11+)
- **Userspace scheduler** -- run the scheduling policy in Java, BPF as a thin transport
- **BPF maps** -- hash maps, arrays, ring buffers, per-CPU maps, task storage, and more
- **Shared maps** -- share maps between cooperating BPF programs via `@SharedFrom`
- **Map of maps** -- hash-of-maps and array-of-maps for dynamic program composition
- **Global variables** -- typed `GlobalVariable<T>` readable and writable from both sides
- **Tail calls** -- `@BPFTailCallTable` for chaining BPF programs
- **BPF arenas** -- shared memory between BPF and Java via `BPFArena` and `@InArena`
- **Timers** -- `bpf_timer` support for deferred callbacks inside BPF programs
- **struct_ops** -- implement kernel struct_ops in Java (sched_ext, TCP CC, qdisc, HID)
- **Attach cookies** -- per-attachment `u64` cookies with multi-kprobe and multi-uprobe
- **CO-RE** -- compile once, run everywhere via BTF relocations; no per-kernel headers
- **Verifier diagnostics** -- human-readable fix suggestions for common verifier rejections



```
Your Java class
      │
      │  javac + hello-ebpf compiler plugin
      ▼
  Generated C  ──► clang ──► .o (embedded in jar)
                                    │
                            BPFProgram.load()
                                    │
                               libbpf / kernel
```

1. You write a class like `MyProgram extends BPFProgram`.
2. Methods annotated `@BPFFunction` are extracted and translated to C by the compiler plugin.
3. The C code is compiled by clang at build time; the `.o` is stored as a jar resource.
4. At runtime `BPFProgram.load(MyProgram.class)` reads the bundled `.o` and calls libbpf to load it into the kernel.
5. Maps, ring buffers, and global variables are accessible from the Java side through a typed API.

## Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| Linux kernel | 6.14 |
| clang / llvm | 19 |
| libbpf-dev | any recent |
| JDK | 22 |
| Privileges | root or CAP_BPF + CAP_NET_ADMIN |

Install the native dependencies on Debian/Ubuntu:

```bash
sudo apt install -y clang-19 llvm-19 libbpf-dev linux-headers-$(uname -r)
```

## Quick example: XDP drop every 3rd packet

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.raw.Lib_1.*;

@BPF(license = "GPL")
public abstract class DropEveryThird extends BPFProgram implements XDPHook {

    /** Packet counter shared between BPF and Java. */
    final GlobalVariable<Long> packetCount = new GlobalVariable<>(0L);

    @Override
    @BPFFunction
    public int xdpHandlePacket(Ptr<xdp_md> ctx) {
        long count = packetCount.get() + 1;
        packetCount.set(count);
        // Drop every third packet
        if (count % 3 == 0) {
            return XDP_DROP;
        }
        return XDP_PASS;
    }

    public static void main(String[] args) throws Exception {
        try (DropEveryThird prog = BPFProgram.load(DropEveryThird.class)) {
            prog.xdpAttach("eth0");
            System.out.println("XDP program attached. Press Ctrl-C to stop.");
            while (true) {
                Thread.sleep(1000);
                System.out.println("Packets seen: " + prog.packetCount.get());
            }
        }
    }
}
```

Build and run:

```bash
mvn package
sudo java -cp target/myapp.jar DropEveryThird
```

!!! note "Network interface"
    Replace `eth0` with the actual interface name on your machine (`ip link` to list them).

## Blog series

This project is accompanied by a 20-part blog series on [mostlynerdless.de](https://mostlynerdless.de/blog/):

| Part | Topic |
|------|-------|
| [1](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/) | Hello World — first eBPF program in Java |
| [2](https://mostlynerdless.de/blog/2024/01/12/hello-ebpf-recording-data-in-basic-ebpf-maps-2/) | eBPF maps — hash maps and counters |
| [3](https://mostlynerdless.de/blog/2024/01/29/hello-ebpf-recording-data-in-event-buffers-3/) | Perf event buffers |
| [4](https://mostlynerdless.de/blog/2024/02/12/hello-ebpf-tail-calls-and-your-first-ebpf-application-4/) | Tail calls and your first eBPF application |
| [5](https://mostlynerdless.de/blog/2024/02/26/hello-ebpf-first-steps-with-libbpf-5/) | First steps with libbpf |
| [6](https://mostlynerdless.de/blog/2024/03/12/hello-ebpf-ring-buffers-in-libbpf-6/) | Ring buffers |
| [7](https://mostlynerdless.de/blog/2024/03/22/hello-ebpf-auto-layouting-structs-7/) | Auto-layouting structs |
| [8](https://mostlynerdless.de/blog/2024/04/09/hello-ebpf-generating-c-code-8/) | Generating C code from Java |
| [9](https://mostlynerdless.de/blog/2024/04/22/hello-ebpf-xdp-based-packet-filter-9/) | XDP-based packet filter |
| [10](https://mostlynerdless.de/blog/2024/05/21/hello-ebpf-global-variables-10/) | Global variables |
| [11](https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/) | BTF and 13,000 generated Java classes |
| [12](https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/) | Write your eBPF application in pure Java |
| [13](https://mostlynerdless.de/blog/2024/08/13/hello-ebpf-a-packet-logger-in-pure-java-using-tc-and-xdp-hooks-13/) | Packet logger with TC and XDP hooks |
| [14](https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/) | Lightning-fast firewall with Java & eBPF |
| [15](https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/) | Writing a Linux scheduler in Java |
| [16](https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/) | Controlling task scheduling from Java |
| [17](https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/) | Lottery scheduler with sched_ext |
| [18](https://mostlynerdless.de/blog/2024/12/27/hello-ebpf-writing-a-lottery-scheduler-in-pure-java-with-bpf-for-each-support-18/) | Lottery scheduler in pure Java (bpf_for_each) |
| [19](https://mostlynerdless.de/blog/2025/02/25/helle-ebpf-concurrency-testing-using-custom-linux-schedulers-19/) | Concurrency testing with custom schedulers |
| [20](https://mostlynerdless.de/blog/2025/03/25/hello-ebpf-a-scheduler-controlled-by-sound-20/) | A scheduler controlled by sound |

## Project layout

```
bpf-processor/   # javac compiler plugin (Java to C translation)
bpf/             # runtime library (BPFProgram, map types, helpers)
annotations/     # @BPF, @BPFFunction, @Type, @Size, ...
samples/         # runnable sample programs
```

## Documentation

| Page | Description |
|------|-------------|
| [Cheatsheet](cheatsheet.md) | Quick reference for annotations, maps, and helpers |
| [Cookbook](cookbook.md) | Recipes for the shapes the BPF verifier cares about |
| [Feature Matrix](feature-matrix.md) | Minimum kernel versions per feature |
| [Maps](maps.md) | BPF map types and Java API |
| [Shared maps](shared-maps.md) | Sharing maps across cooperating BPF programs (`@SharedFrom`) |
| [Helpers](helpers.md) | BPF helper functions |
| [Global Variables](global-variables.md) | `GlobalVariable` API |
| [Tracepoints](tracepoints.md) | `SEC("tp/...")` programs |
| [kprobes](kprobes.md) | `SEC("kprobe/...")` and `SEC("kretprobe/...")` programs |
| [Uprobes](uprobes.md) | `SEC("uprobe/...")` and `SEC("uretprobe/...")` programs, `ProbeContext` |
| [Profiling](profiling.md) | CPU profiler (`CPUProfiler`) and JVM GC pause tracer (`JvmGcPauseTracer`) |
| [TC](tc.md) | Traffic Control hook |
| [XDP](xdp.md) | XDP hook |
| [LSM](lsm.md) | BPF LSM hooks |
| [sched_ext](sched_ext.md) | Custom Linux schedulers |
| [Diagnostics](diagnostics.md) | Debugging and troubleshooting |
| [Changelog](changelog.md) | Release notes |

## License

Apache 2.0 (Java side) / GPL 2.0 (generated BPF C code when license = "GPL").
