# hello-ebpf

hello-ebpf is a Java-to-eBPF compiler plugin that lets you write Linux kernel BPF programs entirely in Java.
You annotate a Java class with `@BPF`, extend `BPFProgram`, and mark individual methods with `@BPFFunction`.
A javac compiler plugin translates those method bodies to C, compiles them with clang, and bundles the resulting
`.o` bytecode into your jar. At runtime, `BPFProgram.load(MyClass.class)` loads the program via libbpf.

No C files, no Makefiles, no separate build step — just Java.

## How it works

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
| Linux kernel | 6.17 |
| clang / llvm | 19 |
| libbpf-dev | any recent |
| JDK | 22 |
| Privileges | root or CAP_BPF + CAP_NET_ADMIN |

Install the native dependencies on Debian/Ubuntu:

```bash
sudo apt install -y clang-19 llvm-19 libbpf-dev linux-headers-$(uname -r)
```

## Quick example — XDP drop every 3rd packet

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

This project is accompanied by an 18-part blog series that walks through each feature step by step:

[Writing eBPF programs in Java with hello-ebpf (Part 1: Hello World)](https://mostlynerdless.de/blog/2024/02/11/writing-ebpf-programs-in-java-with-hello-ebpf-1-hello-world/)

The series covers XDP, TC, tracepoints, kprobes, maps, ring buffers, LSM, sched_ext, and more.

## Project layout

```
bpf-processor/   — javac compiler plugin (Java → C translation)
bpf/             — runtime library (BPFProgram, map types, helpers)
annotations/     — @BPF, @BPFFunction, @Type, @Size, …
samples/         — runnable sample programs
```

## Documentation

| Page | Description |
|------|-------------|
| [Cheatsheet](cheatsheet.md) | Quick reference for annotations, maps, and helpers |
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
