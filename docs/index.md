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

- [XDP](xdp.md), [TC](tc.md), [kprobe/fentry](kprobes.md), [tracepoint](tracepoints.md), [uprobe](uprobes.md), [LSM](lsm.md) hooks
- [sched_ext](sched-ext/index.md): write a Linux CPU scheduler in Java, or run the policy entirely in [userspace](sched-ext/userspace.md)
- [BPF maps](maps.md): [hash](maps.md#bpfhashmapk-v), [array](maps.md#bpfarrayv), [ring buffer](maps.md#bpfringbuffere), [per-CPU](maps.md#bpfpercpuarrayv), [task storage](sched-ext/cookbook.md#per-task-storage), [map-of-maps](map-of-maps.md), [shared maps](shared-maps.md)
- [Global variables](global-variables.md), [tail calls](tail-calls.md), [BPF arenas](arenas.md), [timers](timers.md), [struct_ops](struct-ops.md), [attach cookies](attach-cookies-multi.md)
- [CO-RE](getting-started/how-it-works.md#6-co-re-and-portability): compile once, run on any kernel with BTF
- Human-readable [verifier diagnostics](diagnostics.md)


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

!!! warning "BPF code runs in the kernel, not the JVM"
    `@BPFFunction` methods are compiled to BPF bytecode and verified by the Linux kernel before loading.
    They run under strict constraints that ordinary Java code does not: the BPF stack is limited to
    512 bytes, dynamic heap allocation is not available, loops must be bounded, and the kernel verifier
    rejects any program it cannot prove safe. Runtime exceptions, garbage collection, and JVM reflection
    do not apply inside `@BPFFunction` methods. If the verifier rejects your program, hello-ebpf prints
    a human-readable diagnostic — see [Diagnostics](diagnostics.md).

## Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| Linux kernel | 6.14 |
| clang / llvm | 19 |
| libbpf-dev | any recent |
| JDK | 22 |
| Privileges | root or CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN |

Install the native dependencies on Debian/Ubuntu:

```bash
sudo apt install -y clang-19 llvm-19 libbpf-dev linux-headers-$(uname -r)
```

See [Install & Prerequisites](getting-started/install.md) to add hello-ebpf to your Maven project.

## Quick example: XDP drop every 3rd packet

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.XDPContext;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;

@BPF(license = "GPL")
public abstract class DropEveryThird extends BPFProgram implements XDPHook {

    /** Packet counter shared between BPF and Java. */
    final GlobalVariable<Long> packetCount = new GlobalVariable<>(0L);

    @Override
    @BPFFunction
    public xdp_action xdpHandlePacket(XDPContext ctx) {
        long count = packetCount.get() + 1;
        packetCount.set(count);
        // Drop every third packet
        if (count % 3 == 0) {
            return xdp_action.XDP_DROP;
        }
        return xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws Exception {
        try (DropEveryThird prog = BPFProgram.load(DropEveryThird.class)) {
            prog.xdpAttach();
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
sudo java --enable-native-access=ALL-UNNAMED -cp target/myapp.jar DropEveryThird
```

!!! note "Network interface"
    `xdpAttach()` attaches to all non-loopback interfaces that are up. To attach to a
    specific interface, look up its index (from `ip link`) and call `xdpAttach(ifindex)`.

!!! note "--enable-native-access"
    hello-ebpf uses the Panama foreign-function API to call libbpf. Pass
    `--enable-native-access=ALL-UNNAMED` on every `java` invocation to suppress the
    module-system warning (required on JDK 24+).

See also: [XDP hook docs](xdp.md) · [BPF Maps](maps.md) · [Global Variables](global-variables.md)

<iframe width="560" height="315" src="https://www.youtube.com/embed/16Rv7IWGoDk" title="hello-ebpf XDP demo" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## Quick example: custom Linux scheduler

hello-ebpf can replace the Linux CPU scheduler with pure Java code via [sched_ext](sched_ext.md).
Here is [`MinimalScheduler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java) — the complete program, nothing omitted:

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "minimal_scheduler")
@Property(name = "timeout_ms", value = "10000")
public abstract class MinimalScheduler extends SchedulerBase implements Scheduler {

    // SchedulerBase.init() creates the shared dispatch queue automatically
    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        // Put every task into the shared FIFO queue
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        // Each CPU pulls the next task from the shared queue
        shared.moveToLocal();
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(MinimalScheduler.class)) {
            program.runSchedulerLoop();
        }
    }
}
```

```bash
sudo ./run.sh MinimalScheduler
```

The scheduler runs until you press `Ctrl-C`, at which point the kernel falls back to the default scheduler. See [sched_ext documentation](sched_ext.md) for priority queues, per-CPU dispatch, and userspace scheduling policies.

## History

The project started in December 2023 as an experiment: could Java become a first-class
language for eBPF, without wrapping C or shelling out to a separate toolchain?
The first prototype, published with [Part 1 of the blog series](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/),
used a javac annotation processor to translate `@BPFFunction` method bodies to C.
That core idea has stayed the same; the library has grown around it.

By mid-2024 the compiler plugin could handle maps, ring buffers, global variables, XDP,
TC, kprobes, tracepoints, and uprobes.
[Part 11](https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/)
added CO-RE support by auto-generating 13,000 Java wrapper classes from kernel BTF,
making programs portable across kernel versions without recompilation.

The scheduler work began in
[Part 15](https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/)
with a BPF-side sched_ext scheduler, and culminated in a fully userspace scheduler
where the scheduling policy runs entirely in Java (Parts 16–18).
The 20-part blog series documents the whole journey.

## Samples

Ready-to-run programs in [`bpf-samples/`](https://github.com/parttimenerd/hello-ebpf/tree/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples):

| Sample | What it does |
|--------|-------------|
| [HelloWorld](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloWorld.java) | Print filenames on every `openat2` call |
| [HashMapSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HashMapSample.java) | Count `openat2` calls per process using `BPFHashMap` |
| [RingSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/RingSample.java) | Stream filename+pid events to userspace via ring buffer |
| [SyscallCounter](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/SyscallCounter.java) | Count all syscalls over 5 s with a global variable |
| [XDPDropEveryThirdPacket](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPDropEveryThirdPacket.java) | Drop every third incoming packet at XDP |
| [PacketCountByLength](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/PacketCountByLength.java) | Histogram of packet lengths using XDP |
| [TCDropEveryThirdOutgoingPacket](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TCDropEveryThirdOutgoingPacket.java) | Drop ~1/3 of outgoing packets via TC egress |
| [TCFirewall](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TCFirewall.java) | Block ingress traffic on ports specified at runtime |
| [Firewall](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/Firewall.java) | Full XDP firewall with per-IP rules and ring-buffer event log |
| [PacketLogger](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/PacketLogger.java) | Log packets via XDP + TC to a ring buffer |
| [KProbeMultiCounter](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/KProbeMultiCounter.java) | One program attached to 20 syscall entries (`kprobe.multi`) |
| [LSMDemo](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/LSMDemo.java) | Observe `file_open`, `bpf`, `socket_create` LSM hooks |
| [CGroupBlockHTTPEgress](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CGroupBlockHTTPEgress.java) | Block all cgroup egress HTTP traffic |
| [TimerDemo](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TimerDemo.java) | Self-rearming 1-second BPF timer |
| [TailCallDemo](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TailCallDemo.java) | XDP tail calls via `BPFProgArray` |
| [HelloCubicSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java) | Register a TCP congestion algorithm via `struct_ops` |
| [CPUProfiler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CPUProfiler.java) | CPU profiler with stack-trace symbolisation |
| [FeatureProbeSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/FeatureProbeSample.java) | Print kernel version and feature-probe table |
| [sched/MinimalScheduler](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java) | Minimal FIFO sched_ext scheduler in Java |
| [sched/RustlandFifoSample](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/RustlandFifoSample.java) | Minimal FIFO userspace scheduler (policy entirely in Java) |

See the [full samples index](samples/index.md) for all programs with hook types and descriptions.

## Blog series

This project is accompanied by a 20-part blog series on [mostlynerdless.de](https://mostlynerdless.de/blog/):

| Part | Topic |
|------|-------|
| 1 | [Hello World — first eBPF program in Java](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/) |
| 2 | [eBPF maps — hash maps and counters](https://mostlynerdless.de/blog/2024/01/12/hello-ebpf-recording-data-in-basic-ebpf-maps-2/) |
| 3 | [Perf event buffers](https://mostlynerdless.de/blog/2024/01/29/hello-ebpf-recording-data-in-event-buffers-3/) |
| 4 | [Tail calls and your first eBPF application](https://mostlynerdless.de/blog/2024/02/12/hello-ebpf-tail-calls-and-your-first-ebpf-application-4/) |
| 5 | [First steps with libbpf](https://mostlynerdless.de/blog/2024/02/26/hello-ebpf-first-steps-with-libbpf-5/) |
| 6 | [Ring buffers](https://mostlynerdless.de/blog/2024/03/12/hello-ebpf-ring-buffers-in-libbpf-6/) |
| 7 | [Auto-layouting structs](https://mostlynerdless.de/blog/2024/03/22/hello-ebpf-auto-layouting-structs-7/) |
| 8 | [Generating C code from Java](https://mostlynerdless.de/blog/2024/04/09/hello-ebpf-generating-c-code-8/) |
| 9 | [XDP-based packet filter](https://mostlynerdless.de/blog/2024/04/22/hello-ebpf-xdp-based-packet-filter-9/) |
| 10 | [Global variables](https://mostlynerdless.de/blog/2024/05/21/hello-ebpf-global-variables-10/) |
| 11 | [BTF and 13,000 generated Java classes](https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/) |
| 12 | [Write your eBPF application in pure Java](https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/) |
| 13 | [Packet logger with TC and XDP hooks](https://mostlynerdless.de/blog/2024/08/13/hello-ebpf-a-packet-logger-in-pure-java-using-tc-and-xdp-hooks-13/) |
| 14 | [Lightning-fast firewall with Java & eBPF](https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/) |
| 15 | [Writing a Linux scheduler in Java](https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/) |
| 16 | [Controlling task scheduling from Java](https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/) |
| 17 | [Lottery scheduler with sched_ext](https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/) |
| 18 | [Lottery scheduler in pure Java (bpf_for_each)](https://mostlynerdless.de/blog/2024/12/27/hello-ebpf-writing-a-lottery-scheduler-in-pure-java-with-bpf-for-each-support-18/) |
| 19 | [Concurrency testing with custom schedulers](https://mostlynerdless.de/blog/2025/02/25/helle-ebpf-concurrency-testing-using-custom-linux-schedulers-19/) |
| 20 | [A scheduler controlled by sound](https://mostlynerdless.de/blog/2025/03/25/hello-ebpf-a-scheduler-controlled-by-sound-20/) |

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
