# Cheat Sheet — Java ↔ Kernel / C

Quick reference for every mapping the hello-ebpf compiler plugin understands.

## Program skeleton

| Java | Kernel / C meaning |
|------|-------------------|
| `@BPF(license="GPL") abstract class Foo extends BPFProgram` | Defines a BPF program; license string embedded in ELF |
| `@BPFFunction void myFn(...)` | A C function compiled into the BPF program |
| `@BPFFunction(section = "xdp/foo")` | Override the ELF section name |

## Pointer operations

| Java | Kernel / C |
|------|-----------|
| `Ptr<X> p` | `X *p` |
| `Ptr.of(x)` | `&x` |
| `p.val()` | `*p` (dereference) |
| `p.set(v)` | `*p = v` |
| `p.val().field` | `p->field` |
| `Ptr.of(p.val().field).set(v)` | `p->field = v` |
| `Ptr.<X>cast(p)` | `(X *)p` — safe cast between pointer types |
| `Ptr.voidPointer()` | `(void *)0` / null void pointer |

## Types and structs

| Java | Kernel / C |
|------|-----------|
| `@Type record Foo(int a, int b)` | `struct Foo { int a; int b; };` |
| `@Size(16) String s` | `char s[16]` — fixed-length char array field |
| `BPFJ.charBuf(16)` | `char buf[16] = {}` — stack buffer initialisation |
| `@Unsigned int n` | `u32 n` — treat the Java int as unsigned |
| `@Unsigned long n` | `u64 n` |
| `final static int N = 4` on a `@BPF` class | `static const int N = 4` in generated C |

## Global variables

| Java | Meaning |
|------|---------|
| `GlobalVariable<Long> ctr = new GlobalVariable<>(0L)` | BPF array map of size 1 (kernel) + Java accessor |
| `ctr.get()` | Java-side read (mmap'd) |
| `ctr.set(v)` | Java-side write (mmap'd) |
| `ctr.get()` inside `@BPFFunction` | `ctr` dereference in C |
| `ctr.incrementAndGet()` | Atomic fetch-and-add on the Java side |
| `ctr.addAndGet(delta)` | Atomic add-delta on the Java side |
| `ctr.compareAndSet(expect, update)` | CAS on the Java side |

## Map types

| Java declaration | BPF map type |
|-----------------|-------------|
| `BPFHashMap<K,V>` | `BPF_MAP_TYPE_HASH` |
| `BPFLRUHashMap<K,V>` | `BPF_MAP_TYPE_LRU_HASH` |
| `BPFArray<V>` | `BPF_MAP_TYPE_ARRAY` |
| `BPFRingBuffer<E>` | `BPF_MAP_TYPE_RINGBUF` |
| `BPFPerCpuArray<V>` | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| `BPFBloomFilter<V>` | `BPF_MAP_TYPE_BLOOM_FILTER` |
| `BPFQueue<V>` | `BPF_MAP_TYPE_QUEUE` |
| `BPFStack<V>` | `BPF_MAP_TYPE_STACK` |
| `BPFProgArray` | `BPF_MAP_TYPE_PROG_ARRAY` (tail calls) |

All maps are annotated with `@BPFMapDefinition(maxEntries = N)`.

## Scheduler abstractions (sched_ext)

### DispatchQueue

| Java | Meaning |
|------|---------|
| `new DispatchQueue(id)` | Create a custom DSQ; `scx_bpf_create_dsq(id,-1)` lifted to `init()` |
| `DispatchQueue.attach(id)` | Wrap an already-existing DSQ — no create emitted |
| `DispatchQueue.local()` | `SCX_DSQ_LOCAL` — current CPU's local queue |
| `DispatchQueue.localOn(cpu)` | `SCX_DSQ_LOCAL_ON \| cpu` |
| `DispatchQueue.global()` | `SCX_DSQ_GLOBAL` |
| `dsq.insert(p, slice, flags)` | FIFO insert with explicit slice |
| `dsq.insertScaled(p, flags)` | FIFO insert; slice scaled by queue depth |
| `dsq.insertVtime(p, slice, vtime, flags)` | Vtime-ordered insert |
| `dsq.insertVtimeClamped(p, vtimeNow, flags)` | Vtime insert with idle-budget clamping (WFQ) |
| `DispatchQueue.insertToLocalIfIdle(p, isIdle, slice)` | Fast-path from `selectCPU` |
| `dsq.moveToLocal()` | Move one task to the local CPU queue; returns `true` if moved |
| `dsq.nonEmpty()` | `true` when tasks are waiting |
| `dsq.nrQueued()` | Count of waiting tasks |
| `DispatchQueue.now()` | Monotonic time in ns (`scx_bpf_now()`) |
| `DispatchQueue.kickCpu(cpu, flags)` | Wake a remote CPU |
| `DispatchQueue.yieldNow(p)` | Zero the running task's slice — immediate reschedule |
| `dsq.destroy()` | Destroy a custom DSQ |

### EnqFlags

| Java | Meaning |
|------|---------|
| `EnqFlags.passThrough(enq_flags)` | Wrap the raw `enq_flags` parameter from `enqueue()` |
| `EnqFlags.empty()` | No flags |
| `EnqFlags.of(flag, ...)` | Compose `scx_enq_flags` constants |
| `f.isWakeup()` | `SCX_ENQ_WAKEUP` set? |
| `f.isLast()` | Last runnable task on this CPU? |
| `f.or(other)` | Combine two EnqFlags |

### KickFlags

| Java | Meaning |
|------|---------|
| `KickFlags.idle()` | `SCX_KICK_IDLE` — wake only if the CPU is idle |
| `KickFlags.preempt()` | `SCX_KICK_PREEMPT` — preempt whatever is running |
| `KickFlags.waitForKick()` | `SCX_KICK_WAIT` — wait for the kick to be processed |
| `KickFlags.none()` | No flags |
| `f.or(other)` | Combine two KickFlags |

### CpuMask

`CpuMask` wraps a read-only `const struct cpumask *`. Must be used as a local variable
inside a `@BPFFunction` (never as a field). Always release borrowed masks.

| Java | Meaning |
|------|---------|
| `CpuMask.idle()` | Borrow the global idle CPU mask; release with `releaseIdle()` |
| `CpuMask.idleSmt()` | Idle mask, one logical CPU per physical core |
| `CpuMask.idleOnNode(n)` | Idle mask restricted to NUMA node `n` |
| `CpuMask.online()` | Online CPU mask; release with `release()` |
| `CpuMask.possible()` | Possible CPU mask; release with `release()` |
| `CpuMask.ofTask(p)` | Read-only view of `p->cpus_ptr`; no release needed |
| `mask.test(cpu)` | `true` if `cpu` is set |
| `mask.weight()` | Number of CPUs set |
| `mask.first()` | Lowest-numbered CPU set (or `>= nr_cpu_ids` if empty) |
| `mask.isEmpty()` | `true` if no CPUs set |
| `mask.intersects(other)` | `true` if the two masks share at least one CPU |
| `mask.pickIdle(0)` | Pick and claim an idle CPU; returns CPU or `-EBUSY` |
| `mask.pickAny(0)` | Pick any CPU, preferring idle ones |
| `mask.releaseIdle()` | Release masks from `idle()` / `idleSmt()` / `idleOnNode()` |
| `mask.release()` | Release masks from `online()` / `possible()` |

## Hook interfaces

| Java | BPF hook |
|------|---------|
| `implements XDPHook` | XDP program (express data path) |
| `implements TCHook` | TC classifier (traffic control) |
| `implements Scheduler` | sched_ext scheduler |
| `implements LSMHook` | BPF LSM (requires CONFIG_BPF_LSM=y) |
| `implements CGroupHook` | cgroup ingress/egress |
| `@Kprobe("do_sys_openat2")` on method | kprobe at function entry, auto-attach |
| `@Kretprobe("do_sys_openat2")` on method | kretprobe at function return |
| `@Fentry("do_sys_openat2")` on method | fentry (BTF-based), auto-attach |
| `@Fexit("do_sys_openat2")` on method | fexit (BTF-based) |
| `@Tracepoint(category="syscalls", name="sys_enter_openat")` | tracepoint section |
| `@RawTracepoint("sys_enter")` | raw_tracepoint section |
| `@Ksyscall("openat")` | ksyscall (arch-portable kprobe on syscall) |

## BPFJ helper methods (BPF side)

| Java call | Expands to in C |
|-----------|----------------|
| `BPFJ.bpf_trace_printk(fmt, args)` | `bpf_trace_printk(fmt, sizeof(fmt), args)` |
| `BPFJ.currentPid()` | `(u32)(bpf_get_current_pid_tgid())` |
| `BPFJ.currentTgid()` | `(u32)(bpf_get_current_pid_tgid() >> 32)` |
| `BPFJ.currentNs()` | `bpf_ktime_get_ns()` |
| `BPFJ.getCurrentComm(buf)` | `bpf_get_current_comm(buf, sizeof(buf))` |
| `BPFJ.bpf_loop(n, callback, ctx, flags)` | `bpf_loop(n, callback, ctx, flags)` |
| `BPFJ.bpf_probe_read_user(dst, size, src)` | `bpf_probe_read_user(dst, size, src)` |
| `BPFJ.bpf_probe_read_kernel(dst, size, src)` | `bpf_probe_read_kernel(dst, size, src)` |
| `BPFJ.bpf_skb_store_bytes(skb, off, from, len, flags)` | `bpf_skb_store_bytes(...)` |

## Pointer pattern examples

```java
// Read a struct field through a pointer
Ptr<xdp_md> ctx = ...;
int data = ctx.val().data;

// Write through a nested pointer
Ptr<sock_common> sk = ...;
Ptr.of(sk.val().skc_daddr).set(newAddr);

// Cast void pointer
Ptr<ethhdr> eth = Ptr.cast(Ptr.of(ctx.val().data));
```

## Byte-order note

Network protocols use big-endian (network byte order). x86 hosts are little-endian. Always convert:

```java
// In @BPFFunction — use kernel helpers
int proto = BPFJ.bpf_ntohs(eth.val().h_proto);

// Or use the raw macros via Lib constants
if (eth.val().h_proto == bpf_htons(ETH_P_IP)) { ... }
```

On the Java side, use `Short.reverseBytes()`, `Integer.reverseBytes()`, or `java.nio.ByteOrder`.
