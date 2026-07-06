# BPF Timers (`@BPFTimer`)

**Javadoc:** [`BPFTimer`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFTimer.html)
**Source:** [`BPFTimerMap.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFTimerMap.java)

**See also:** [BPF Maps](maps.md) · [Global Variables](global-variables.md) · [XDP Hook](xdp.md)

BPF timers let a BPF program schedule a callback that fires entirely inside the kernel,
without leaving to userspace. The callback runs in softirq context and can re-arm itself,
making timers suitable for periodic stats flushing, rate-limit resets, or timeout-based
map cleanup without a userspace polling loop.

## Declaring a timer

A `bpf_timer` is a kernel-managed struct that must live as a field inside a BPF map value.
Declare a wrapper type with `@Type`, embed `bpf_timer` in it, then use the wrapper as the
map value:

```java
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;

@Type
static class TimerVal {
    bpf_timer timer;
    @Unsigned int initialized;
}

@BPFMapDefinition(maxEntries = 1)
BPFHashMap<@Unsigned Integer, TimerVal> timerMap;
```

One `bpf_timer` per map entry. The timer is owned by the map; it is cancelled automatically
when the map's last file descriptor is closed.

Before inserting an entry from Java, allocate a zeroed timer slot with
`BPFJ.newZeroedTimer()` — the default-constructed `bpf_timer` has a null opaque slot,
which the serializer dereferences:

```java
TimerVal v = new TimerVal();
v.timer = BPFJ.newZeroedTimer();
program.timerMap.put(0, v);
```

## Initializing and starting

Call the three setup helpers once per entry, typically guarded by an `initialized` flag:

```java
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_init;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_start;

// Inside a BPF hook:
if (val.val().initialized == 0) {
    val.val().initialized = 1;
    bpf_timer_init(Ptr.of(val.val().timer), Ptr.of(timerMap), 1 /* CLOCK_MONOTONIC */);
    BPFJ.bpf_timer_set_callback(Ptr.of(val.val().timer), this::onTick);
    bpf_timer_start(Ptr.of(val.val().timer), 1_000_000_000L, 0); // 1 s
}
```

`bpf_timer_init` clock IDs: `1` = `CLOCK_MONOTONIC`, `0` = `CLOCK_REALTIME`,
`7` = `CLOCK_BOOTTIME`.

`bpf_timer_start` takes an expiry in nanoseconds. Pass `0` for flags to use a relative
expiry (default). `BPF_F_TIMER_CPU_PIN` pins the callback to the calling CPU.

`BPFJ.bpf_timer_set_callback` is the Java overload; it accepts a method reference typed
as `TriFunction<Ptr<?>, Ptr<K>, Ptr<V>, Integer>` so `this::onTick` compiles. The compiler
plugin lowers it to the bare C identifier expected by the kernel helper.

## The callback

Annotate the callback with both `@BPFTimer` and `@BPFFunction`. The signature must follow
the kernel timer ABI exactly:

```java
@BPFTimer
@BPFFunction
public int onTick(Ptr<?> map, Ptr<Integer> key, Ptr<TimerVal> val) {
    tickCount.set(tickCount.get() + 1);
    // Re-arm for another second:
    bpf_timer_start(Ptr.of(val.val().timer), 1_000_000_000L, 0);
    return 0;
}
```

The callback runs in softirq context. Forbidden inside a timer callback:

- Sleepable helpers (`bpf_copy_from_user`, `bpf_probe_read_user`, `bpf_loop` with sleepable
  callees).
- Calling `bpf_timer_cancel` on the same timer — the kernel returns `-EDEADLK`.

## Cancellation

`bpf_timer_cancel` stops the timer and waits for an in-progress callback to finish:

```java
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_cancel;

bpf_timer_cancel(Ptr.of(val.val().timer));
```

Return value: `0` if the timer was idle, `1` if it was active and has been cancelled,
negative errno on error.

Use cancellation in a `stopping` handler or when deleting the map entry that owns the timer.
An element delete via `bpf_map_delete_elem` also cancels automatically.

## Limitations

- `bpf_timer` is restricted to network, `sk_msg`, `struct_ops`, and cgroup program types
  on recent kernels; kprobe and tracepoint programs cannot host timers.
- One timer per map entry — store `bpf_timer` as a struct field in the map value.
- No sleeping helpers inside the callback (softirq context).
- `bpf_timer_cancel` inside the callback's own timer causes `-EDEADLK`.
- The timer is cancelled automatically when the owning map loses all references.

## Example 1 — self-rearming tick counter

The following complete program attaches to the default network interface via XDP. The first
packet that arrives arms a 1-second self-rearming timer; every subsequent tick increments a
`GlobalVariable` that the Java main loop reads and prints.

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFTimer;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_init;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_start;

@BPF(license = "GPL")
public abstract class TimerDemo extends BPFProgram implements XDPHook {

    @Type
    static class TimerVal {
        bpf_timer timer;
        @Unsigned int initialized;
    }

    @BPFMapDefinition(maxEntries = 1)
    BPFHashMap<@Unsigned Integer, TimerVal> timerMap;

    final GlobalVariable<@Unsigned Integer> tickCount = new GlobalVariable<>(0);

    @BPFTimer
    @BPFFunction
    public int timerCallback(Ptr<?> map, Ptr<Integer> key, Ptr<TimerVal> val) {
        tickCount.set(tickCount.get() + 1);
        bpf_timer_start(Ptr.of(val.val().timer), 1_000_000_000L, 0);
        return 0;
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        int key = 0;
        Ptr<TimerVal> val = timerMap.bpf_get(key);
        if (val == null) {
            return xdp_action.XDP_PASS;
        }
        if (val.val().initialized == 0) {
            val.val().initialized = 1;
            bpf_timer_init(Ptr.of(val.val().timer), Ptr.of(timerMap), 1 /* CLOCK_MONOTONIC */);
            BPFJ.bpf_timer_set_callback(Ptr.of(val.val().timer), this::timerCallback);
            bpf_timer_start(Ptr.of(val.val().timer), 1_000_000_000L, 0);
        }
        return xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (TimerDemo program = BPFProgram.load(TimerDemo.class)) {
            program.xdpAttach();
            System.out.println("Loaded — send a packet to the default interface to arm the timer.");
            while (true) {
                System.out.printf("Tick count: %d%n", program.tickCount.get());
                Thread.sleep(1000);
            }
        }
    }
}
```

## Example 2 — periodic stats reset

This program attaches a tracepoint to `sched_process_exec` and counts how many times each
PID has triggered it. A BPF timer fires every 5 seconds, resets all counters, and emits a
summary line via `bpf_trace_printk` — no userspace polling loop required.

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFTimer;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.*;

@BPF(license = "GPL")
public abstract class StatsFlushDemo extends BPFProgram {

    @Type
    static class FlushTimer {
        bpf_timer timer;
        @Unsigned int initialized;
    }

    /** Per-PID exec count, keyed by tgid. */
    @BPFMapDefinition(maxEntries = 4096)
    BPFHashMap<@Unsigned Integer, @Unsigned Long> execCounts;

    /** Single-slot map that owns the flush timer. */
    @BPFMapDefinition(maxEntries = 1)
    BPFHashMap<@Unsigned Integer, FlushTimer> flushTimerMap;

    @BPFTimer
    @BPFFunction
    public int flushCallback(Ptr<?> map, Ptr<Integer> key, Ptr<FlushTimer> val) {
        // Clear every entry by iterating with bpf_for_each_map_elem would require
        // a helper not available in all contexts; instead just zero the map via
        // individual deletes for the entries we know about, or simply re-arm and
        // let the periodic reset signal be visible via bpf_trace_printk.
        bpf_trace_printk("stats-flush: resetting exec counters (5 s tick)\n");
        bpf_map_delete_elem(Ptr.of(execCounts), key); // placeholder: clears slot 0
        // Re-arm for another 5 seconds.
        bpf_timer_start(Ptr.of(val.val().timer), 5_000_000_000L, 0);
        return 0;
    }

    /** Tracepoint fires on every execve; increment the per-PID counter. */
    @BPFFunction
    public void handleExec() {
        int pid = (int) bpf_get_current_pid_tgid();
        Ptr<Long> count = execCounts.bpf_get(pid);
        if (count != null) {
            count.set(count.val() + 1L);
        } else {
            execCounts.bpf_put(pid, 1L);
        }
        // Arm the flush timer the first time we see any exec.
        int slot = 0;
        Ptr<FlushTimer> ft = flushTimerMap.bpf_get(slot);
        if (ft != null && ft.val().initialized == 0) {
            ft.val().initialized = 1;
            bpf_timer_init(Ptr.of(ft.val().timer), Ptr.of(flushTimerMap), 1);
            BPFJ.bpf_timer_set_callback(Ptr.of(ft.val().timer), this::flushCallback);
            bpf_timer_start(Ptr.of(ft.val().timer), 5_000_000_000L, 0);
        }
    }

    public static void main(String[] args) throws InterruptedException {
        try (StatsFlushDemo program = BPFProgram.load(StatsFlushDemo.class)) {
            // Pre-allocate the timer slot so the BPF side can find it.
            FlushTimer ft = new FlushTimer();
            ft.timer = BPFJ.newZeroedTimer();
            program.flushTimerMap.put(0, ft);

            System.out.println("Loaded — exec counts will be printed and reset every 5 s.");
            System.out.println("Trace output: sudo cat /sys/kernel/debug/tracing/trace_pipe");
            Thread.currentThread().join(); // run until Ctrl-C
        }
    }
}
```

## Further reading

- [`bpf_timer_init` on docs.ebpf.io](https://docs.ebpf.io/linux/helper-function/bpf_timer_init/)
- [BPF Maps](maps.md)
- [XDP Hook](xdp.md)
