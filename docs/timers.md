# BPF Timers (`@BPFTimer`)

**Javadoc:** [`BPFTimer`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFTimer.html)
**Source:** [`BPFTimerMap.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFTimerMap.java)

BPF timers let a BPF program schedule a callback that fires entirely inside the kernel,
without leaving to userspace. The callback runs in softirq context and can re-arm itself,
making timers suitable for periodic stats flushing, rate-limit resets, or timeout-based
map cleanup without a userspace polling loop. Requires kernel ≥ 5.15.

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

- Kernel ≥ 5.15 required (`bpf_timer` added in 5.15).
- `bpf_timer` is restricted to network, `sk_msg`, `struct_ops`, and cgroup program types
  on recent kernels; kprobe and tracepoint programs cannot host timers.
- One timer per map entry — store `bpf_timer` as a struct field in the map value.
- No sleeping helpers inside the callback (softirq context).
- `bpf_timer_cancel` inside the callback's own timer causes `-EDEADLK`.
- The timer is cancelled automatically when the owning map loses all references.

## Full example

`bpf-samples/src/main/java/me/bechberger/ebpf/samples/TimerDemo.java` — an XDP program
that arms a 1-second self-rearming timer on the first incoming packet and exposes the tick
count as a `GlobalVariable` readable from Java.

---

## Examples

- [`TimerDemo.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TimerDemo.java) — periodic BPF timer with ring buffer output
