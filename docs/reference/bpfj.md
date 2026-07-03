# BPFJ Helpers Reference

`BPFJ` is a utility class containing static methods that map to BPF kernel helper functions.
Use these inside `@BPFFunction` methods. Each call is translated to the corresponding C
`bpf_*` function by the compiler plugin.

---

## Tracing

### `BPFJ.bpf_trace_printk(fmt, args...)`

Write a formatted string to `/sys/kernel/debug/tracing/trace_pipe`. Useful for debugging.

```java
BPFJ.bpf_trace_printk("pid=%d file=%s\n", pid, filename);
```

Expands to: `bpf_trace_printk(fmt, sizeof(fmt), args...)`

!!! note "Performance"
    `bpf_trace_printk` is slow and should not be used in production paths. Use ring buffers
    for production event streaming.

**Read output:**
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

## String / Buffer

### `BPFJ.charBuf(int size)`

Allocate a zero-initialised stack char buffer of exactly `size` bytes.

```java
var buf = BPFJ.charBuf(256);
BPFJ.bpf_probe_read_user_str(Ptr.cast(buf), 256, userPtr);
```

Expands to: `char buf[256] = {}`

The `size` argument must be a compile-time integer constant.

### `BPFJ.getCurrentComm(buf)`

Fill `buf` with the name of the currently executing process (up to `TASK_COMM_LEN` = 16 bytes).

```java
var comm = BPFJ.charBuf(16);
BPFJ.getCurrentComm(comm);
```

Expands to: `bpf_get_current_comm(buf, sizeof(buf))`

---

## Process / Task Info

### `BPFJ.currentPid()`

Returns the PID of the current process (thread PID, not TGID).

```java
int pid = BPFJ.currentPid();
```

Expands to: `(u32)(bpf_get_current_pid_tgid())`

### `BPFJ.currentTgid()`

Returns the TGID (process group ID, what `getpid()` returns in user-space).

```java
int tgid = BPFJ.currentTgid();
```

Expands to: `(u32)(bpf_get_current_pid_tgid() >> 32)`

### `BPFJ.currentNs()`

Returns the current monotonic timestamp in nanoseconds.

```java
long ts = BPFJ.currentNs();
```

Expands to: `bpf_ktime_get_ns()`

### `BPFJ.currentUid()`

Returns the UID of the current process.

```java
int uid = BPFJ.currentUid();
```

Expands to: `(u32)(bpf_get_current_uid_gid())`

### `BPFJ.currentGid()`

Returns the GID of the current process.

```java
int gid = BPFJ.currentGid();
```

Expands to: `(u32)(bpf_get_current_uid_gid() >> 32)`

---

## Memory — Probe Reads

Use these to safely read memory that may be in user-space or in potentially-faulting kernel
addresses. Direct pointer dereference of user pointers will be rejected by the BPF verifier.

### `BPFJ.bpf_probe_read_user(dst, size, src)`

Read `size` bytes from user-space address `src` into `dst`.

```java
BPFJ.bpf_probe_read_user(Ptr.cast(myBuf), 64, userPtr);
```

### `BPFJ.bpf_probe_read_kernel(dst, size, src)`

Read `size` bytes from a kernel address.

```java
BPFJ.bpf_probe_read_kernel(Ptr.cast(dst), sizeof(dst), Ptr.of(kernelObj));
```

### `BPFJ.bpf_probe_read_user_str(dst, size, src)`

Read a null-terminated string from user-space. Returns the string length (including null
terminator) or a negative error code.

```java
long len = BPFJ.bpf_probe_read_user_str(Ptr.cast(myBuf), 256, userStrPtr);
```

### `BPFJ.bpf_probe_read_kernel_str(dst, size, src)`

Read a null-terminated string from kernel memory.

---

## Packet / Socket Helpers

### `BPFJ.bpf_skb_store_bytes(skb, offset, from, len, flags)`

Write `len` bytes from `from` into the socket buffer at `offset`.
Available in TC programs.

```java
short newProto = bpf_htons(ETH_P_IP);
BPFJ.bpf_skb_store_bytes(skb, 12, Ptr.of(newProto), 2, BPF_F_RECOMPUTE_CSUM);
```

### `BPFJ.bpf_l3_csum_replace(skb, offset, from, to, flags)`

Incrementally update the L3 (IP) checksum after rewriting a field.

### `BPFJ.bpf_l4_csum_replace(skb, offset, from, to, flags)`

Incrementally update the L4 (TCP/UDP) checksum.

### `BPFJ.bpf_redirect(ifindex, flags)`

Redirect a packet to another interface (use in XDP or TC).

---

## Atomics

BPF verifier-approved atomic operations for shared counters. These are needed when multiple
CPUs may update the same map value concurrently without per-CPU maps.

### `BPFJ.bpf_atomic_add(ptr, delta)`

Atomically add `delta` to `*ptr`. Returns the old value.

```java
Ptr<Long> val = myMap.bpf_get(key);
if (val != null) {
    BPFJ.bpf_atomic_add(val, 1L);
}
```

Expands to: `__sync_fetch_and_add(ptr, delta)` (kernel) or `BPF_ATOMIC_ADD` (newer kernels).

### `BPFJ.bpf_atomic_cmpxchg(ptr, expected, desired)`

Atomic compare-and-exchange. Returns the original value at `*ptr`.

---

## Control Flow

### `BPFJ.bpf_loop(nr_loops, callback, ctx, flags)`

Execute `callback` up to `nr_loops` times. This is a bounded loop construct that satisfies
the BPF verifier when the loop count is not a compile-time constant.

```java
BPFJ.bpf_loop(packetCount, (i, data) -> {
    // process packet i
    return 0;   // continue; return 1 to break
}, ctx, 0);
```

Expands to: `bpf_loop(nr_loops, callback, ctx, flags)`

!!! note "Kernel ≥5.17"
    `bpf_loop` requires kernel 5.17. For older kernels, use bounded `for` loops with a
    compile-time constant upper bound.

### `BPFJ.bpf_tail_call(ctx, prog_array, index)`

Jump to another BPF program via a `BPFProgArray` tail call. Does not return on success.

```java
BPFJ.bpf_tail_call(ctx, jumptable, 0);
// Only reached if tail call fails
return XDP_DROP;
```

---

## Miscellaneous

### `BPFJ.bpf_get_smp_processor_id()`

Returns the current CPU index. Useful for indexing per-CPU data structures.

```java
int cpu = BPFJ.bpf_get_smp_processor_id();
```

### `BPFJ.bpf_perf_event_output(ctx, map, flags, data, size)`

Write data to a perf event array (older alternative to ring buffer).

### `BPFJ.bpf_get_stack(ctx, buf, size, flags)`

Capture a kernel or user-space stack trace into `buf`.

### `BPFJ.bpf_csum_diff(from, from_size, to, to_size, seed)`

Compute the incremental checksum difference when rewriting packet fields.

### `BPFJ.bpf_skb_pull_data(skb, len)`

Ensure `len` bytes of the socket buffer are linearly accessible. Required before
`bpf_skb_store_bytes` on non-linear skbs.

---

## Ring Buffer

### `BPFJ.bpf_ringbuf_reserve(map, size, flags)`

Reserve `size` bytes in the ring buffer map. Returns a pointer to the reserved slot, or null
if the ring buffer is full.

```java
Ptr<Event> e = BPFJ.bpf_ringbuf_reserve(events, BPFType.sizeOf(Event.class), 0);
if (e == null) {
    return 0;
}
e.val().pid = BPFJ.currentPid();
BPFJ.bpf_ringbuf_submit(e, 0);
```

Expands to: `bpf_ringbuf_reserve(map, size, flags)`

### `BPFJ.bpf_ringbuf_submit(data, flags)`

Submit a previously reserved slot. The slot becomes visible to userspace readers after this call.

```java
Ptr<Event> e = BPFJ.bpf_ringbuf_reserve(events, BPFType.sizeOf(Event.class), 0);
if (e == null) {
    return 0;
}
e.val().pid = BPFJ.currentPid();
BPFJ.bpf_ringbuf_submit(e, 0);
```

Expands to: `bpf_ringbuf_submit(data, flags)`

!!! note
    Always call either `bpf_ringbuf_submit` or `bpf_ringbuf_discard` for every reserved slot.
    Leaking a reservation stalls the ring buffer consumer.

### `BPFJ.bpf_ringbuf_discard(data, flags)`

Discard a previously reserved slot without making it visible to userspace.

```java
BPFJ.bpf_ringbuf_discard(e, 0);
```

Expands to: `bpf_ringbuf_discard(data, flags)`

---

## Attach cookies

### `BPFJ.bpf_get_attach_cookie(ctx)`

Read the `u64` cookie bound to this particular attachment of the program. Returns 0 if no
cookie was set at attach time.

```java
long cookie = BPFJ.bpf_get_attach_cookie(ctx);
switch ((int) cookie) {
    case 1 -> handleOpen(ctx);
    case 2 -> handleClose(ctx);
}
```

Expands to: `bpf_get_attach_cookie(ctx)`

!!! note "Kernel ≥ 5.15"
    Attach-cookie support for kprobes requires kernel 5.15. See
    [Attach cookies with multi-kprobe](../attach-cookies-multi.md) for usage patterns.

---

## Arena helpers

### `BPFJ.bpfArenaAllocPages(arena, user_addr, page_cnt, node, flags)`

Allocate `page_cnt` pages inside a BPF arena. Returns null on failure.

```java
Ptr<Void> mem = BPFJ.bpfArenaAllocPages(myArena, 0L, 4, -1, 0);
if (mem == null) {
    return 0;
}
```

Expands to: `bpf_arena_alloc_pages(&arena, user_addr, page_cnt, node, flags)`

!!! note "Kernel ≥ 6.9"
    BPF arenas require kernel 6.9.

!!! note "page_cnt = 0"
    Passing `page_cnt = 0` returns null immediately. The compiler plugin uses this call to
    anchor the arena to a program without allocating any pages.

---

## Timers

### `BPFJ.newZeroedTimer()`

Return a zero-initialised `bpf_timer` suitable for insertion into a BPF map. The default
constructor leaves the internal opaque pointer null, which causes the kernel to fault when
the map entry is serialised — always use this factory.

```java
TimerVal v = new TimerVal();
v.timer = BPFJ.newZeroedTimer();
prog.timerMap.put(0, v);
```

See [Timers](../timers.md) for full timer usage including `bpf_timer_init` and
`bpf_timer_start`.

### `BPFJ.bpf_timer_set_callback(timer, method)`

Register a BPF timer callback. Accepts a method reference; the compiler plugin lowers it to
the bare C identifier expected by the kernel.

```java
TimerVal val = prog.timerMap.bpf_get(0);
if (val != null) {
    BPFJ.bpf_timer_set_callback(Ptr.of(val.val().timer), this::onTick);
}
```

Expands to: `bpf_timer_set_callback(timer, callback)`

---

## Byte-order helpers

These are available as C macros in the generated code (not `BPFJ` methods but imported
via `Lib_1.*`):

| Java | C |
|------|---|
| `bpf_htons(x)` | `__builtin_bswap16(x)` |
| `bpf_ntohs(x)` | `__builtin_bswap16(x)` |
| `bpf_htonl(x)` | `__builtin_bswap32(x)` |
| `bpf_ntohl(x)` | `__builtin_bswap32(x)` |
| `bpf_cpu_to_be64(x)` | `__builtin_bswap64(x)` |
