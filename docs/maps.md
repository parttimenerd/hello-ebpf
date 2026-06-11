# BPF Maps

Maps are the primary mechanism for sharing data between BPF programs and user-space Java code.
hello-ebpf provides typed Java wrappers for all major map types. Maps are declared as fields on
your `@BPF` class and annotated with `@BPFMapDefinition`.

## Declaration pattern

```java
@BPF(license = "GPL")
public abstract class MyProg extends BPFProgram {

    @BPFMapDefinition(maxEntries = 1024)
    final BPFHashMap<Integer, Long> counts = BPFHashMap.newInstance();
}
```

The compiler plugin generates the corresponding `SEC(".maps")` definition in C.

---

## BPFHashMap<K, V>

**When to use:** General-purpose key/value store. Lookups are O(1) average.

**Map type:** `BPF_MAP_TYPE_HASH`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 10_000)
final BPFHashMap<@Unsigned Integer, Long> pidToCount = BPFHashMap.newInstance();
```

**BPF-side API (inside `@BPFFunction`):**
```java
Ptr<Long> valPtr = pidToCount.bpf_get(pid);   // returns Ptr<V> — may be null!
if (valPtr != null) {
    valPtr.set(valPtr.val() + 1);
} else {
    long zero = 0;
    pidToCount.bpf_put(pid, zero);
}
pidToCount.bpf_delete(pid);
```

!!! warning "`bpf_get` returns `Ptr<V>`, not `V`"
    Always null-check the result of `bpf_get`. If the key is absent the pointer is null and
    dereferencing it will crash the BPF verifier.

**Java-side API:**
```java
prog.pidToCount.get(1234);          // Optional<Long>
prog.pidToCount.put(1234, 99L);
prog.pidToCount.delete(1234);
prog.pidToCount.forEach((k, v) -> System.out.println(k + " -> " + v));
```

---

## BPFLRUHashMap<K, V>

**When to use:** Like `BPFHashMap` but automatically evicts least-recently-used entries when full.
Ideal for connection tracking or caches where stale entries are acceptable.

**Map type:** `BPF_MAP_TYPE_LRU_HASH`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 65536)
final BPFLRUHashMap<Long, ConnInfo> connTable = BPFLRUHashMap.newInstance();
```

API is identical to `BPFHashMap`.

---

## BPFArray<V>

**When to use:** Fixed-size indexed array. All entries exist from creation (no null for missing
entries). Great for per-index counters or lookup tables.

**Map type:** `BPF_MAP_TYPE_ARRAY`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 256)
final BPFArray<Long> histogram = BPFArray.newInstance();
```

**BPF-side API:**
```java
// Index must be a constant or a verified variable in [0, maxEntries)
Ptr<Long> slot = histogram.bpf_get(index);   // never null for arrays
if (slot != null) {
    slot.set(slot.val() + 1);
}
```

**Java-side API:**
```java
prog.histogram.get(42);             // Optional<Long>
prog.histogram.put(42, 0L);
```

---

## BPFRingBuffer<E>

**When to use:** Low-overhead, variable-size event streaming from BPF to user-space.
Prefer over perf event arrays for new code (kernel ≥5.8).

**Map type:** `BPF_MAP_TYPE_RINGBUF`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 1 << 24)   // size in bytes, must be power of 2
final BPFRingBuffer<Event> events = BPFRingBuffer.newInstance(Event.class);
```

**BPF-side API:**
```java
Ptr<Event> e = events.reserve();
if (e != null) {
    e.val().pid  = BPFJ.currentPid();
    e.val().tgid = BPFJ.currentTgid();
    events.submit(e);
}
// Or discard: events.discard(e);
```

**Java-side API:**
```java
prog.events.setCallback((event) -> System.out.println("pid=" + event.pid));
BPFProgram.ringBufferManager().consumeAll();   // poll in a loop
```

---

## BPFPerCpuArray<V>

**When to use:** Per-CPU counters. Each CPU has its own independent copy — no locking, maximum
throughput. Aggregate values Java-side by summing across CPUs.

**Map type:** `BPF_MAP_TYPE_PERCPU_ARRAY`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 1)
final BPFPerCpuArray<Long> pktCount = BPFPerCpuArray.newInstance();
```

**BPF-side API:** identical to `BPFArray`.

**Java-side API:**
```java
List<Long> perCpu = prog.pktCount.getAll(0);  // one value per CPU
long total = perCpu.stream().mapToLong(Long::longValue).sum();
```

---

## BPFBloomFilter<V>

**When to use:** Probabilistic membership test. Zero false negatives; small false-positive rate.
Useful for quick rejection of known-bad IPs or processes.

**Map type:** `BPF_MAP_TYPE_BLOOM_FILTER` (kernel ≥5.16)

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 10_000)
final BPFBloomFilter<Integer> blocklist = BPFBloomFilter.newInstance();
```

**BPF-side API:**
```java
if (blocklist.bpf_peek(suspectIp) == 0) {
    // Definitely not in set — pass
    return XDP_PASS;
}
// Probably in set — apply heavier check or drop
return XDP_DROP;
```

**Java-side API:**
```java
prog.blocklist.add(0xC0A80001);   // 192.168.0.1
```

---

## BPFQueue<V>

**When to use:** FIFO queue. BPF enqueues events; Java dequeues them. Simpler than ring buffer
when variable-length records are not needed.

**Map type:** `BPF_MAP_TYPE_QUEUE`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 512)
final BPFQueue<Event> queue = BPFQueue.newInstance();
```

**BPF-side API:**
```java
Event e = new Event();
e.pid = BPFJ.currentPid();
queue.bpf_push(e);
```

**Java-side API:**
```java
Optional<Event> e = prog.queue.pop();
```

---

## BPFStack<V>

**When to use:** LIFO stack. Otherwise identical to `BPFQueue`.

**Map type:** `BPF_MAP_TYPE_STACK`

API mirrors `BPFQueue`; `pop()` returns the most-recently-pushed entry.

---

## BPFProgArray

**When to use:** Tail calls — jump from one BPF program to another without returning.
The array maps integer indices to loaded BPF programs.

**Map type:** `BPF_MAP_TYPE_PROG_ARRAY`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 8)
final BPFProgArray jumptable = BPFProgArray.newInstance();
```

**BPF-side API:**
```java
// In @BPFFunction
jumptable.bpf_tail_call(ctx, index);
// Execution continues here only if tail call fails (index out of range / map empty)
```

**Java-side setup:**
```java
prog.jumptable.set(0, prog.getFd("handle_ipv4"));
prog.jumptable.set(1, prog.getFd("handle_ipv6"));
```

---

## Common patterns

### Initialise a map entry atomically

```java
// BPF side — safe increment even under concurrency
Ptr<Long> val = counts.bpf_get(key);
if (val == null) {
    long zero = 1;
    counts.bpf_put(key, zero);
} else {
    // __sync_fetch_and_add via BPFJ if needed
    val.set(val.val() + 1);
}
```

### Iterate over a hash map from Java

```java
prog.counts.forEach((k, v) -> {
    System.out.printf("key=%d count=%d%n", k, v);
    prog.counts.delete(k);   // reset as we read
});
```
