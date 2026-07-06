# BPF Maps

**Javadoc:** [`BPFHashMap`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFHashMap.html) · [`BPFArray`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFArray.html) · [`BPFRingBuffer`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFRingBuffer.html) · [`BPFPerCpuArray`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFPerCpuArray.html) · [`BPFPerCpuHashMap`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFPerCpuHashMap.html)
**Source:** [`BPFHashMap.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHashMap.java) · [`BPFArray.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArray.java) · [`BPFRingBuffer.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFRingBuffer.java) · [`BPFPerCpuArray.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFPerCpuArray.java) · [`BPFPerCpuHashMap.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFPerCpuHashMap.java)
**See also:** [Ring Buffer](maps.md#bpfringbuffere) · [Global Variables](global-variables.md) · [Map of Maps](map-of-maps.md) · [Shared Maps](shared-maps.md) · [Tail Calls](tail-calls.md)

Maps are the primary mechanism for sharing data between BPF programs and user-space Java code.
hello-ebpf provides typed Java wrappers for all major map types. Maps are declared as fields on
your `@BPF` class and annotated with `@BPFMapDefinition`.

**Blog series:** [Part 2 — Recording data in basic eBPF maps](https://mostlynerdless.de/blog/2024/01/12/hello-ebpf-recording-data-in-basic-ebpf-maps-2/) · [Part 6 — Ring buffers in libbpf](https://mostlynerdless.de/blog/2024/03/12/hello-ebpf-ring-buffers-in-libbpf-6/)
**Javadoc:** [`BPFHashMap`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFHashMap.html) · [`BPFArray`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFArray.html) · [`BPFRingBuffer`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFRingBuffer.html) · [`BPFPerCpuArray`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFPerCpuArray.html) · [`BPFPerCpuHashMap`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFPerCpuHashMap.html)

![eBPF map as bidirectional bridge between kernel and user space](https://mostlynerdless.de/wp-content/uploads/2024/01/ebpf_maps-2000x425.png)

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
Prefer over perf event arrays for new code.

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
prog.consumeAndThrow();   // poll ring buffer (or prog.consumeAndSleep(intervalMs))
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

**Map type:** `BPF_MAP_TYPE_BLOOM_FILTER`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 10_000)
final BPFBloomFilter<Integer> blocklist = BPFBloomFilter.newInstance();
```

**BPF-side API:**
```java
if (blocklist.peek(suspectIp)) {
    // Probably in set — apply heavier check or drop
    return XDP_DROP;
}
// Definitely not in set — pass
return XDP_PASS;
```

**Java-side API:**
```java
prog.blocklist.put(0xC0A80001);   // 192.168.0.1
```

---

## BPFPerCpuHashMap<K, V>

**When to use:** Per-CPU hash map for lock-free counters keyed by an arbitrary value. Each CPU
has its own value slot; aggregate Java-side by summing across CPUs.

**Map type:** `BPF_MAP_TYPE_PERCPU_HASH`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 4096)
final BPFPerCpuHashMap<Integer, Long> pidBytes = BPFPerCpuHashMap.newInstance();
```

**BPF-side API:** identical to `BPFHashMap` (`bpf_get`, `bpf_put`, `bpf_delete`).

**Java-side API:**
```java
List<Long> perCpuValues = prog.pidBytes.getAll(pid);   // one value per CPU
long total = perCpuValues.stream().mapToLong(Long::longValue).sum();
```

---

## BPFHashOfMaps<K, InnerMap> / BPFArrayOfMaps<InnerMap>

**When to use:** A map whose values are themselves maps — e.g. per-CPU, per-connection, or
per-user maps where each key needs its own independent state. See [Map-of-Maps](map-of-maps.md)
for full documentation.

**Map types:** `BPF_MAP_TYPE_HASH_OF_MAPS` / `BPF_MAP_TYPE_ARRAY_OF_MAPS`

**Declaration:**
```java
@BPFMapDefinition(maxEntries = 1)   // inner-map template
BPFHashMap<Long, Long> innerTemplate;

@InnerMap("innerTemplate")
@BPFMapDefinition(maxEntries = 256)
BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;
```

**BPF-side API:**
```java
Ptr<BPFHashMap<Long, Long>> inner = outer.lookup(cpuId);
if (inner != null) {
    inner.bpf_put(syscallNr, count + 1);
}
```

**Java-side API:**
```java
prog.outer.register(cpuId, innerMapHandle);   // insert inner map fd
prog.outer.get(cpuId);                        // retrieve fresh fd handle
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
queue.push(e);
```

**Java-side API:**
```java
Event e = prog.queue.pop();   // returns null if empty
if (e != null) { ... }
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
prog.jumptable.register(0, prog.getProgramByName("handle_ipv4"));
prog.jumptable.register(1, prog.getProgramByName("handle_ipv6"));
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

---

## Examples

- [`HashMapSample.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HashMapSample.java) — BPFHashMap for syscall counting
- [`RingSample.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/RingSample.java) — BPFRingBuffer event streaming
- [`HelloArrayOfMaps.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloArrayOfMaps.java) — BPFArrayOfMaps / BPFHashOfMaps
- [`PerCpuInnerMapSample.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/PerCpuInnerMapSample.java) — per-CPU inner maps

---

## Further reading

- [BPF map types — docs.ebpf.io](https://docs.ebpf.io/linux/map-type/)
- [BPF_MAP_TYPE_HASH — docs.ebpf.io](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_HASH/)
- [BPF_MAP_TYPE_RINGBUF — docs.ebpf.io](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/)
- [BPF_MAP_TYPE_PERCPU_ARRAY — docs.ebpf.io](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERCPU_ARRAY/)
- [Global Variables](global-variables.md) · [Map of Maps](map-of-maps.md) · [Shared Maps](shared-maps.md)
