# Map-of-Maps (HASH_OF_MAPS, ARRAY_OF_MAPS)

**Javadoc:** [`BPFHashOfMaps`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFHashOfMaps.html) · [`BPFArrayOfMaps`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFArrayOfMaps.html)

Use a map-of-maps when you need a different map *per key* — e.g. per-CPU
accounting, per-connection state, or per-user rate limits. A plain
`BPFHashMap<K, V>` requires a fixed value type; a
`BPFHashOfMaps<K, BPFHashMap<...>>` lets each key point at its own independent
map, registered at load time or dynamically. Kernel requirement: Linux ≥ 4.12
for both `HASH_OF_MAPS` and `ARRAY_OF_MAPS`.

hello-ebpf exposes the kernel's `BPF_MAP_TYPE_HASH_OF_MAPS` and
`BPF_MAP_TYPE_ARRAY_OF_MAPS` via two wrapper classes:

- `me.bechberger.ebpf.bpf.map.BPFHashOfMaps<K, InnerMap>`
- `me.bechberger.ebpf.bpf.map.BPFArrayOfMaps<InnerMap>`

Both hold inner-map file descriptors as values. The kernel requires every
inner map registered under an outer to share the same template
(type, key_size, value_size, max_entries, map_flags).

## Wiring the template

The inner-map template must be visible to libbpf before load. hello-ebpf
supplies it via a sibling `@BPFMapDefinition` field pointed to by
`@InnerMap`. The processor substitutes the sibling field name into the outer
map's C struct as `__array(values, innerFieldName)`, which is libbpf's BTF
idiom for declaring an inner-map template. libbpf resolves the inner-map fd
automatically during `bpf_object__load`.

```java
@BPFMapDefinition(maxEntries = 1)
BPFHashMap<Long, Long> innerTemplate;

@InnerMap("innerTemplate")
@BPFMapDefinition(maxEntries = 256)
BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;
```

The annotation processor validates at compile time that the name passed to
`@InnerMap` matches a sibling `@BPFMapDefinition` field.

## Java API

- `outer.register(key, innerMap)` — insert the inner map's fd at `key`.
- `outer.unregister(key)` — drop the outer's reference; the inner's own fd
  stays valid.
- `outer.get(key)` — return a fresh `BPFMap` handle wrapping a new fd
  (`bpf_map_get_fd_by_id`); caller must close it. Returns `null` if no
  inner is registered at `key`.

## When to use which outer type

`BPFHashOfMaps<K, Inner>`: arbitrary keys up to `max_entries` inner slots;
suitable for per-CPU, per-connection, or per-user maps where the key space is
not contiguous.

`BPFArrayOfMaps<Inner>`: u32 keys in `[0, max_entries)`; lookup is a direct
index into the outer array, which is faster than a hash probe; use when your
key is a CPU id, socket id, or another small integer whose range is known at
load time.

## BPF API

- `Ptr<InnerMap> outer.lookup(key)` — inside a BPF function, resolve the
  inner map pointer. Null-check before use.

## Attaching programs that use map-of-maps

Programs using `raw_tracepoint` sections cannot be auto-attached; call
`rawTracepointAttach(methodName, tracepointName)` explicitly:

```java
rawTracepointAttach("countSyscall", "sys_enter");
```

## Samples

**`PerCpuInnerMapSample`** — `HASH_OF_MAPS` keyed by CPU id, with a per-CPU
inner hash map of syscall counts; userspace aggregates the inners at read time
and prints the top-10 syscalls by invocation count.

```
mvn -pl bpf-samples exec:java \
    -Dexec.mainClass=me.bechberger.ebpf.samples.PerCpuInnerMapSample
```

**`HelloArrayOfMaps`** — `ARRAY_OF_MAPS` with `NUM_SLOTS=4` buckets;
syscalls are routed to bucket `syscall_nr % NUM_SLOTS` and counted in the
corresponding inner map; demonstrates `BPFArrayOfMaps` and index-based
`lookup`.

```
mvn -pl bpf-samples exec:java \
    -Dexec.mainClass=me.bechberger.ebpf.samples.HelloArrayOfMaps
```

## Limitations (v1)

- Heterogeneous inner maps are not supported (kernel constraint).
- No compile-time deep nesting (`HASH_OF_MAPS<K, HASH_OF_MAPS<...>>`).
- Registering the same physical inner map at multiple outer keys is
  allowed but shares state; use distinct `bpf_map_create` calls for
  true per-key isolation.
