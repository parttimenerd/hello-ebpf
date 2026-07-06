# BPF Arenas (`@InArena`)

**Javadoc:** [`BPFArena`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFArena.html)

A `BPF_MAP_TYPE_ARENA` is a page-granular memory region backed by a BPF map.
Both the BPF program and userspace address it directly — the BPF side through
clang address-space 1 (`__arena`), the Java side through a `mmap`'d
`MemorySegment` — without any per-element syscall.

Use an arena when you need heap-like allocation inside BPF: per-CPU bitmasks,
variable-length work queues, or any structure whose size is known only at load
time.  A `BPFHashMap` involves a hash-table lookup per read/write; an arena
pointer is a plain memory dereference.

Kernel requirement: ≥ 6.9 (`BPF_MAP_TYPE_ARENA` merged in 6.9).
This project requires kernel 6.14.

---

## §1 Declaring an arena

```java
@BPFMapDefinition(maxEntries = 1)   // 1 page = 4 KiB
BPFArena idleMask;

@InArena
Ptr<Long> idleMaskBase;
```

`@BPFMapDefinition` creates the `BPF_MAP_TYPE_ARENA` map at load time.
`maxEntries` is the capacity in 4 KiB pages.

`@InArena` tells the compiler plugin that `idleMaskBase` lives in arena
address space.  The plugin emits `__arena` on the pointer's C type so clang's
address-space type checker is satisfied.

Initialize the pointer in the `init()` callback (a sleepable `struct_ops`
entry — the only context where `bpf_arena_alloc_pages` is permitted):

```java
@Override
public int init() {
    idleMaskBase = bpfArenaAllocPages(idleMask, null, 1,
                                      MmConstants.NUMA_NO_NODE, 0);
    if (idleMaskBase == null) return -12;  // -ENOMEM
    return 0;
}
```

`BPFJ.bpfArenaAllocPages(arena, addrHint, pageCount, nodeId, flags)` lowers to
the `bpf_arena_alloc_pages` kfunc
(`bpf/src/main/java/me/bechberger/ebpf/bpf/BPFJ.java`, line 442).
Pass `null` for `addrHint` and `NUMA_NO_NODE` for `nodeId` unless you have a
specific placement requirement.

Real-world usage:
`bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java`, lines 269–284 and 544.

---

## §2 Reading and writing arena memory

From BPF code, dereference `idleMaskBase` like any other `Ptr<T>`:

```java
long v = idleMaskBase.val();          // read
idleMaskBase.set(v | (1L << cpu));    // write

@InArena Ptr<Long> word = idleMaskBase.add(wordIdx);
long bits = word.val();
```

The compiler plugin lowers `val()` and `set()` on an `@InArena` pointer to
`addr_space_cast` instructions (AS1 → AS0), which the verifier requires before
operating on arena memory.

From Java, obtain a `MemorySegment` via `BPFArena.userView()`:

```java
var view = arena.userView();
view.set(ValueLayout.JAVA_INT, 0, 0xCAFEBABE);
int v = view.get(ValueLayout.JAVA_INT, 0);
```

The same bytes BPF wrote at byte offset N are visible at offset N in `view`
without any syscall.  `userView()` is cached after the first call; the segment's
lifetime is tied to the `BPFArena` instance (closed by `BPFArena.close()`).

Smoke test:
`bpf/src/test/java/me/bechberger/ebpf/bpf/BPFArenaSmokeTest.java`, line 60.

---

## §3 `struct_ops` entry association

Each `struct_ops` callback is a separate BPF prog in the kernel's view.  The
verifier sets `prog->aux->arena` only when the prog's instruction stream
contains a `BPF_PSEUDO_MAP_FD ldimm64` referencing the arena map.  Without
that instruction, `addr_space_cast` is rejected.

**Since compiler-plugin 0.1.4, this is automatic.**  The `ArenaAssociationPass`
(`bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/passes/ArenaAssociationPass.java`)
performs a transitive-reachability analysis over the call graph.  For every
`struct_ops` or `struct_ops.s` entry that transitively dereferences an
`@InArena` pointer, it prepends a call to a generated inline helper:

```c
static __always_inline void bpf_arena_associate_idleMask(void) {
    static bool _verify_once;
    if (_verify_once) return;
    bpf_printk("arena=%p\n", (void *)(&idleMask));
    _verify_once = true;
}
```

`bpf_printk` is used (not `bpf_arena_alloc_pages`) because `alloc_pages` is a
sleepable kfunc that the verifier rejects in non-sleepable handlers.
The pattern matches upstream scx (`sdt_alloc.bpf.c scx_arena_subprog_init`).

You do not call anything manually.

!!! note
    Prior to the automatic injection, users had to call
    `BPFJ.bpfArenaAssociate(arena)` manually at the start of each handler.
    That API has been removed.  If you have existing code that calls it, delete
    those calls.

---

## §4 Userspace access via `mmap`

`BPFArena.userView()` maps the arena into the JVM process and returns a
`MemorySegment` spanning `pageCount * 4096` bytes.

The arena's `map_extra` field holds the virtual address the kernel requires.
`userView()` passes that address with `MAP_FIXED` — passing `NULL` returns
`EINVAL` on arenas that set `map_extra`
(`bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArena.java`, line 82).

The segment is valid as long as the `BPFProgram` is loaded.  `BPFArena.close()`
calls `munmap` automatically.

Convenience accessor in `UserspaceSchedulerBase`:

```java
public MemorySegment idleMaskView() {
    return idleMask.userView();
}
```

---

## §5 Limitations

- Kernel ≥ 6.9 required (`BPF_MAP_TYPE_ARENA` added in 6.9).
- One arena per BPF class for now; the kernel supports multiple arenas and the
  auto-injection pass handles them independently, but the single-arena idiom is
  the tested path.
- `@InArena` fields must be initialized via
  `BPFJ.bpfArenaAllocPages(arenaField, ...)` in a sleepable `init()` callback.
  The pass cannot resolve the arena association for any other initializer
  pattern.
- Arena pointers cannot be stored in regular BPF maps.  The verifier rejects
  cross-address-space stores.

---

## Examples

- [`sched/UserspaceSchedulerBase.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java) — arena-backed idle CPU bitmask in a scheduler
