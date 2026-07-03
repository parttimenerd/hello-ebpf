# BPF Arenas (`@InArena`)

!!! note "Placeholder"
    This page is a placeholder for content coming in Spec 2. See the
    [annotations audit](superpowers/audit/audit-annotations.md)
    for the symbols it will cover.

Planned scope:

- `BPFArena` map type and `bpfArenaAllocPages()`
- `@InArena Ptr<T>` field declaration and initialization
- Arena-qualified dereferencing and `addr_space_cast` lowering
- struct_ops entry auto-association (automatic since compiler-plugin vX.Y)
- Per-NUMA allocation, `NUMA_NO_NODE`, capacity limits
- Comparison with `BPFHashMap` for dynamic memory needs
