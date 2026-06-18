# API Migration Guide

This file documents BPF helper and sched_ext function renames across kernel versions.
Deprecated Java methods for each old name are emitted automatically by `bpf-gen`
based on `bpf-gen/src/main/resources/aliases.json`.

When `./mvnw -pl bpf-gen test -Dtest=SnapshotTest` detects a removal:
1. Add an entry to `aliases.json` mapping `oldName → newName`.
2. Re-run `./mvnw -pl bpf-gen test -Dtest=SnapshotTest -Dsnapshot.update=true`
   to update the snapshot (the deprecated forwarding method will now appear).
3. Add a section here under the appropriate kernel version.

---

## Kernel 6.12 — sched_ext API cleanup

The `scx_bpf_dispatch*` family was renamed to clearer `scx_bpf_dsq_*` names.

| Old name (pre-6.12) | New name (6.12+) |
|---|---|
| `scx_bpf_dispatch` | `scx_bpf_dsq_insert` |
| `scx_bpf_dispatch_vtime` | `scx_bpf_dsq_insert_vtime` |
| `scx_bpf_dispatch_from_dsq` | `scx_bpf_dsq_move` |

**Migration**: Replace call sites. The Java deprecated methods delegate to the
new implementations, so code compiles with a warning until updated.
