# Changelog

This page lists renamed and removed generated methods per kernel version. It is generated from kernel BTF snapshot diffs.

See [MIGRATIONS.md](../MIGRATIONS.md) for the full list.

<!-- Entries are appended automatically by:
     ./mvnw -pl bpf-gen test -Dsnapshot.update=true
     when a rename or removal is detected in the BTF snapshot diff.
-->

## Known renames

| Old name | New name | Kernel version |
|----------|----------|---------------|
| `scx_bpf_dispatch` | `scx_bpf_dsq_insert` | 6.12 |
| `scx_bpf_dispatch_vtime` | `scx_bpf_dsq_insert_vtime` | 6.12 |
| `scx_bpf_consume_task` | `scx_bpf_dsq_move_to_local` | 6.12 |
