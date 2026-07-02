# struct_ops layouts

Pre-dumped BTF layouts for the kernel struct_ops kinds hello-ebpf supports.
Consumed at plugin-compile time by `StructOpsLayout.load(kind)`; not consulted
at runtime.

## Refresh procedure

Run against a live 6.14+ kernel (thinkstation qualifies):

```
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
python3 scripts/extract-struct-ops-layouts.py /tmp/vmlinux.h \
    bpf-compiler-plugin/src/main/resources/struct-ops-layouts/
```

Verify no unexpected field additions/removals:

```
git diff bpf-compiler-plugin/src/main/resources/struct-ops-layouts/
```

Land the refresh in a commit of its own with a note in the message about
which kernel version the dump was taken from.

## When to refresh

- A new kernel adds a field to one of the four supported kinds → refresh, land,
  and consider bumping the `since` for that field (fine-grained gating is a
  future roadmap item — today's `since` is per-kind, not per-field).
- A kernel renames a field → the plugin will emit a compile error for
  existing user code that overrides that name. Refresh, and update the
  matching marker interface's method name.
- Adding a new supported kind → dump-script needs an entry in `TARGETS`,
  a new marker interface, a new codegen test.
