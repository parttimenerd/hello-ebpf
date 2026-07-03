# Audit: Hooks / Section Strings

Point-in-time snapshot, 2026-07-03. Rows derived from `grep -rn 'section' bpf-compiler-plugin/` and `ProgramType.java`.

Gap definitions: **OK** = named on target page with working example. **Partial** = named or in a table, no dedicated coverage. **Missing** = not mentioned in any page. **Rewrite** = coverage violates style guide.

| Section string | bpf_prog_type | Java annotation/interface | Min kernel | Source (plugin file:line) | Documented in | Gap | Target page |
|----------------|---------------|--------------------------|------------|---------------------------|---------------|-----|-------------|
| `kprobe/<fn>` | `BPF_PROG_TYPE_KPROBE` | `@Kprobe` | 4.1 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:493` | cheatsheet.md, kprobes.md, feature-matrix.md, index.md, cookbook.md | OK | docs/kprobes.md |
| `kretprobe/<fn>` | `BPF_PROG_TYPE_KPROBE` | `@Kretprobe` | 4.1 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:496` | cheatsheet.md, kprobes.md, feature-matrix.md, index.md | OK | docs/kprobes.md |
| `fentry/<fn>` | `BPF_PROG_TYPE_TRACING` | `@Fentry` | 5.5 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:499` | cheatsheet.md, kprobes.md, feature-matrix.md, diagnostics.md | OK | docs/kprobes.md |
| `fexit/<fn>` | `BPF_PROG_TYPE_TRACING` | `@Fexit` | 5.5 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:502` | cheatsheet.md, kprobes.md, feature-matrix.md, diagnostics.md | OK | docs/kprobes.md |
| `tp/<category>/<name>` | `BPF_PROG_TYPE_TRACEPOINT` | `@Tracepoint` | 4.7 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:513` | cheatsheet.md, tracepoints.md, feature-matrix.md, index.md | OK | docs/tracepoints.md |
| `raw_tracepoint/<name>` | `BPF_PROG_TYPE_RAW_TRACEPOINT` | `@RawTracepoint` | 4.17 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:506` | tracepoints.md, cheatsheet.md, map-of-maps.md | OK | docs/tracepoints.md |
| `ksyscall/<name>` | `BPF_PROG_TYPE_KPROBE` | `@Ksyscall` | 5.11 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:518` | tracepoints.md, cheatsheet.md, feature-matrix.md | OK | docs/tracepoints.md |
| `uprobe/<path>:<sym>` | `BPF_PROG_TYPE_KPROBE` | `@Uprobe` | 4.1 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:525` | uprobes.md, feature-matrix.md, index.md, profiling.md, shared-maps.md | OK | docs/uprobes.md |
| `uretprobe/<path>:<sym>` | `BPF_PROG_TYPE_KPROBE` | `@Uretprobe` | 4.1 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:533` | uprobes.md, feature-matrix.md, index.md, profiling.md | OK | docs/uprobes.md |
| `lsm/<hook>` | `BPF_PROG_TYPE_LSM` | `@LSM` / `LSMHook` interface | 5.7 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java:538` | lsm.md, feature-matrix.md, index.md | OK | docs/lsm.md |
| `xdp` | `BPF_PROG_TYPE_XDP` | `XDPHook` interface | 4.8 | `bpf/src/main/java/me/bechberger/ebpf/bpf/XDPHook.java:45` | xdp.md, cheatsheet.md, feature-matrix.md, index.md | OK | docs/xdp.md |
| `tc` | `BPF_PROG_TYPE_SCHED_CLS` | `TCHook` interface | 4.1 | `bpf/src/main/java/me/bechberger/ebpf/bpf/TCHook.java:29` | tc.md, cheatsheet.md, feature-matrix.md, index.md | OK | docs/tc.md |
| `cgroup_skb/ingress` | `BPF_PROG_TYPE_CGROUP_SKB` | `CGroupHook` interface | 4.10 | `bpf/src/main/java/me/bechberger/ebpf/bpf/CGroupHook.java:42` | cheatsheet.md, lsm.md | Partial | docs/lsm.md (no dedicated page) |
| `cgroup_skb/egress` | `BPF_PROG_TYPE_CGROUP_SKB` | `CGroupHook` interface | 4.10 | `bpf/src/main/java/me/bechberger/ebpf/bpf/CGroupHook.java:54` | cheatsheet.md, lsm.md | Partial | docs/lsm.md (no dedicated page) |
| `struct_ops/<field>` | `BPF_PROG_TYPE_STRUCT_OPS` | `@StructOps` interface | 5.6 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java:105` | struct-ops.md, sched_ext.md, changelog.md, shared-maps.md | OK | docs/struct-ops.md |
| `struct_ops.s/<field>` | `BPF_PROG_TYPE_STRUCT_OPS` | `@StructOps` interface + `@Sleepable` | 5.10 | `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java:103` | struct-ops.md | OK | docs/struct-ops.md |
| `kprobe.multi/<glob>` | `BPF_PROG_TYPE_KPROBE` | `@KProbeMulti` + `@BPFFunction(section=…, autoAttach=false)` | 5.18 | `bpf/src/main/java/me/bechberger/ebpf/bpf/XDPHook.java` (user supplies via `@BPFFunction`; no synthesizer path) | attach-cookies-multi.md | Partial | docs/attach-cookies-multi.md |
| `kretprobe.multi/<glob>` | `BPF_PROG_TYPE_KPROBE` | `@KProbeMulti(retprobe=true)` + `@BPFFunction(section=…)` | 5.18 | (user supplies section string; recognised by `BPFProgram.isMultiAttachSection()` at `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java:835`) | attach-cookies-multi.md | Partial | docs/attach-cookies-multi.md |
| `uprobe.multi/<glob>` | `BPF_PROG_TYPE_KPROBE` | `@UProbeMulti` + `@BPFFunction(section=…, autoAttach=false)` | 6.6 | (user supplies section string; recognised by `BPFProgram.isMultiAttachSection()` at `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java:836`) | attach-cookies-multi.md | Partial | docs/attach-cookies-multi.md |
| `uretprobe.multi/<glob>` | `BPF_PROG_TYPE_KPROBE` | `@UProbeMulti(retprobe=true)` + `@BPFFunction(section=…)` | 6.6 | (user supplies section string; recognised by `BPFProgram.isMultiAttachSection()` at `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java:836`) | attach-cookies-multi.md | Partial | docs/attach-cookies-multi.md |

## Notes

- **`kprobe.multi` / `kretprobe.multi` / `uprobe.multi` / `uretprobe.multi`**: The compiler plugin does NOT synthesise these section strings from annotations. The user must supply `@BPFFunction(section = "kprobe.multi/…", autoAttach = false)` directly and call `attachKProbeMulti` / `attachUprobeMulti` at runtime. The `@KProbeMulti` / `@UProbeMulti` annotations are documentation markers only.

- **`cgroup_skb`**: No dedicated doc page exists. Coverage in cheatsheet.md (one table row) and a brief mention in lsm.md. Gap is **Partial**; a dedicated cgroup section would be the logical home.

- **`struct_ops.s/`** (sleepable): Emitted when the implementing method (or the interface default) carries `@Sleepable`. Documented in struct-ops.md. Kernel minimum is 5.10 (sleepable BPF programs).

- **`ProgramType.TC`** / **`ProgramType.CGROUP_SKB`**: `ProgramType.fromSection` recognises `tc/` and `classifier/` prefixes for TC; `cgroup_skb/` and `cgroup/` for cgroup. The `TCHook` interface always emits bare `tc`, matching libbpf's `TC_INGRESS`/`TC_EGRESS` shorthand sections.

- The `ProgramType` enum also lists `TC` and `CGROUP_SKB` but the plugin's `synthesizeBPFFunction` does not handle them — both hook types are expressed via interface-default `@BPFFunction` methods in `TCHook` / `CGroupHook`, not via shorthand annotations.
