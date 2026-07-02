# bpftrace deep-read: DSL-level ergonomics hello-ebpf lacks

Source: /tmp/ebpf-research/bpftrace at commit `c17ee7ed5b844d8c3f1e83dbe51c2cf904bc9b58`
Positioning: bpftrace is a REPL DSL for one-liners; hello-ebpf is a full Java framework for eBPF programs. This doc extracts what bpftrace's DSL makes free that hello-ebpf could offer as typed Java APIs (helper methods, aggregation classes, symbol resolvers). Positioning caveat: hello-ebpf is not trying to be a REPL — anything here is opt-in helper surface, not a paradigm shift.

## 1. Aggregation primitives — the biggest missing framework feature — **New**

bpftrace's `@` maps double as aggregation containers. Nine aggregation kinds are recognised by the compiler (`src/ast/passes/map_sugar.cpp:15`, dispatch in `src/ast/passes/codegen_llvm.cpp:942-1200`, sizing/detail in `src/ast/passes/resource_analyser.cpp:255-320`):

| bpftrace form | semantics |
|---|---|
| `@[key] = count()` | per-cpu counter, summed on read |
| `@[key] = sum(v)` | per-cpu summed integer |
| `@[key] = min(v)` / `max(v)` | per-cpu reduction |
| `@[key] = avg(v)` | per-cpu (sum, count) pair; div on read |
| `@[key] = stats(v)` | count, sum, min, max, avg, stddev on one map |
| `@[key] = hist(v)` | log2 histogram; bpftrace prints ASCII bars |
| `@[key] = lhist(v, min, max, step)` | linear histogram with fixed bins |
| `@[key] = tseries(v, interval, num_intervals[, agg])` | time-series ring; agg one of avg/sum/min/max/last |
| `clear(@map)` / `zero(@map)` / `delete(@map, key)` | lifecycle |

One-liner example from bpftrace docs (`stdlib/base.bt` around the `count`/`hist` blocks): `kprobe:vfs_read { @bytes = hist(arg2); }` — three tokens produce a log2 histogram of read sizes and print it as an ASCII bar chart on exit.

**Java API sketch** (all `@BPFMap`-derived; the compiler-plugin could recognise these as sugar for BPF_MAP_TYPE_PERCPU_HASH/ARRAY plus a userspace reduction routine):

```java
@BPFMapDefinition(maxEntries = 10240)
Aggregation.Count<String>      byComm;   // increment(key)
Aggregation.Sum<Integer>       bytes;    // add(key, v)
Aggregation.MinMax<Integer>    lat;      // observeMin/observeMax
Aggregation.Avg<Long>          latAvg;   // observe(key, v)
Aggregation.Stats<Long>        latFull;  // count/sum/min/max/stddev
Aggregation.Log2Histogram<K>   hist;     // observe(key, v)
Aggregation.LinearHistogram<K> lhist;    // buckets configured at construction
Aggregation.TimeSeries<K>      ts;       // observe(key, v); windowed
```

Bpftrace also ships `print(@map, top, div)` (`codegen_llvm.cpp` and `stdlib/base.bt` `len`/`clear` region) which prints the top-N entries sorted — a `readTopN(int n, ToLongFunction<V> sort)` reader on the map wrappers would carry this over.

**Refines** the "runtime-swappable map types" bullet from the rust-go catalog by picking a concrete surface. The wrappers themselves would sit above hello-ebpf's existing `BPFPerCpuHashMap`/`BPFPerCpuVar`, so no verifier work — only Java-side reduction plus a printer.

## 2. Symbol resolution — ksym/usym/kaddr/uaddr — **New**

bpftrace exposes four builtins for address ↔ symbol conversion (`ksyms.h`, `usyms.h`, listed in codegen at `codegen_llvm.cpp` under `"ksym"`/`"usym"`/`"kaddr"`/`"percpu_kaddr"`):

- `ksym(addr) -> string` — kernel address to `symbol+offset` (backed by `/proc/kallsyms` or blazesym; `Ksyms::resolve(addr, show_offset, perf_mode, show_debug_info)` in `src/ksyms.h:22`).
- `usym(addr) -> string` — userspace address to `symbol+offset`; needs pid because layouts differ (`Usyms::resolve(addr, pid, exe, …)` in `src/usyms.h:31`; caches per-pid or per-exe).
- `kaddr("name")` and `uaddr("name")` — reverse lookup: symbol name → address (`base.bt:1425` for `uaddr`).
- `percpu_kaddr("name")` — per-CPU variant.

hello-ebpf has no symbolizer; stack traces returned via the current stack-map wrapper are just raw addresses. **Java API sketch**:

```java
public interface Symbolizer {
    String resolveKernel(long addr);                       // ksym
    String resolveUser(long addr, int pid);                // usym
    OptionalLong lookupKernel(String symbol);              // kaddr
    OptionalLong lookupUser(String symbol, int pid);       // uaddr
    List<String> resolveKernelStack(long[] addrs);
    List<String> resolveUserStack(long[] addrs, int pid);
}
class KsymSymbolizer { /* /proc/kallsyms cache */ }
class UsymSymbolizer { /* per-pid, reads /proc/PID/maps + ELF */ }
```

Refines the DWARF-unwinder bullet from prior catalogs: unwinding gives you addresses, and this is the missing step from addresses → names. Also refines aya's `/proc/PID/maps + ld.so.cache` note by fixing a concrete pluggable interface. Blazesym-equivalent could be optional.

## 3. DWARF-driven typed argument access — **New**

For a probe like `kprobe:vfs_open { printf("%s", str(args->pathname)); }`, `args->pathname` is resolved through DWARF/BTF, not `pt_regs`. Implementation is in `src/dwarf_parser.h:53-63`:

```cpp
std::vector<std::string> get_function_params(const std::string &function) const;
std::shared_ptr<Struct> resolve_args(const std::string &function);
SizedType get_stype(const std::string &type_name) const;
Result<uint64_t> line_to_addr(const std::string &source_file, size_t line_num, size_t col_num = 0) const;
```

bpftrace resolves DWARF from vmlinux BTF for kernel probes, from `/usr/lib/debug` or `.debug_info` in-binary for userspace (`--dwarf-pid`, `-p`, `-c` flags feed the DWARF resolver, `main.cpp:527` `DWARF_PID`). Argument names by identifier — no `PT_REGS_PARM1` shenanigans, no arch-specific register handling in user code.

hello-ebpf currently gives you `Ptr<pt_regs>` and expects manual `BPFHelpers.bpf_probe_read_kernel` chains, or (for uprobes with the new `@ProbeArgs` annotation) positional register access. A DWARF-backed layer would let the compiler-plugin generate the parameter accessors from the target binary/BTF at build time:

```java
@KProbe("vfs_open")
int onOpen(@Arg("pathname") Ptr<byte> path, @Arg("flags") int flags) { ... }
```

This is the single biggest ergonomic delta from bpftrace's `args->pathname` idiom. **Refines** the "typed .rodata/.bss via mmap" bullet from libbpf-rs by extending kernel-BTF-to-Java code generation into function-argument space. Also refines `line_to_addr` — bpftrace can attach a uprobe to `path:file:line`, resolving source lines to text-section offsets (a natural addition to hello-ebpf's `@UProbe`).

## 4. Format-string helpers — printf directives — **New**

`src/format_string.cpp:29` defines the master regex:

```
%(-?)(\+?)( ?)(#?)(0?)(\*|\d+)?(?:\.(\*|\d+))?([hlLjzt]*)([diouxXeEfFGaAcspn%]|gr|g|rh|rx|r)
```

Beyond stdio C99 specifiers, bpftrace-specific specifiers:

| specifier | meaning |
|---|---|
| `%s` | kernel-safe string (probe-read on the pointer) |
| `%r` | buffer, printed as ASCII with `\xNN` for non-printable |
| `%rx` | buffer, all hex |
| `%rh` | buffer, hex with spaces (`0a fe`) |
| `%p` | pointer, symbolised via `ksym`/`usym` when applicable |
| `%gr` | GFP flags decoded to human-readable text |

Plus companion async builtins: `strftime(fmt, nsecs)` (`codegen_llvm.cpp` `"strftime"`), `time(fmt)` (auto-formats current time), `ntop(af, addr)` (IP address to string), `pton("1.2.3.4")` (reverse), `macaddr(bytes)`. hello-ebpf's `bpf_trace_printk` is a raw kernel helper with only C-standard specifiers. A `BPFJ.trace(...)` or ring-buffer helper accepting `%r` (buffer hex), `%s` (kernel-string via `bpf_probe_read_kernel_str`), `%p` (with pluggable symbolizer applied in Java userspace) would be pure Java-side sugar built on the existing pipeline. `strftime` and `ntop`/`pton` are userspace-only formatters — trivial to implement.

## 5. Probe glob expansion — **Refines** kprobe.multi bullet

bpftrace lets you write `kprobe:tcp_*` and expands to every matching symbol at compile/attach time (`src/probe_matcher.h:72` `expand_probetype_kernel` and `:73` `expand_probetype_userspace`; `src/ast/passes/ap_probe_expansion.cpp`). The expansion enumerates `/sys/kernel/tracing/available_filter_functions` for kprobes, walks `/sys/kernel/tracing/events/` for tracepoints, iterates ELF symbols for uprobes, and generates one attach per match. Distinct from `KPROBE.MULTI` (a single kernel-side link) — this is user-facing wildcard sugar that also drives listing (`-l`).

**Java API sketch**: extend the `@KProbe("...")` annotation processor to accept a glob and enumerate matches at load time. Alternatively a builder:

```java
BPFProgramBuilder.attachAll(KProbeSpec.glob("tcp_*"),  ctx -> onTcp(ctx));
```

The matcher also powers `-l` (list probes matching a filter): `bpftrace -l 'kprobe:tcp_*'`. hello-ebpf has no equivalent CLI, but the API is still useful (introspection: "does this kernel expose the symbol I want to attach to?").

## 6. CLI / runtime capabilities — **New (positioning)**

bpftrace CLI options worth mirroring (`src/main.cpp:429` short options `"d:bB:f:e:hlp:vqc:Vo:I:k"` plus `getopt_long` cases at `:557` onward):

| flag | meaning | hello-ebpf status |
|---|---|---|
| `-c CMD` | spawn `CMD`, trace its lifetime, exit when it exits | absent — no `spawnAndTrace` runner |
| `-p PID` | attach a per-PID filter to all probes | there is per-attach PID filter but no top-level `--pid` |
| `-l [FILTER]` | list probes matching a glob, exit | absent — no probe-introspection CLI |
| `--info` | print supported program/map types, helper availability | overlaps aya `ProgramInfo` and cilium's features/ — but as a one-shot "show me what this kernel does" tool it's separately useful |
| `--aot OUT` | AOT-compile to a portable binary | see §7 below |
| `-B mode` | line/full/none stdout buffering for interactive use | not applicable (Java framework) |
| `--unsafe` | permit destructive helpers (`signal`, `override`, `write_user`, `system`) | hello-ebpf has these but no gate |
| `--dwarf-pid PID` | preload DWARF for a running PID | ties to §3 |
| `-o FILE` | output to file (also plugged into JSON output via `--fmt json`) | absent |
| `-f json` | JSON output formatter | see §8 |
| `-I DIR` / `--include` | preprocessor include paths | hello-ebpf embeds C in Java; irrelevant |

hello-ebpf is a jar/library, not a CLI, so the raw flag set doesn't port. But a **runner class** (`BPFRunner.spawnAndTrace(cmd)`, `BPFRunner.attachToPid(pid)`, `BPFProgram.listAvailableProbes(glob)`) closes the ergonomic gap for the common "one-shot trace" pattern that bpftrace one-liners serve. Adding `--unsafe` awareness (a runtime opt-in for destructive helpers `override(-EPERM)`, `signal(SIGKILL)`, `write_user`, `system`) is more of a safety-hardening choice.

## 7. AOT compilation — **Refines** aya/libbpf skel bullet

`src/aot/aot.h` exposes:

```cpp
int generate(const RequiredResources &, const std::string &out, void *elf, size_t elf_size);
int load(BPFtrace &, const std::string &in);
```

Also `AOT_SHIM_NAME = "bpftrace-aotrt"` — the runtime shim executable that's bundled into the AOT binary. Result: a portable file that runs on any kernel supporting the required helpers via CO-RE relocation on load. hello-ebpf jars already carry pre-compiled BTF-enabled object files, so this is 80% present — the remaining delta is a **standalone runnable artifact** (a jlink/native-image image that bundles the runtime + the compiled object into one executable). Not a framework gap per se, more a distribution ergonomics gap. Flag as low priority.

## 8. Output formatters — text/JSON — **New (low priority)**

`src/output/` has `text.h`, `json.h`, `capture.h`, `buffer_mode.h`, `discard.h`. bpftrace can emit trace records as JSON (`-f json`) — one JSON object per record. hello-ebpf apps typically consume ring buffers directly in Java, so full formatters aren't needed, but a `RecordFormatter` interface (`toText`, `toJson`) on the ring-buffer wrapper would eliminate boilerplate for logging use cases and let downstream OTel/Loki adapters be trivial. Ties into aggregation printers from §1: bpftrace's `print(@hist)` renders the histogram; a Java equivalent would render a `Log2Histogram` as ASCII bars in `.toString()`.

## 9. Stdlib helpers (from `src/stdlib/*.bt`)

For each file, listing public helpers as `macro` declarations. Bpftrace's stdlib is authored in bpftrace-DSL itself and compiled together with the user script — a good template for a hello-ebpf `BPFJ` companion class.

### `base.bt` (47 macros; `src/stdlib/base.bt`)
`assert`, `cgroup`, `comm`/`comm($pid)`, `has_cpid`, `cpid`, `cpu`, `curtask`, `delete(@map, key)` (4 arities), `elapsed`, `find(@map,key,$var)`, `func`, `gid`, `has_key(@map,key)`, `is_err(ptr)`, `jiffies`, `len(@map|expr)`, `ncpus`, `numaid`, `override(expr)`, `write_user(dst,src,len)`, `ppid`, `leader_tid`, `pcomm`, `leader_comm`, `probe`, `probetype`, `rand`, `retval`, `signal(expr)`, `signal_thread(expr)`, `uaddr(sym)`, `uid`, `usermode`, `username`, `dw_ustack(mode,limit)`.

Cross-ref against hello-ebpf `BPFJ` / `BPFHelpers`:
- **already exists (or trivial via bpf helpers)**: `comm`, `cpu`, `pid`/`tid` (via helpers), `gid`, `uid`, `elapsed` (delta from BEGIN via `bpf_ktime_get_ns`), `rand`, `retval` (via probe return-type support), `curtask`, `func`, `probe`, `probetype`.
- **missing / high-value**: `find`, `has_key` (map probe without failing), `is_err(ptr)` (IS_ERR helper — decodes `-4095..-1` range), `override(expr)` (bpf_override_return, needs error-injection kprobe), `signal(expr)` / `signal_thread(expr)` (bpf_send_signal_task), `write_user` (bpf_probe_write_user — already flagged in prior catalog), `ncpus`, `numaid`, `username` (uid → passwd via userspace resolver), `leader_tid`/`leader_comm`/`ppid`, `pcomm` (thread group leader comm), `has_cpid`/`cpid` (child pid from `-c`), `jiffies`, `usermode` (in-kernel? predicate on pt_regs), `dw_ustack` (DWARF unwinder — prior).
- **irrelevant**: `assert` (Java has `assert`; but a compile-time-safe variant emitting a ringbuf record on failure would still be nice), `probe`/`probetype` (metadata about current attach — Java has this via reflection).

### `strings.bt` (11 macros; `src/stdlib/strings.bt`)
`assert_str`, `default_str_length`, `strlen(exp)`, `strcap`, `strstr($haystack, needle)` (4 arities), `strcontains`, `strerror(errno)`, `signal_name(sig)`, `syscall_name(n)`. Also (from base.bt / codegen): `str(ptr[, len])`, `buf(ptr[, len])`, `strftime(fmt, nsecs)`, `strncmp(a,b,n)`, `join(argv, delim)`, `path(dentry_or_file)`, `ntop(af, addr)`, `pton(str)`.

Missing in hello-ebpf: string primitives that decode integers to human text (`strerror`, `signal_name`, `syscall_name` — small lookup tables), search (`strstr`, `strcontains`), `strcap` (capitalize — actually less critical), `path` (bpf_d_path — resolves dentry to absolute path; already used inside hello-ebpf for LSM hooks but not exposed as a helper), `join` (concatenate string array with separator — pointer-array specific; used for `argv` of exec traces), `strncmp` (in-kernel string compare — bpf_probe_read + memcmp).

### `meta.bt` (9 macros; `src/stdlib/meta.bt`)
`is_str`, `is_ptr`, `is_array`, `is_integer`, `is_unsigned_integer`, `static_assert(cond, msg)`, `check_key(@map, key, func)`, `is_literal(expr)`, `assert_userspace_probe(func)`, `elf_is_exe`, `elf_info`. These are DSL-level type introspection macros. Java has full compile-time types, so most are irrelevant — but `assert_userspace_probe` (statically ensures a func was called from a uprobe context) is a nice compiler-plugin diagnostic pattern to steal, and `check_key(@map, key, func)` (deferred lookup that only runs `func` if the key exists) is an ergonomic map-access pattern.

### `internal.bt` (2 primitives)
`memcmp(l, r, count)` (4 arities), `memcmp_record`, `usdt_arg(x)` — the second one is USDT-related and already in prior catalogs.

### `kfunc.bt` (2 primitives)
`kfunc_exist(kfunc)`, `kfunc_allowed(kfunc)` — runtime capability probes for kfunc availability. **Refines** the feature-detection bullet by naming the specific granularity: not just "is BPF_PROG_TYPE_TRACING supported" but "is *this specific kfunc* callable". hello-ebpf has `@BPFFunction` bindings but no `kfuncExists("bpf_get_current_task_btf")` check for optional attaches.

### `process.bt` (1 macro)
`__signal(expr, is_tid)` — internal helper for `signal`/`signal_thread`. Nothing new.

### C-file helpers under `stdlib/*/` 
`stdlib/strings/strings.bpf.c`, `stdlib/stack/dwunwind.bpf.c`, `stdlib/process/process.bpf.c`, `stdlib/task/task.bpf.c` + `vma.bpf.c`, `stdlib/usdt/usdt.bpf.c`, `stdlib/system/system.bpf.c`, `stdlib/map/map.bpf.c` — the implementations of the macros above. hello-ebpf would ship these as compiled `.c` snippets bundled with the compiler plugin (or, more Java-idiomatic, as `@BuiltinBPFFunction`-annotated methods on `BPFJ`).

## 10. Cross-reference summary

| Feature | Priority | Cross-ref |
|---|---|---|
| Aggregation classes (count/sum/hist/lhist/avg/stats/tseries) | **High** — biggest DSL delta | New; refines "runtime-swappable map types" |
| Symbolizer (ksym/usym/kaddr/uaddr) | **High** — needed for stack readability | New; refines DWARF unwinder |
| DWARF-typed args (`@Arg("name")`) | **High** — replaces `Ptr<pt_regs>` | New; refines libbpf-rs typed-mmap |
| printf directives `%s`/`%r`/`%p`/strftime/ntop/pton | **Medium** — pure userspace sugar | New |
| Probe glob expansion at compile time | **Medium** | Refines kprobe.multi bullet |
| Spawn-and-trace / attach-to-pid runner | **Medium** | New (positioning) |
| AOT native-image single-file distribution | **Low** | Refines aya/libbpf skel |
| JSON output formatter for ring records | **Low** | New |
| `kfunc_exist` / `kfunc_allowed` fine-grained feature probe | **Medium** | Refines feature-detection |
| `is_err(ptr)`, `signal`, `override`, `write_user`, `d_path`, `strerror`, `signal_name`, `syscall_name`, `join`, `strncmp` | **Medium** (each) | New (individual helpers) |
| Assertion / `check_key` / `has_key` map ergonomics | **Medium** | New |
| Lockdown detection (`src/lockdown.h`) | **Low** | New — hello-ebpf could refuse to load with a friendly diagnostic when `/sys/kernel/security/lockdown` reports `integrity`/`confidentiality` |

The dominant story: bpftrace's DSL brevity comes almost entirely from (a) aggregation-as-map-syntax and (b) DWARF-typed argument access. Everything else is small helper icing. Both (a) and (b) are large but *shippable-in-isolation* additions to hello-ebpf's Java API — no changes to the loader, no kernel-side new primitives.
