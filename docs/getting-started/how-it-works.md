# How the Plugin Works

**Blog series:** [Part 5 — First steps with libbpf](https://mostlynerdless.de/blog/2024/02/26/hello-ebpf-first-steps-with-libbpf-5/) · [Part 8 — Generating C code from Java](https://mostlynerdless.de/blog/2024/04/09/hello-ebpf-generating-c-code-8/) · [Part 11 — BTF and 13,000 generated Java classes](https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/) · [Part 12 — Write eBPF in pure Java](https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/)

**Javadoc:** [`BPFProgram`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/BPFProgram.html) · [`@BPF`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/bpf/BPF.html) · [`@BPFFunction`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/bpf/BPFFunction.html) · [`@Type`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/Type.html) · [`@BPFMapDefinition`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/bpf/BPFMapDefinition.html)

![Annotation processor and compiler plugin pipeline](https://mostlynerdless.de/wp-content/uploads/2024/07/compiler_pipeline-2000x1125.png)

The kernel BPF verifier operates on eBPF bytecode. The only production-quality
compiler that targets that bytecode is clang. hello-ebpf does not bypass that
requirement — it makes clang invisible. You write `@BPFFunction` methods in
Java; the build toolchain translates them to C, invokes clang, and bundles the
resulting `.o` into your jar before `javac` finishes.

## §1 The two build phases

A single `mvn package` run triggers two distinct javac phases for every
`@BPF`-annotated class.

**Phase 1 — Annotation processor (`bpf-processor`).**
Runs at round 1 of javac annotation processing
(`bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/Processor.java`).
It discovers [`@BPFMapDefinition`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/bpf/BPFMapDefinition.html) fields and [`@Type`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/Type.html)-annotated
records, resolves their BTF struct layouts via `TypeProcessor.java`, and writes a `.bpf.json` manifest
that the compiler plugin reads in phase 2.

**Phase 2 — Compiler plugin (`bpf-compiler-plugin`).**
Runs during the compilation pass, after annotation processing
(`bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java`).
For each [`@BPF`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/bpf/BPF.html) class it walks the AST of every [`@BPFFunction`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/bpf/BPFFunction.html) method, translates
Java constructs to C, and writes a `.bpf.c` source file. It then invokes clang,
embeds the resulting `.o` as a jar resource, and replaces each `@BPFFunction`
body with `throw new MethodIsBPFRelatedFunction()` so the JVM never executes it.

```
Your @BPF class
      │
      │  annotation processor (bpf-processor)
      ▼
  .bpf.json manifest (BTF layouts, map defs)
      │
      │  compiler plugin (bpf-compiler-plugin)
      ▼
  generated .bpf.c  ──►  clang  ──►  .o (embedded in jar)
      │
      │  BPFProgram.load(YourClass.class) at runtime
      ▼
  libbpf ──► kernel verifier ──► attached BPF prog
```

## §2 What the plugin translates

The compiler plugin covers the following Java-to-C mappings:

- `int`/`long` → `__u32`/`__u64`; `@Unsigned` qualifiers applied where present.
- `Ptr<T>` → C pointer `T *`.
- `@InArena Ptr<T>` → `T __arena *` (BPF arena address space).
- Field access on BPF structs → CO-RE access via `BPF_CORE_READ`.
- BPF map operations (`bpf_get`, `put`, etc.) → corresponding kernel helper calls.
- `@BPFFunction` calls within the same class → static C function calls.

## §3 Extending the plugin — `@BuiltinBPFFunction` templates

**Javadoc:** [`@BuiltinBPFFunction`](https://parttimenerd.github.io/hello-ebpf/javadoc/annotations/me/bechberger/ebpf/annotations/bpf/BuiltinBPFFunction.html)

When a method in a `@BPFInterface` or map class cannot be expressed as a normal `@BPFFunction` body — because the C code is a single expression, involves a GNU statement expression, or needs to reference the receiver or a specific argument positionally — annotate it with `@BuiltinBPFFunction` and provide a C template string. The plugin substitutes `$`-placeholders at call sites and inlines the result directly.

### Placeholder reference

| Placeholder | Expands to |
|-------------|-----------|
| `$this` | The receiver expression (map variable name, context pointer, …) |
| `$arg1`, `$arg2`, … | The n-th argument expression (1-based) |
| `$args` | All arguments, comma-separated |
| `$argsN_` | Arguments from the N-th onwards |
| `$pointery$argN` | `&argN` if it is a value type; `argN` if it is already a pointer or String |
| `$typeof$argN` | `__typeof__(argN)` — useful in GNU statement expressions for temporary variables |
| `$sizeof$argN` | `sizeof(argN)` |
| `$deref$argN` | `*(argN)` |
| `$str$argN` | Raw string content of a `StringConstant` argument (no surrounding quotes) |
| `$strlen$argN` | Length of a `StringConstant` argument as an integer literal |
| `$T1`, `$T2`, … | n-th generic type argument of the enclosing map class |
| `$funcN` | Promotes the n-th lambda argument to a named top-level C function; expands to that function's name |
| `$lambdaN:code` | Inline body of the n-th lambda argument |

A leading `!` in the template wraps the whole expression in `!(…)` — useful for helpers that return 0 on success.

### Examples

```java
// Simple field access on the receiver
@BuiltinBPFFunction("($this->data)")
int data();

// Map lookup — $pointery wraps non-pointer keys in & automatically
@BuiltinBPFFunction("bpf_map_lookup_elem(&$this, $pointery$arg1)")
Ptr<V> bpf_get(K key);

// Map update, return value inverted to boolean
@BuiltinBPFFunction("!bpf_map_update_elem(&$this, $pointery$arg1, $pointery$arg2, BPF_ANY)")
boolean put(K key, V value);

// GNU statement expression for atomic increment
@BuiltinBPFFunction("({ __typeof__($arg2) *___v = bpf_map_lookup_elem(&$this, $pointery$arg1); " +
                    "if (___v) __sync_fetch_and_add(___v, $arg2); })")
void bpf_increment(K key, V delta);

// GNU statement expression for lookup-or-default
@BuiltinBPFFunction("({ __typeof__($arg2) *___v = bpf_map_lookup_elem(&$this, $pointery$arg1); " +
                    "___v ? *___v : $arg2; })")
V bpf_getOrDefault(K key, V defaultValue);

// Composite expression using a literal and a helper
@BuiltinBPFFunction("scx_bpf_dsq_insert($arg1, 1 + scx_bpf_task_cpu($arg1), SCX_SLICE_DFL, $arg2)")
void insertOnCurrentCpu(task_struct task, long slice);
```

The template source and parser live in
`bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/MethodTemplate.java`.
Real-world examples are in `BPFBaseMap.java`, `XDPContext.java`, and `TCContext.java`.



The generated `.bpf.c` is written to the annotation output directory after
`mvn package`:

```
target/generated-sources/annotations/me/bechberger/ebpf/.../YourClass.bpf.c
```

The file is plain C. Verifier errors reported by `dmesg` or libbpf refer to
symbols defined in it. `bpftool prog dump xlated` output maps back to the same
symbol names.

## §4 CO-RE and portability

The generated C uses `BPF_CORE_READ` for every struct field access. This macro
emits BTF relocations into the `.o`; libbpf resolves them at load time against
the running kernel's BTF. The result is a single `.o` that loads on any kernel
≥ 5.2 that exports BTF (`CONFIG_DEBUG_INFO_BTF=y`), without recompilation or
per-kernel headers.

## §5 What the processor and plugin do not touch

`main()` and all non-`@BPFFunction` methods run unchanged on the JVM. Map
field access from Java (e.g. `myMap.get(key)`) uses the Panama/libbpf binding,
not the BPF side. The two call paths — kernel eBPF program and Java user-space
code — share the same file descriptor returned by `BPFProgram.load()`.

---

For the error-classifier, diagnostic messages, and plugin extension points, see
[Architecture: Compiler Plugin](../architecture/plugin.md) and
[Diagnostics](../diagnostics.md).
