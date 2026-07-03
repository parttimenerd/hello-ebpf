# How the Plugin Works

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
(`bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java`).
It discovers `@BPFMapClass`/`@BPFMapDefinition` fields and `@Type`-annotated
records, resolves their BTF struct layouts, and writes a `.bpf.json` manifest
that the compiler plugin reads in phase 2.

**Phase 2 — Compiler plugin (`bpf-compiler-plugin`).**
Runs during the compilation pass, after annotation processing
(`bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java`).
For each `@BPF` class it walks the AST of every `@BPFFunction` method, translates
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

## §3 Inspecting the generated C

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
