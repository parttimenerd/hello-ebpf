# Contributing

hello-ebpf has a split test environment: the compiler plugin and annotation processor are tested with pure-Java tools (no Linux kernel required); BPF integration tests require a real kernel and run in `vng` (virtme-ng) on a Linux machine (the project uses a dedicated thinkstation). CI runs the full suite on `ubuntu-26.04` hosted runners that provide a 6.x kernel with BTF enabled.

## Development environment

### Mac (plugin and annotation processor work)

Standard Maven test on the pure-Java modules:

```
./mvnw test -pl annotations,bpf-processor,bpf-compiler-plugin,bpf-compiler-plugin-test
```

No kernel, no clang, and no BPF headers are needed for these tests. `CompilerPluginTest` compiles `@BPF` classes in-process via `InMemoryJavaCompiler` and asserts on the generated C string.

### Linux / thinkstation (BPF integration tests)

Prerequisites (from `.github/workflows/ci.yml`):

- clang 19+ (`apt install clang-19`)
- `libbpf-dev`, `linux-tools-$(uname -r)`, `bpftool`
- Linux kernel 6.17 or later with BTF (`/sys/kernel/btf/vmlinux` present)
- `CONFIG_SCHED_CLASS_EXT=y` and `CONFIG_BPF_LSM=y` for scheduler and LSM tests

Run BPF integration tests as root (sudo strips PATH; supply `HOME` and `JAVA_HOME` explicitly):

```
sudo -E env HOME=$HOME JAVA_HOME=$JAVA_HOME PATH=$JAVA_HOME/bin:$PATH \
  ./mvnw -ntp -B test -pl bpf,bpf-samples \
  -Dmaven.test.skip=false -DskipTests=false
```

For tests that need `vng`, write logs to `/tmp` rather than the repo directory: virtme-ng's copy-on-write overlay silently discards writes to the host filesystem on exit.

## Module structure

| Module | What it contains |
|---|---|
| `annotations` | All `@BPF*`, `@Type`, `@Size`, etc. annotation definitions; no runtime code |
| `bpf-processor` | Annotation processor (`Processor`, `TypeProcessor`); generates `$Impl` class skeletons |
| `bpf-compiler-plugin` | javac compiler plugin; translates `@BPFFunction` bodies to C and embeds the `.o` |
| `bpf-compiler-plugin-test` | Pure-Java unit tests for the compiler plugin using `InMemoryJavaCompiler` |
| `bpf` | Runtime: `BPFProgram`, map types, `BPFJ` helpers, BPF integration tests |
| `bpf-runtime` | Auto-generated Panama bindings for the kernel BPF uAPI (~1000 files) |
| `bpf-samples` | End-to-end sample programs; doubles as integration-test source |
| `bpf-archetype` | Maven archetype for bootstrapping new hello-ebpf projects |

## Adding a new hook type end-to-end

1. Add a `@MyHook` annotation in `annotations/src/main/java/me/bechberger/ebpf/annotations/`. Follow the pattern of existing hook annotations in that package.
2. Register the SEC pattern. If the hook maps to a known `SEC("mytype/...")` string, add a case to `ProgramType` (in `bpf/`) so `autoAttachPrograms` can discover it. If the SEC string requires codegen (e.g. a per-field suffix), register the pattern in the compiler plugin's `processBPFProgramImpl` dispatch.
3. Add a Java interface (e.g. `MyHookInterface`) with a default-body method for the callback. The Java body must throw `MethodIsBPFRelatedFunction()` so the compiler plugin recognises it as a BPF-only method.
4. Add attach logic in `BPFProgram` (or as a new `@StructOps`-style handler) using the existing `autoAttachPrograms` mechanism or a dedicated `attach*` method.
5. Write a compiler plugin test in `bpf-compiler-plugin-test/` that compiles a minimal `@BPF` class implementing the interface and asserts the generated C contains the expected `SEC("mytype/...")` declaration.
6. Write a BPF integration test in `bpf/src/test/java/` that loads the program on a real kernel, attaches it, and verifies it fires.

## Coding conventions

- Annotations belong in `annotations/`, not in `bpf/` or `bpf-processor/`.
- Methods that exist only on the BPF side must have `throw new MethodIsBPFRelatedFunction()` as their Java body. This is the signal the compiler plugin uses to recognise them as translation targets.
- Do not write inline C strings inside `@BPF` classes. Use `@BuiltinBPFFunction` templates with `$arg1`, `$typeof`, `$lambda`, etc. placeholders instead. The template language is documented in `memory/reference_method_template_language.md`.
- BPF integration tests live in `bpf/src/test/java/` and are tagged so they are skipped when running without root or a kernel. Check existing tests (e.g. `XDPTest.java`) for the `@Tag` convention in use.
- Do not name `@StructOps` interface method arguments `ctx` — the `BPF_PROG` macro reserves that identifier and clang will reject the generated C (`feedback_bpf_prog_macro_ctx_collision.md`).
