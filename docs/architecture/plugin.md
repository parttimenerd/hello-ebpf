# Compiler Plugin Overview

**Blog series:** [Part 5 — First steps with libbpf](https://mostlynerdless.de/blog/2024/02/26/hello-ebpf-first-steps-with-libbpf-5/) · [Part 8 — Generating C code from Java](https://mostlynerdless.de/blog/2024/04/09/hello-ebpf-generating-c-code-8/) · [Part 11 — BTF and 13,000 generated Java classes](https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/) · [Part 12 — Write eBPF in pure Java](https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/)

![Annotation processor + compiler plugin pipeline](https://mostlynerdless.de/wp-content/uploads/2024/07/compiler_pipeline-2000x1125.png)

The compiler plugin is a javac `Plugin` (not an annotation processor) that intercepts the compilation of `@BPF`-annotated classes. It runs after annotation processing, walks the AST of each `@BPFFunction`-annotated method, and emits C. The annotation processor (`Processor`) generates an implementation class with a `getByteCode()` override; the compiler plugin fills in that bytecode by translating Java method bodies to C, invoking clang, and embedding the resulting `.o` as a jar resource.

## Entry point

Class: `me.bechberger.ebpf.bpf.compiler.CompilerPlugin`
File: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java`

The class implements `com.sun.source.util.Plugin`. javac discovers it via the SPI file:

```
bpf-compiler-plugin/src/main/resources/META-INF/services/com.sun.source.util.Plugin
```

That file contains a single line: `me.bechberger.ebpf.bpf.compiler.CompilerPlugin`.

javac calls `CompilerPlugin.init(JavacTask task, String... args)` (line 307) at the start of each compilation. The `init` method registers a `TaskListener` that fires after `ANALYZE` events. This ensures the full type hierarchy is resolved before translation begins.

## Translation pipeline

1. **Discover `@BPF` classes.** The `TaskListener.finished()` callback calls `getBPFProgramImpls()` on the `CompilationUnitTree` to collect all classes that extend `BPFProgram` and carry the generated `@BPFImpl` annotation.
2. **Translate each `@BPFFunction` method.** `processBPFProgramImpl()` iterates the methods. For each one it calls `Translator.translate()`, which walks the javac AST and produces a `CAST.Statement.FunctionDeclarationStatement`.
3. **Run `ArenaAssociationPass`.** After all methods are translated, `ArenaAssociationPass` examines the `directArenaRefs` map populated by `Translator` and injects per-arena association helper calls into `struct_ops` entry points (`CompilerPlugin.java:1037`, `ArenaAssociationPass.java`).
4. **Assemble and write the C file.** `combineCode()` hoists `#include` directives and primitive `SEC(".data")` declarations before the function bodies (`CompilerPlugin.java:1514–1536`), then writes the result to `target/generated-sources/annotations/<ClassName>.bpf.c`.
5. **Invoke clang.** `Processor.compile()` calls `findNewestClangVersion()` and runs clang with `-O2 -g -std=gnu2y -target bpf` (`Processor.java:865`). Clang 19+ is required.
6. **Embed the object file.** The compiled `.o` bytes are gzip-compressed, base64-encoded, and stored as a `static final` field in the generated implementation class. For large programs the bytes are written as a class-path resource named `<FQN>.o` and loaded at runtime via `getByteCode()` (`Processor.java:1282`).

## Key classes

| Class | File | Role |
|---|---|---|
| `CompilerPlugin` | `bpf-compiler-plugin/.../compiler/CompilerPlugin.java` | javac `Plugin` entry point; orchestrates discovery, translation, codegen, clang invocation |
| `Translator` | `bpf-compiler-plugin/.../compiler/Translator.java` | Walks javac AST, converts Java statements and expressions to `CAST` nodes |
| `CAST` | `bpf-compiler-plugin/.../cast/CAST.java` (module `cast`) | Immutable C AST; rendered to a C string by `CAST.Statement.render()` |
| `ArenaAssociationPass` | `bpf-compiler-plugin/.../compiler/passes/ArenaAssociationPass.java` | Post-translation pass; wires `@InArena` map references to struct_ops program entries |
| `VerifierFixSuggester` | `bpf-compiler-plugin/.../compiler/VerifierFixSuggester.java` | Converts a parsed verifier log entry into a four-part What/Why/Fix/See diagnostic hint |

## Plugin flags

The plugin accepts a single argument block passed to `-Xplugin`:

| Flag | Example | Effect |
|---|---|---|
| `dumpC=true` | `-Xplugin:"BPFCompilerPlugin dumpC=true"` | Write the generated `.bpf.c` to a file beside the source (default path: `<ClassName>.bpf.c` in the source directory) |
| `dumpC=false` | `-Xplugin:"BPFCompilerPlugin dumpC=false"` | Suppress C dump (default) |
| `dumpC=<path>` | `-Xplugin:"BPFCompilerPlugin dumpC=/tmp/out.c"` | Write the generated C to the given absolute path |

Source: `CompilerPlugin.java:133,319`.

The annotation processor accepts a separate `-A` flag:

| Flag | Example | Effect |
|---|---|---|
| `-Aebpf.folder=<dir>` | `-Aebpf.folder=/my/project/src/bpf` | Base directory used when resolving `EBPF_PROGRAM` path constants (source: `Processor.java:1007`) |

## Adding a new translation rule

1. **Find the AST node handler.** Open `Translator.java` and locate the `visitXxx` method or `switch` case that handles the Java construct you want to translate (e.g. `visitMethodInvocation`, expression dispatch in `translateExpression`).
2. **Add the case.** Produce the appropriate `CAST` node. Emit a `logger.printError(path, node, "message")` for unsupported sub-cases rather than silently dropping them.
3. **Write a test.** Add a test class to `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/CompilerPluginTest.java`. Tests compile a small `@BPF` class via `InMemoryJavaCompiler` and assert on the generated C string — no kernel or clang needed.
