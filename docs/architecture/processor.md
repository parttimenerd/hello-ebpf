# Annotation Processor

The annotation processor (`bpf-processor`) is a standard javac annotation processor that runs at round 1. It handles `@BPF`, `@BPFMapClass`, `@BPFMapDefinition`, and `@Type` annotations — tasks that need the full type hierarchy and field declarations but not the method bodies.

## Responsibilities

- Discover `@BPF`-annotated classes and verify they extend `BPFProgram` (`Processor.java:135–142`).
- Resolve `@Type`-annotated Java records, classes, and enums to BTF struct layouts via `TypeProcessor`.
- Emit a generated implementation class (e.g. `MyProgram$Impl`) with a `getByteCode()` override; the compiler plugin later fills in the bytecode (`Processor.java:300–367`).
- Write a `META-INF/ebpf-shared-from/<FQN>.json` resource for cross-module `@SharedFrom` map references (`Processor.java:198–202`).
- Validate `@GlobalVariable` field declarations: must be non-static, final, and initialised as `new GlobalVariable<>(...)` (`TypeProcessor.java:602–632`).
- Validate map field names and types for `@BPFMapDefinition` fields.
- Invoke clang (via `Processor.compile()`) to produce the `.o` bytes that are embedded into `getByteCode()`.

## Key classes

| Class | File | Role |
|---|---|---|
| `Processor` | `bpf-processor/.../processor/Processor.java` | Entry-point `AbstractProcessor`; dispatches to `TypeProcessor`, generates implementation class, calls clang |
| `TypeProcessor` | `bpf-processor/.../processor/TypeProcessor.java` | Resolves `@Type` records/classes/enums to `BPFType` instances; emits C struct/enum declarations |
| `BPFTypeLike` | `bpf-processor/.../processor/BPFTypeLike.java` | Sealed hierarchy of BPF-representable type wrappers (struct, enum, typedef, verbatim, …) |
| `DefinedTypes` | `bpf-processor/.../processor/DefinedTypes.java` | Name registry: maps Java names ↔ BPF names ↔ spec field names; detects cycles |
| `AnnotationUtils` | `bpf-processor/.../processor/AnnotationUtils.java` | Helpers for reading annotation mirrors in a javac-version-safe way |
| `CompilationCache` | `bpf-processor/.../processor/CompilationCache.java` | Caches clang compilation results keyed by C source hash to avoid recompiling unchanged programs |
| `CompilerErrorProcessor` | `bpf-processor/.../processor/CompilerErrorProcessor.java` | Parses clang error output and maps C line numbers back to Java source positions |
| `TailCallTableInfo` | `bpf-processor/.../processor/TailCallTableInfo.java` | Holds resolved metadata for `@BPFTailCallTable`-annotated prog-array fields |

## How it differs from the compiler plugin

The processor sees only annotations and type declarations, not method bodies. It runs at annotation-processing time (before the compilation phase), so it can generate new source files that javac will then compile. The compiler plugin runs at compilation time (after all annotation processors have finished), when method ASTs are available. The two components communicate indirectly: the processor generates the `$Impl` class skeleton, and the compiler plugin patches `getByteCode()` by embedding the compiled BPF object file into that class.

## Extending the processor

1. **Add a new annotation.** Define the annotation in the `annotations/` module (not in `bpf-processor/` or `bpf/`).
2. **Add a processor round in `TypeProcessor` or `Processor`.** If the annotation describes a type shape, add a resolution branch in `TypeProcessor.processType()`. If it affects the generated implementation class, add logic in `Processor.processBPFProgram()`.
3. **Write an integration test.** Use the `InMemoryJavaCompiler` helper already used in `bpf-compiler-plugin-test/`. Compile a minimal `@BPF` class that uses the new annotation and assert on the generated Java source or on any diagnostic messages emitted.
