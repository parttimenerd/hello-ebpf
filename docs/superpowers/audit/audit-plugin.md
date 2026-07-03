# Audit: Compiler Plugin Extension Points

Point-in-time snapshot, 2026-07-03. Audience: contributors.

Rows derived from:
- `grep -n 'option\|getOption' bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java` (plugin flags)
- `grep -rn 'printError\|printWarning\|Kind.ERROR\|Kind.WARNING' bpf-processor/src/main/java/` (processor diagnostics)
- `grep -rn 'throw new\|Kind.ERROR\|Kind.WARNING' bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/` (plugin diagnostics and codegen behaviours)

Gap definitions: **OK** = documented with working example. **Partial** = mentioned but no dedicated coverage. **Missing** = not documented. **Rewrite** = coverage is wrong or outdated.

## A — Plugin Flags (javac `-Xplugin:` and `-A` options)

| Symbol / Behaviour | Source path:line | Purpose (≤ 12 words) | Documented in | Gap | Target page |
|--------------------|------------------|----------------------|---------------|-----|-------------|
| `-Xplugin:"BPFCompilerPlugin dumpC=true\|false\|<path>"` | `CompilerPlugin.java:133,319` | Write generated C to file beside source or given path | `diagnostics.md:265-270` (mentions `-AdumpC=true`, wrong prefix) | Partial | `architecture/plugin.md` |
| `-Aebpf.folder=<dir>` | `Processor.java:1007` | Base folder for resolving `EBPF_PROGRAM` path constants | `Processor.java:606` (error message only) | Missing | `architecture/plugin.md` |

## B — Annotation Processor Diagnostics (bpf-processor)

### Processor.java

| Symbol / Behaviour | Source path:line | Purpose (≤ 12 words) | Documented in | Gap | Target page |
|--------------------|------------------|----------------------|---------------|-----|-------------|
| ERROR: class not extending `BPFProgram` | `Processor.java:136-142` | Reject `@BPF` class not inheriting `BPFProgram` | — | Missing | `architecture/errors.md` |
| WARNING: deprecated API usage | `Processor.java:221` | Warn when deprecated BPF API element is used | — | Missing | `architecture/errors.md` |
| ERROR: `EBPF_PROGRAM` field wrong type | `Processor.java:589` | Field must be `String` or `Path` | — | Missing | `architecture/errors.md` |
| ERROR: `EBPF_PROGRAM` not a constant | `Processor.java:596` | Field must evaluate to a compile-time constant | — | Missing | `architecture/errors.md` |
| ERROR: `EBPF_PROGRAM` path does not exist | `Processor.java:606` | Referenced C file missing; hints at `-Aebpf.folder` | — | Missing | `architecture/errors.md` |
| WARNING: no license defined | `Processor.java:701` | Warn when no `license` field is present | — | Missing | `diagnostics.md` |
| ERROR: license defined twice | `Processor.java:705` | Field and annotation both define license | — | Missing | `architecture/errors.md` |
| ERROR: clang compilation failed | `Processor.java:882,896-901` | C compilation of generated BPF source failed | `diagnostics.md:265` (partial) | Partial | `architecture/errors.md` |

### TypeProcessor.java

| Symbol / Behaviour | Source path:line | Purpose (≤ 12 words) | Documented in | Gap | Target page |
|--------------------|------------------|----------------------|---------------|-----|-------------|
| ERROR: enum implements `Typedef` | `TypeProcessor.java:132` | Enums must not implement `Typedef` | — | Missing | `architecture/errors.md` |
| ERROR: enum does not implement `Enum` interface | `TypeProcessor.java:138` | BPF enums must implement the `Enum` marker interface | — | Missing | `architecture/errors.md` |
| ERROR: record has superclass | `TypeProcessor.java:148` | BPF record types must not extend other classes | — | Missing | `architecture/errors.md` |
| ERROR: nested class not static | `TypeProcessor.java:158,173` | Inner BPF type classes must be static | — | Missing | `architecture/errors.md` |
| ERROR: union implements `Typedef` | `TypeProcessor.java:181` | Union types must not implement `Typedef` | — | Missing | `architecture/errors.md` |
| ERROR: typedef also extends `TypedefBase` | `TypeProcessor.java:188` | Typedef must not doubly inherit | — | Missing | `architecture/errors.md` |
| ERROR: class does not extend `Object`/`Union`/`Struct` | `TypeProcessor.java:195` | BPF class hierarchy constraint | — | Missing | `architecture/errors.md` |
| WARNING: unknown annotation on type member | `TypeProcessor.java:381` | Flag unrecognised annotation so user doesn't silently lose it | — | Missing | `architecture/errors.md` |
| ERROR: unsupported annotation combination | `TypeProcessor.java:476` | Annotation combo rejected by type system | — | Missing | `architecture/errors.md` |
| ERROR: `GlobalVariable` field not `final` | `TypeProcessor.java:602` | GlobalVariable fields must be final | `global-variables.md` (implicit) | Partial | `architecture/errors.md` |
| ERROR: `GlobalVariable` field is `static` | `TypeProcessor.java:607` | GlobalVariable fields must be instance fields | `global-variables.md` (implicit) | Partial | `architecture/errors.md` |
| ERROR: `GlobalVariable` field is `Box` | `TypeProcessor.java:614` | Box wrapper not needed around GlobalVariable | — | Missing | `architecture/errors.md` |
| ERROR: `GlobalVariable` missing initializer | `TypeProcessor.java:628` | Field must call `new GlobalVariable<>(...)` | — | Missing | `architecture/errors.md` |
| ERROR: `GlobalVariable` bad initializer form | `TypeProcessor.java:632` | Initializer must be `new GlobalVariable<>(...)` | — | Missing | `architecture/errors.md` |
| ERROR: type recursion detected | `TypeProcessor.java:653` | Cycle in BPF type definitions | — | Missing | `architecture/errors.md` |
| ERROR: type not defined | `TypeProcessor.java:660` | Referenced type is unknown | — | Missing | `architecture/errors.md` |
| ERROR: type could not be processed | `TypeProcessor.java:666` | Generic type-processing failure | — | Missing | `architecture/errors.md` |
| ERROR: enum member duplicate C name | `TypeProcessor.java:823` | Two enum members map to same C identifier | — | Missing | `architecture/errors.md` |
| ERROR: record member count mismatch | `TypeProcessor.java:886` | Record components don't match BPF struct fields | — | Missing | `architecture/errors.md` |
| ERROR: class member count mismatch | `TypeProcessor.java:915` | Class fields don't match BPF struct fields | — | Missing | `architecture/errors.md` |
| ERROR: union has non-default constructor | `TypeProcessor.java:930` | Union classes must have only the default constructor | — | Missing | `architecture/errors.md` |
| ERROR: member has initializer | `TypeProcessor.java:961` | Struct/union members must not have initializers | — | Missing | `architecture/errors.md` |
| ERROR: `@InlineUnion` on non-record | `TypeProcessor.java:981` | `@InlineUnion` is only valid on records | — | Missing | `architecture/errors.md` |
| ERROR: `@InlineUnion` members not contiguous | `TypeProcessor.java:1011` | Same union ID must group consecutive members | — | Missing | `architecture/errors.md` |
| ERROR: `@InlineUnion` offset mismatch | `TypeProcessor.java:1023` | Same union ID members must share the same offset | — | Missing | `architecture/errors.md` |
| ERROR: member type could not be processed | `TypeProcessor.java:1048,1059` | Generic member type-resolution failure | — | Missing | `architecture/errors.md` |
| ERROR: `Box` not allowed in context | `TypeProcessor.java:1118` | Box is invalid at this position | — | Missing | `architecture/errors.md` |
| ERROR: `Box` type must be a class | `TypeProcessor.java:1122` | Box type argument must be a class type | — | Missing | `architecture/errors.md` |
| ERROR: `Box` must have exactly one type argument | `TypeProcessor.java:1127` | Box requires a single generic parameter | — | Missing | `architecture/errors.md` |
| ERROR: unsupported type | `TypeProcessor.java:1162,1177` | Type cannot be represented in BPF C | — | Missing | `architecture/errors.md` |
| ERROR: pointer needs one type argument | `TypeProcessor.java:1191` | `Ptr<T>` must have exactly one type parameter | — | Missing | `architecture/errors.md` |
| ERROR: `@Size` required for array | `TypeProcessor.java:1254,1263` | Array fields need `@Size(N)` annotation | `global-variables.md` (partial) | Partial | `architecture/errors.md` |
| ERROR: unsigned char not supported | `TypeProcessor.java:1299` | `char` in unsigned context is unsupported | — | Missing | `architecture/errors.md` |
| ERROR: unsupported integer type | `TypeProcessor.java:1305` | Integer type has no BPF mapping | — | Missing | `architecture/errors.md` |
| ERROR: `@Size` required for string | `TypeProcessor.java:1317` | String fields need `@Size(N)` annotation | — | Missing | `architecture/errors.md` |
| ERROR: type not annotated with `@Type` | `TypeProcessor.java:1331` | Struct/union type must carry `@Type` annotation | — | Missing | `architecture/errors.md` |
| ERROR: `specFieldName` must be set | `TypeProcessor.java:1399` | `@StructOps` annotation missing `specFieldName` | — | Missing | `architecture/errors.md` |
| ERROR: struct member type unresolvable | `TypeProcessor.java:1478,1485` | Member type cannot be mapped to a C type | — | Missing | `architecture/errors.md` |

## C — CompilerPlugin Diagnostics

| Symbol / Behaviour | Source path:line | Purpose (≤ 12 words) | Documented in | Gap | Target page |
|--------------------|------------------|----------------------|---------------|-----|-------------|
| ERROR: `BPFFunction` processing failure | `CompilerPlugin.java:603` | Generic error processing `@BPFFunction`-annotated method | — | Missing | `architecture/errors.md` |
| ERROR: BPF interface processing failure | `CompilerPlugin.java:777` | Generic error processing `@BPF` class | — | Missing | `architecture/errors.md` |
| ERROR: duplicate `@PropertyDefinition` | `CompilerPlugin.java:921` | Two definitions for the same property name | `struct-ops.md:62` (mentions feature) | Partial | `architecture/errors.md` |
| ERROR: duplicate `@Property` value | `CompilerPlugin.java:933` | Same property specified twice | — | Missing | `architecture/errors.md` |
| ERROR: property value fails regexp | `CompilerPlugin.java:955` | `@PropertyDefinition.regexp()` not matched | — | Missing | `architecture/errors.md` |
| ERROR: undefined properties | `CompilerPlugin.java:965` | `@Property` keys without `@PropertyDefinition` | — | Missing | `architecture/errors.md` |
| ERROR: property not defined (with closest match) | `CompilerPlugin.java:970` | Typo detection for property names | — | Missing | `architecture/errors.md` |
| ERROR: not all methods processed | `CompilerPlugin.java:1054` | Some `@BPFFunction` methods were skipped | — | Missing | `architecture/errors.md` |
| ERROR: missing `@BPFImpl` annotation | `CompilerPlugin.java:1129` | BPF program implementation class needs `@BPFImpl` | — | Missing | `architecture/errors.md` |
| ERROR: conflicting inter-method definitions | `CompilerPlugin.java:1180` | Method defined in two incompatible ways | — | Missing | `architecture/errors.md` |
| ERROR: C code write failure (`dumpC`) | `CompilerPlugin.java:1260` | Could not write generated C to dump path | — | Missing | `architecture/errors.md` |
| ERROR: no output folder | `CompilerPlugin.java:1288` | Bytecode output directory missing | — | Missing | `architecture/errors.md` |
| ERROR: bytecode write failure | `CompilerPlugin.java:1295` | Could not write compiled BPF object file | — | Missing | `architecture/errors.md` |

## D — Translator Diagnostics (code-gen-time errors)

| Symbol / Behaviour | Source path:line | Purpose (≤ 12 words) | Documented in | Gap | Target page |
|--------------------|------------------|----------------------|---------------|-----|-------------|
| ERROR: unsupported return type | `Translator.java:187,193` | BPF does not support the Java return type | — | Missing | `architecture/errors.md` |
| ERROR: unsupported parameter type | `Translator.java:233` | BPF does not support the Java parameter type | — | Missing | `architecture/errors.md` |
| ERROR: method lacks `@BPFFunction` | `Translator.java:262` | Body method must be annotated with `@BPFFunction` | — | Missing | `architecture/errors.md` |
| ERROR: labelled break/continue | `Translator.java:538,545` | Labelled break/continue not supported | — | Missing | `architecture/errors.md` |
| ERROR: enhanced for-loop | `Translator.java:551` | `for (T x : coll)` not supported in BPF | — | Missing | `architecture/errors.md` |
| ERROR: switch statement | `Translator.java:558` | Switch is rejected (verifier rejects jump tables) | — | Missing | `architecture/errors.md` |
| ERROR: try-catch | `Translator.java:565` | Exception handling not supported in BPF | — | Missing | `architecture/errors.md` |
| ERROR: unsupported statement kind | `Translator.java:572` | Generic unsupported-statement fallthrough | — | Missing | `architecture/errors.md` |
| ERROR: string concatenation in BPF | `Translator.java:691` | String `+` operator not supported in BPF context | — | Missing | `architecture/errors.md` |
| ERROR: unsupported binary operator | `Translator.java:726` | Binary operator has no BPF equivalent | — | Missing | `architecture/errors.md` |
| ERROR: unsupported unary operator | `Translator.java:747` | Unary operator has no BPF equivalent | — | Missing | `architecture/errors.md` |
| ERROR: member not found | `Translator.java:777,784` | Class member resolution failure during translation | — | Missing | `architecture/errors.md` |
| ERROR: Java pointer cast | `Translator.java:875,883` | `(Ptr)` / `(Ptr<T>)` casts are rejected; use BPFJ helpers | `cookbook.md:293-294` (partial) | Partial | `architecture/errors.md` |
| ERROR: unsupported type cast | `Translator.java:896` | Cast to an unsupported type | — | Missing | `architecture/errors.md` |
| ERROR: anonymous class body | `Translator.java:908` | Anonymous class bodies not supported | — | Missing | `architecture/errors.md` |
| ERROR: unsupported class type | `Translator.java:915` | `new X(...)` for unsupported class type | — | Missing | `architecture/errors.md` |
| ERROR: unsupported constructor call | `Translator.java:952,959,969` | `new X(...)` form not handled by translator | — | Missing | `architecture/errors.md` |
| ERROR: constructor argument count mismatch | `Translator.java:982` | Wrong argument count for struct constructor | — | Missing | `architecture/errors.md` |
| ERROR: lambda in unsupported position | `Translator.java:1030` | Lambda only allowed as BPF-loop callback argument | — | Missing | `architecture/errors.md` |
| ERROR: switch expression | `Translator.java:1039` | Switch expressions not supported in BPF | — | Missing | `architecture/errors.md` |
| ERROR: `@InArena` arena unresolvable | `Translator.java:1950` | Plugin cannot determine arena map for `@InArena` field | `cookbook.md:321-323` | Partial | `architecture/errors.md` |
| ERROR: untrusted pointer passed to kfunc | `Translator.java:2439` | Pointer without `@TrustedPtr` passed to kfunc | `cookbook.md:293-294` | Partial | `architecture/errors.md` |

## E — Verifier-Error Classification and Fix Suggestions

| Symbol / Behaviour | Source path:line | Purpose (≤ 12 words) | Documented in | Gap | Target page |
|--------------------|------------------|----------------------|---------------|-----|-------------|
| `ErrorClass.INVALID_MEM_ACCESS` | `VerifierLogParser.java:58` | Invalid register memory-access pattern | `cookbook.md:253` (general) | Partial | `diagnostics.md` |
| `ErrorClass.UNCHECKED_NULL_DEREF` | `VerifierLogParser.java:59` | Null pointer used in arithmetic/comparison | `cookbook.md:§Nullability` | Partial | `diagnostics.md` |
| `ErrorClass.OUT_OF_BOUNDS` | `VerifierLogParser.java:60` | Array/pointer index not provably in range | `cookbook.md:§Bounds` | Partial | `diagnostics.md` |
| `ErrorClass.STACK_OOB` | `VerifierLogParser.java:61` | Stack access outside 512-byte frame | `cookbook.md:§Stack` | Partial | `diagnostics.md` |
| `ErrorClass.TYPE_MISMATCH` | `VerifierLogParser.java:62` | Helper argument type wrong for expected region | `cookbook.md:§Memory regions` | Partial | `diagnostics.md` |
| `ErrorClass.UNREACHABLE_INSTRUCTION` | `VerifierLogParser.java:63` | Dead code or fall-through after unconditional return | `cookbook.md:§Control flow` | Partial | `diagnostics.md` |
| `ErrorClass.INFINITE_LOOP` | `VerifierLogParser.java:64` | Unbounded loop or instruction-budget exceeded | `cookbook.md:§Loops` | Partial | `diagnostics.md` |
| `ErrorClass.HELPER_NOT_ALLOWED` | `VerifierLogParser.java:65` | BPF helper not allowed in this program section | `cookbook.md:§Helpers` | Partial | `diagnostics.md` |
| `ErrorClass.UNRESOLVED_FUNC` | `VerifierLogParser.java:66` | Call to unknown or disallowed function | `cookbook.md:§Helpers` | Partial | `diagnostics.md` |
| `ErrorClass.PROGRAM_TOO_LARGE` | `VerifierLogParser.java:67` | Program exceeds instruction or size budget | `cookbook.md:§Program size` | Partial | `diagnostics.md` |
| `ErrorClass.ARENA_NOT_ASSOCIATED` | `VerifierLogParser.java:68` | `addr_space_cast` in program with no arena association | `cookbook.md:§Arena` | Partial | `diagnostics.md` |
| `ErrorClass.INVALID_TIMER_DEFINITION` | `VerifierLogParser.java:69` | `bpf_timer` used bare as map value | `cookbook.md:§Timers` | Partial | `diagnostics.md` |
| `ErrorClass.OTHER` | `VerifierLogParser.java:70` | Catch-all for unclassified verifier rejections | `cookbook.md:§Verifier` | Partial | `diagnostics.md` |
| `VerifierFixSuggester.suggest()` | `VerifierFixSuggester.java:22` | Converts parsed error to 4-part What/Why/Fix/See hint | `cookbook.md:253` | Partial | `diagnostics.md` |
| `VerifierLogParser.parseLog()` | `VerifierLogParser.java:74` | Parses raw libbpf verifier log into structured `ParseResult` | — | Missing | `diagnostics.md` |
| `SourceMapReader` | `VerifierLogParser.java` (stage 16) | Maps BPF instruction offsets to Java source positions | — | Missing | `diagnostics.md` |

## F — Code-Gen Behaviours (Translator + CompilerPlugin passes)

| Symbol / Behaviour | Source path:line | Purpose (≤ 12 words) | Documented in | Gap | Target page |
|--------------------|------------------|----------------------|---------------|-----|-------------|
| `@BPFAbstraction` local variable substitution | `Translator.java:347,617,633` | Replaces abstraction variable with its C carrier expression | `sched_ext.md:232`, `changelog.md:77` | Partial | `architecture/plugin.md` |
| `@BPFAbstraction` factory/constructor carrier yield | `Translator.java:1183` | Constructor call yields the carrier expression, not Java object | — | Missing | `architecture/plugin.md` |
| `@InArena` pointer qualifier injection | `Translator.java:1872-1883` | Wraps pointer declarator with `__arena` qualifier | `cookbook.md:296-323` | OK | `architecture/plugin.md` |
| `@InArena` arena-map tracking for ArenaAssociationPass | `Translator.java:1077-1098` | Records which `@InArena` deref belongs to which arena | `cookbook.md:304` (brief) | Partial | `architecture/plugin.md` |
| `@TrustedPtr` untrusted-pointer guard | `Translator.java:2335-2439` | Emits compile-error when un-trusted ptr reaches a kfunc | `cookbook.md:293-294` | Partial | `architecture/plugin.md` |
| `__arena` prelude auto-injection | `CompilerPlugin.java:1225-1247` | Adds `#define __arena __attribute__((address_space(1)))` when missing | — | Missing | `architecture/plugin.md` |
| `SEC(".data")` global hoist | `CompilerPlugin.java:1516-1535` | Primitive `SEC(".data")` declarations moved before function bodies | — | Missing | `architecture/plugin.md` |
| `@Sleepable` SEC suffix on struct\_ops methods | `StructOpsSynthesizer.java:99-102` | Emits `SEC("struct_ops.s/<field>")` instead of non-sleepable form | `struct-ops.md:45-54` | OK | `architecture/plugin.md` |
| `emittedNamePrefix` on `@StructOps` | `StructOpsDiscovery.java:31,41,57` | Prepends prefix to each synthesised struct\_ops C function name | `struct-ops.md` (not shown) | Missing | `architecture/plugin.md` |
| `@PropertyDefinition` / `@Property` template substitution | `CompilerPlugin.java:914-970` | Replaces `{{name}}` placeholders in generated C with `@Property` values | `struct-ops.md:62` (mention only) | Partial | `architecture/plugin.md` |
| `ArenaAssociationPass` auto-injection | `CompilerPlugin.java:1037`, `ArenaAssociationPass.java` | Injects per-arena association helper calls into struct\_ops entries | `cookbook.md:304` (brief) | Partial | `architecture/plugin.md` |
| `StructOpsDiscovery` superclass walk | `StructOpsDiscovery.java:22-57` | Discovers `@StructOps` kinds by walking the full class hierarchy | — | Missing | `architecture/plugin.md` |
| `StructOpsValidator` field/arg/return validation | `CompilerPlugin.java:426-472` | Cross-checks Java method signatures against kernel BTF layout | — | Missing | `architecture/plugin.md` |
| Switch / try-catch rejection with diagnostic | `Translator.java:558,565` | Java constructs with no safe BPF lowering are compile errors | — | Missing | `architecture/errors.md` |
| Enhanced for-loop rejection | `Translator.java:551` | `for(T x : coll)` has no BPF equivalent; replaced by `bpfForEach` | — | Missing | `architecture/errors.md` |
| Lambda context restriction | `Translator.java:1030` | Lambdas only allowed as callbacks to `bpfLoop`/`bpfForEach`/timers | — | Missing | `architecture/plugin.md` |
| `@BuiltinBPFFunction` template render | `MethodTemplate.java:87-270` | Expands `$arg1`/`$typeof`/`$lambda` etc. placeholders to C code | memory `reference_method_template_language.md` | Partial | `architecture/plugin.md` |
| `InternalMethodDefinition` persistence | `CompilerPlugin.java:607-635` | Stores compiled C body on method symbol for downstream callers | — | Missing | `architecture/plugin.md` |
| `moveIncludesToTheFront` include hoisting | `CompilerPlugin.java:1514-1536` | `#include` lines and primitive globals hoisted before function bodies | — | Missing | `architecture/plugin.md` |
