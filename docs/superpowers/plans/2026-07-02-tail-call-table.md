# @BPFTailCallTable Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an ergonomic annotation surface — `@BPFTailCallTable` + `@TailCallSlot` — over the existing `BPFProgArray` primitive, so users declare a slots-enum once and the annotation processor auto-registers each `@TailCallSlot`-marked `@BPFFunction` at load time. Add a `replaceSlot` freplace hot-swap API on `BPFProgArray`, a full `HelloTailCall` XDP sample, and vng-verified real-kernel tests.

**Architecture:** Two new annotations live in `annotations/` alongside `@BPFMapDefinition`. `@BPFTailCallTable` targets a `BPFProgArray` field and takes `slots()` (an enum class). `@TailCallSlot` targets methods and takes a `String` name matching a constant of that enum. The bpf-processor (`TypeProcessor` + `Processor`) discovers both, validates them, and emits `progArray.register(<enum ordinal>, getProgramByName("<method name>"))` statements into the generated `ProgramImpl` constructor, right after existing map initializers. `BPFProgArray` grows one runtime method: `replaceSlot(int, ProgramHandle)` using libbpf's `bpf_program__attach_freplace`, gated on `Features.hasProgramType(EXT)` (kernel ≥ 5.10).

**Tech Stack:** Java 25 (sapmchn), annotations module (compile-time constants), bpf-processor (annotation processing, JavaPoet codegen), bpf module (libbpf FFI via `Lib`/`Lib_2`), bpf-samples (user-facing runnable), bpf-compiler-plugin-test (in-memory `javac` diagnostic assertion), vng + qemu (real-kernel harness on thinkstation), libbpf ≥ 1.4 (`bpf_program__attach_freplace`).

**Reference existing code (read before starting):**
- `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java` — the primitive we wrap.
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/TailCallDemo.java` — hand-registered predecessor of `HelloTailCall`.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/TailCallTest.java` — existing kernel-side integration test for tail calls.
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFMapDefinition.java` — annotation shape to mirror.
- `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java` — search `BPF_MAP_DEFINITION` (line 57) and `processDefinedMaps` (line 1433).
- `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/Processor.java` — constructor codegen (lines 391-408).
- `bpf/src/main/java/me/bechberger/ebpf/bpf/features/Features.java` — feature-probe surface (`Features.hasProgramType`).
- `bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFProgramType.java` — `EXT(28)` enum constant.

---

## File Structure

**New files (annotations):**
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFTailCallTable.java` — field annotation carrying `slots()` enum class.
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/TailCallSlot.java` — method annotation carrying `value()` (String enum-constant name).

**New files (samples):**
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloTailCall.java` — XDP profiler-style tail-call chain with 3 slots.

**New files (JVM-only compiler tests):**
- `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCompileErrorTest.java` — diagnostic-text assertions.
- `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCodegenTest.java` — asserts the generated `Impl.java` source contains the expected `register(...)` statements.

**New files (real-kernel tests, vng-only):**
- `bpf-samples/src/test/java/me/bechberger/ebpf/samples/HelloTailCallSmokeTest.java` — loads `HelloTailCall`, forces packet traffic on `lo`, asserts each slot fired ≥ N times.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/TailCallReplaceSlotTest.java` — freplace hot-swap.

**New files (docs):**
- `docs/tail-calls.md` — one-page: annotation surface, freplace section, links to sample + primitive.

**Modified files:**
- `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java` — add `replaceSlot(int, ProgramHandle)` and its libbpf handler.
- `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java` — discover `@BPFTailCallTable` + `@TailCallSlot`, validate, thread through `MapDefinition`/new record.
- `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/Processor.java` — emit `register(...)` statements after existing `mapDefinitions().forEach(...)` block.
- `README.md` — one-line link to `docs/tail-calls.md` under Features.

**Decomposition rationale:** Annotations land first (Task 1) so the rest of the code can reference them. Discovery (Task 2) and codegen (Task 3) split cleanly because discovery is a pure validation stage that returns a data structure; codegen consumes it. `replaceSlot` (Task 4) is orthogonal to codegen and only touches `BPFProgArray`, so it can proceed in parallel once Task 1 lands. Sample and real-kernel tests (Tasks 5-7) all depend on Tasks 1-4. Docs (Task 8) close out.

---

## Tasks

### Task 1: `@BPFTailCallTable` + `@TailCallSlot` annotation sources + annotation-only sanity tests

**Files:**
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFTailCallTable.java`
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/TailCallSlot.java`
- Create: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCompileErrorTest.java`

- [ ] **Step 1: Write the annotation source `BPFTailCallTable.java`**

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks a {@code BPFProgArray} field as a tail-call dispatch table with
 * named, enum-driven slots. Sits alongside {@link BPFMapDefinition} on the
 * same field:
 *
 * {@snippet :
 *   enum Slot { PARSE_ETH, PARSE_IP, COUNT }
 *
 *   @BPFTailCallTable(slots = Slot.class)
 *   @BPFMapDefinition(maxEntries = 3)
 *   BPFProgArray dispatch;
 * }
 *
 * <p>Every {@code @BPFFunction} method annotated with {@link TailCallSlot} whose
 * {@code value()} names a constant of {@link #slots()} will be auto-registered
 * into this table at program load time. The slot index is the enum constant's
 * {@link Enum#ordinal() ordinal}.
 *
 * <p>The annotation processor emits {@code register(ordinal, getProgramByName(methodName))}
 * calls into the generated {@code ProgramImpl} constructor. Users may still call
 * {@link me.bechberger.ebpf.bpf.map.BPFProgArray#register} manually to override slots.
 *
 * <p>{@code maxEntries} on the sibling {@code @BPFMapDefinition} must equal
 * {@code slots().getEnumConstants().length}; the processor emits a compile-time
 * error otherwise.
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFTailCallTable {
    /** The enum type whose constants name the slots. Slot index = ordinal. */
    Class<? extends Enum<?>> slots();
}
```

- [ ] **Step 2: Write the annotation source `TailCallSlot.java`**

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks a {@link BPFFunction}-annotated method as the implementation of a
 * specific slot in a {@link BPFTailCallTable}.
 *
 * <p>The {@link #value()} must be the exact name of a constant of the enum
 * referenced by the sibling table's {@code slots()} class. The processor
 * cross-checks this at compile time and emits a diagnostic on mismatch.
 *
 * <p>If the enclosing class declares multiple {@code @BPFTailCallTable} fields,
 * the {@link #table()} attribute disambiguates by field name; otherwise it may
 * be left empty and the sole table is used.
 *
 * <p>Annotation values cannot be arbitrary enum instances, so we take the
 * constant's name as a {@code String} and validate it at annotation-processing
 * time.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface TailCallSlot {
    /** Name of an enum constant of the target table's {@code slots()} class. */
    String value();

    /** Optional table field name when the class has more than one table. */
    String table() default "";
}
```

- [ ] **Step 3: Run `mvn -pl annotations compile` on thinkstation to verify the annotations compile**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.sdkman/candidates/java/25-sapmchn/bin/java -version && ./mvnw -pl annotations -am -DskipTests compile'`
Expected: BUILD SUCCESS, two new `.class` files under `annotations/target/classes/…/bpf/`.

- [ ] **Step 4: Write a JVM-only smoke test for the annotation surface** (this test does NOT exercise the processor yet — that's Task 2)

Create `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCompileErrorTest.java` with a single test that verifies the annotations exist, are runtime-retained, and target the right elements:

```java
package me.bechberger.ebpf.compiler;

import me.bechberger.ebpf.annotations.bpf.BPFTailCallTable;
import me.bechberger.ebpf.annotations.bpf.TailCallSlot;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic sanity checks on the annotation shapes; the interesting compile-error
 * assertions arrive in Task 2 once the processor discovers them.
 */
public class TailCallTableCompileErrorTest {

    @Test
    public void tailCallTableTargetsField() {
        Target t = BPFTailCallTable.class.getAnnotation(Target.class);
        assertNotNull(t);
        assertArrayEquals(new ElementType[]{ElementType.FIELD}, t.value());
    }

    @Test
    public void tailCallTableRuntimeRetained() {
        Retention r = BPFTailCallTable.class.getAnnotation(Retention.class);
        assertEquals(RetentionPolicy.RUNTIME, r.value());
    }

    @Test
    public void tailCallSlotTargetsMethod() {
        Target t = TailCallSlot.class.getAnnotation(Target.class);
        assertNotNull(t);
        assertArrayEquals(new ElementType[]{ElementType.METHOD}, t.value());
    }

    @Test
    public void tailCallSlotHasEmptyTableDefault() throws Exception {
        String def = (String) TailCallSlot.class
                .getMethod("table").getDefaultValue();
        assertEquals("", def);
    }
}
```

- [ ] **Step 5: Run the test on thinkstation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-compiler-plugin-test -am -Dtest=TailCallTableCompileErrorTest test'`
Expected: 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFTailCallTable.java \
        annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/TailCallSlot.java \
        bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCompileErrorTest.java
git commit -m "Add @BPFTailCallTable and @TailCallSlot annotations

Introduce the two annotation types that will drive auto-registration of
BPFProgArray slots in later tasks. Annotations only; processor wiring in
follow-ups."
```

---

### Task 2: Processor discovery + compile-time validation

Add discovery of `@BPFTailCallTable` fields and `@TailCallSlot` methods in `TypeProcessor`. Return a new `TailCallTableInfo` data structure. Emit compile-time errors for:
1. `@BPFTailCallTable` on a non-`BPFProgArray` field.
2. `@BPFTailCallTable` without a sibling `@BPFMapDefinition`.
3. `maxEntries` mismatch between `@BPFMapDefinition.maxEntries()` and `slots().length`.
4. `@TailCallSlot(value = X)` where `X` is not the name of a constant of any table's `slots()` enum.
5. `@TailCallSlot(table = "foo")` where field `foo` is not a `@BPFTailCallTable`.
6. Ambiguity: multiple tables and `@TailCallSlot` without `table = "..."`.

**Files:**
- Modify: `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java`
- Create: `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TailCallTableInfo.java`
- Modify: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCompileErrorTest.java` (add real diagnostic-text tests)

- [ ] **Step 1: Add the data record for discovered tables**

Create `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TailCallTableInfo.java`:

```java
package me.bechberger.ebpf.bpf.processor;

import java.util.List;

/**
 * Result of {@link TypeProcessor#processTailCallTables} — one entry per
 * {@code @BPFTailCallTable} field.
 *
 * @param fieldName    Java field name of the {@code BPFProgArray} field.
 * @param slotEnumFqn  Fully-qualified name of the enum whose ordinals are slot indices.
 * @param slotNames    Enum constants in declaration order (ordinal 0 first).
 * @param registrations One entry per method carrying a matching {@code @TailCallSlot}.
 */
public record TailCallTableInfo(String fieldName,
                                String slotEnumFqn,
                                List<String> slotNames,
                                List<Registration> registrations) {

    /**
     * A single method-to-slot binding. {@code ordinal} is
     * {@code slotNames.indexOf(slotConstant)}.
     */
    public record Registration(String methodName, String slotConstant, int ordinal) {}
}
```

- [ ] **Step 2: Add the discovery method to `TypeProcessor.java`**

Add near line 1433 (below `processDefinedMaps`) and add two constants near line 57:

```java
public final static String BPF_TAIL_CALL_TABLE =
        "me.bechberger.ebpf.annotations.bpf.BPFTailCallTable";
public final static String TAIL_CALL_SLOT =
        "me.bechberger.ebpf.annotations.bpf.TailCallSlot";
```

Then add:

```java
/**
 * Discover {@code @BPFTailCallTable} fields on {@code outerElement} and match
 * every {@code @TailCallSlot}-annotated method against them. Emits compile-time
 * errors on any inconsistency and returns the successfully validated tables.
 * Called after {@link #processDefinedMaps} so we can cross-check that each
 * table field also carries {@code @BPFMapDefinition}.
 */
List<TailCallTableInfo> processTailCallTables(TypeElement outerElement,
                                              List<MapDefinition> alreadyKnownMaps) {
    // 1. Find every field carrying @BPFTailCallTable and validate its shape.
    var messager = this.processingEnv.getMessager();
    var elems    = this.processingEnv.getElementUtils();
    var typeUtil = this.processingEnv.getTypeUtils();

    // fieldName -> (slotEnumFqn, slotNames)
    var tables = new java.util.LinkedHashMap<String, TailCallTableInfo>();

    for (var enc : outerElement.getEnclosedElements()) {
        if (enc.getKind() != ElementKind.FIELD) continue;
        VariableElement vf = (VariableElement) enc;
        var tblAnn = getAnnotationMirror(vf, BPF_TAIL_CALL_TABLE);
        if (tblAnn.isEmpty()) continue;

        String fieldName = vf.getSimpleName().toString();

        // 1a. Must be BPFProgArray.
        TypeMirror fieldType = vf.asType();
        String fieldTypeStr = typeUtil.erasure(fieldType).toString();
        if (!fieldTypeStr.equals("me.bechberger.ebpf.bpf.map.BPFProgArray")) {
            messager.printError("@BPFTailCallTable only applies to BPFProgArray fields — "
                    + "found " + fieldTypeStr, vf);
            continue;
        }

        // 1b. Must have @BPFMapDefinition on the same field.
        boolean hasMapDef = alreadyKnownMaps.stream()
                .anyMatch(m -> m.javaFieldName().equals(fieldName));
        if (!hasMapDef) {
            messager.printError("@BPFTailCallTable requires @BPFMapDefinition on the same "
                    + "field '" + fieldName + "' — the map must be declared to be discovered", vf);
            continue;
        }

        // 1c. Extract the slots enum and its constants.
        TypeMirror slotsMirror = getAnnotationValue(tblAnn.get(), "slots", null);
        if (!(slotsMirror instanceof DeclaredType slotsDecl)) {
            messager.printError("@BPFTailCallTable.slots() must be a Class literal", vf);
            continue;
        }
        TypeElement slotEnum = (TypeElement) slotsDecl.asElement();
        if (slotEnum.getKind() != ElementKind.ENUM) {
            messager.printError("@BPFTailCallTable.slots() must reference an enum type — "
                    + slotEnum.getQualifiedName() + " is not an enum", vf);
            continue;
        }
        var slotNames = slotEnum.getEnclosedElements().stream()
                .filter(e -> e.getKind() == ElementKind.ENUM_CONSTANT)
                .map(e -> e.getSimpleName().toString())
                .toList();
        if (slotNames.isEmpty()) {
            messager.printError("@BPFTailCallTable.slots() enum "
                    + slotEnum.getQualifiedName() + " has no constants", vf);
            continue;
        }

        // 1d. maxEntries must equal slotNames.size().
        var mapDefAnn = getAnnotationMirror(vf.asType(), BPF_MAP_DEFINITION).orElse(null);
        if (mapDefAnn != null) {
            int maxEntries = getAnnotationValue(mapDefAnn, "maxEntries", 0);
            if (maxEntries != slotNames.size()) {
                messager.printError("@BPFTailCallTable slots enum has " + slotNames.size()
                        + " constant(s) but @BPFMapDefinition(maxEntries=" + maxEntries
                        + ") disagrees — set maxEntries = " + slotNames.size(), vf);
                continue;
            }
        }

        tables.put(fieldName, new TailCallTableInfo(
                fieldName,
                slotEnum.getQualifiedName().toString(),
                slotNames,
                new java.util.ArrayList<>()));
    }

    // 2. Match every @TailCallSlot method against the discovered tables.
    boolean multipleTables = tables.size() > 1;
    for (var enc : outerElement.getEnclosedElements()) {
        if (enc.getKind() != ElementKind.METHOD) continue;
        ExecutableElement me = (ExecutableElement) enc;
        var slotAnn = getAnnotationMirror(me, TAIL_CALL_SLOT);
        if (slotAnn.isEmpty()) continue;

        String slotConstant = getAnnotationValue(slotAnn.get(), "value", "");
        String requestedTable = getAnnotationValue(slotAnn.get(), "table", "");

        TailCallTableInfo target;
        if (!requestedTable.isEmpty()) {
            target = tables.get(requestedTable);
            if (target == null) {
                messager.printError("@TailCallSlot(table=\"" + requestedTable
                        + "\") — no @BPFTailCallTable field with that name. "
                        + "Known tables: " + tables.keySet(), me);
                continue;
            }
        } else if (tables.size() == 1) {
            target = tables.values().iterator().next();
        } else if (multipleTables) {
            messager.printError("@TailCallSlot without table=\"...\" but this class declares "
                    + tables.size() + " @BPFTailCallTable fields: " + tables.keySet()
                    + " — disambiguate with table=\"<fieldName>\"", me);
            continue;
        } else {
            messager.printError("@TailCallSlot on method '" + me.getSimpleName()
                    + "' but no @BPFTailCallTable field found in this class", me);
            continue;
        }

        int ordinal = target.slotNames().indexOf(slotConstant);
        if (ordinal < 0) {
            messager.printError("@TailCallSlot(\"" + slotConstant
                    + "\") — no such constant in enum " + target.slotEnumFqn()
                    + ". Known: " + target.slotNames(), me);
            continue;
        }

        target.registrations().add(new TailCallTableInfo.Registration(
                me.getSimpleName().toString(), slotConstant, ordinal));
    }

    return List.copyOf(tables.values());
}
```

- [ ] **Step 3: Wire the new discovery into `TypeProcessorResult`** (around line 224-297 where `mapDefinitions` is threaded through)

Add `List<TailCallTableInfo> tailCallTables` as a parameter of the result record, update all constructor overloads accordingly, and add a call site:

```java
// inside process(TypeElement outerTypeElement)  — right after
//   var mapDefinitions = processDefinedMaps(...);   (line 292)
var tailCallTables = processTailCallTables(outerTypeElement, mapDefinitions);
```

Add `tailCallTables` as the last field of the `TypeProcessorResult` record and pass it through to the constructor call at line 331 (where the result is built).

- [ ] **Step 4: Write failing compile-error assertions in `TailCallTableCompileErrorTest`** (append to the class from Task 1)

```java
    // ── real processor diagnostic tests ────────────────────────────────────

    private static final String PKG = "tail_call_test";

    private static javax.annotation.processing.Processor newProcessor() {
        return new me.bechberger.ebpf.bpf.processor.Processor();
    }

    private static InMemoryJavaCompiler.Source bpfClass(String simpleName, String body) {
        return new InMemoryJavaCompiler.Source(PKG + "." + simpleName,
                "package " + PKG + ";\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class " + simpleName + " extends BPFProgram {\n"
                        + "  public enum Slot { A, B, C }\n"
                        + body
                        + "\n}\n");
    }

    @Test
    public void errorWhenTableWithoutMapDefinition() {
        var src = bpfClass("T1",
                "@BPFTailCallTable(slots = Slot.class) BPFProgArray t;");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("missing @BPFMapDefinition must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@BPFTailCallTable requires @BPFMapDefinition", "t");
    }

    @Test
    public void errorWhenMaxEntriesMismatch() {
        var src = bpfClass("T2",
                "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 5) BPFProgArray t;");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("maxEntries mismatch must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "3 constant", "maxEntries=5", "set maxEntries = 3");
    }

    @Test
    public void errorWhenSlotConstantUnknown() {
        var src = bpfClass("T3",
                "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 3) BPFProgArray t;\n"
              + "@BPFFunction(section = \"xdp\")\n"
              + "@TailCallSlot(\"Z\")\n"
              + "public int slotZ() { return 0; }");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("unknown slot must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@TailCallSlot(\"Z\")", "no such constant", "[A, B, C]");
    }

    @Test
    public void errorWhenAnnotationOnNonProgArrayField() {
        var src = bpfClass("T4",
                "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 3) BPFHashMap<Integer, Long> t;");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("wrong map type must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "@BPFTailCallTable only applies to BPFProgArray",
                "BPFHashMap");
    }

    @Test
    public void errorWhenAmbiguousTable() {
        var src = bpfClass("T5",
                "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 3) BPFProgArray t1;\n"
              + "@BPFTailCallTable(slots = Slot.class)"
              + "@BPFMapDefinition(maxEntries = 3) BPFProgArray t2;\n"
              + "@BPFFunction(section = \"xdp\")\n"
              + "@TailCallSlot(\"A\")\n"
              + "public int a() { return 0; }");
        var res = InMemoryJavaCompiler.compile(java.util.List.of(src), newProcessor())
                .requireFailure("ambiguous must fail");
        DiagnosticAssert.assertContainsAll(res.diagnostics(),
                "declares 2 @BPFTailCallTable fields", "disambiguate", "t1", "t2");
    }
```

- [ ] **Step 5: Run the failing tests on thinkstation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-compiler-plugin-test -am -Dtest=TailCallTableCompileErrorTest test'`
Expected: 5 new tests FAIL (processor doesn't invoke `processTailCallTables` yet from the compilation pipeline in this branch — but the discovery method exists; `TypeProcessorResult` threading is what wires it in).

- [ ] **Step 6: Rebuild the processor JAR + rerun tests**

Because `bpf-processor` is a compile-time dependency, rebuild it:

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-processor -am -DskipTests install && ./mvnw -pl bpf-compiler-plugin-test -am -Dtest=TailCallTableCompileErrorTest test'`
Expected: 5 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TailCallTableInfo.java \
        bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java \
        bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCompileErrorTest.java
git commit -m "Processor: discover and validate @BPFTailCallTable annotations

Add processTailCallTables in TypeProcessor plus TailCallTableInfo record.
Emits diagnostics for non-BPFProgArray fields, missing @BPFMapDefinition,
maxEntries mismatch, unknown slot constants, and ambiguous tables."
```

---

### Task 3: Codegen — emit `register(...)` in the generated constructor

Consume `tailCallTables()` from `TypeProcessorResult` in `Processor.java` and append `<fieldName>.register(<ordinal>, getProgramByName("<methodName>"))` statements right after existing map initializer statements.

**Files:**
- Modify: `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/Processor.java`
- Create: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCodegenTest.java`

- [ ] **Step 1: Write the failing codegen test**

```java
package me.bechberger.ebpf.compiler;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verify the annotation processor emits the expected register(...) calls
 * into the generated Impl.java. We inspect the emitted source text (not
 * bytecode) because it is stable and easy to read.
 */
public class TailCallTableCodegenTest {

    @Test
    public void generatedImplContainsRegisterCallsForEachSlot() {
        var src = new InMemoryJavaCompiler.Source("tct.Prog",
                "package tct;\n"
                        + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                        + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                        + "import me.bechberger.ebpf.bpf.map.*;\n"
                        + "@BPF(license = \"GPL\")\n"
                        + "public abstract class Prog extends BPFProgram {\n"
                        + "  public enum Slot { PARSE_ETH, PARSE_IP, COUNT }\n"
                        + "  @BPFTailCallTable(slots = Slot.class)\n"
                        + "  @BPFMapDefinition(maxEntries = 3)\n"
                        + "  BPFProgArray dispatch;\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"PARSE_ETH\")\n"
                        + "  public int parseEthImpl() { return 0; }\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"PARSE_IP\")\n"
                        + "  public int parseIpImpl() { return 0; }\n"
                        + "  @BPFFunction(section = \"xdp\") @TailCallSlot(\"COUNT\")\n"
                        + "  public int countImpl() { return 0; }\n"
                        + "}\n");
        var res = InMemoryJavaCompiler.compile(List.of(src),
                new me.bechberger.ebpf.bpf.processor.Processor())
                .requireSuccess("processor should accept a valid @BPFTailCallTable");

        String generated = res.generatedSource("tct.ProgImpl")
                .orElseThrow(() -> new AssertionError("no ProgImpl emitted"));
        // register calls should appear in the constructor.
        assertTrue(generated.contains("dispatch.register(0, getProgramByName(\"parseEthImpl\"))"),
                "missing register(0, parseEthImpl) in:\n" + generated);
        assertTrue(generated.contains("dispatch.register(1, getProgramByName(\"parseIpImpl\"))"),
                "missing register(1, parseIpImpl) in:\n" + generated);
        assertTrue(generated.contains("dispatch.register(2, getProgramByName(\"countImpl\"))"),
                "missing register(2, countImpl) in:\n" + generated);
    }
}
```

If `InMemoryJavaCompiler.Result` does not yet expose `generatedSource(String)`, add it as part of this step:

```java
// InMemoryJavaCompiler.java – Result record helper
public java.util.Optional<String> generatedSource(String fqcn) {
    return sources().stream()
            .filter(s -> s.className().equals(fqcn))
            .map(Source::content)
            .findFirst();
}
```

Read the existing `InMemoryJavaCompiler.java` first to see whether the helper is needed (search for `generatedSource`).

- [ ] **Step 2: Run the failing test on thinkstation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-compiler-plugin-test -am -Dtest=TailCallTableCodegenTest test'`
Expected: FAIL — "no `dispatch.register(...)` in emitted source".

- [ ] **Step 3: Emit the `register(...)` statements in `Processor.java`**

Around line 407 in `Processor.java`, after the loop:

```java
code.tp.mapDefinitions().forEach(m -> {
    constructor.addStatement("$L", m.javaFieldInitializer());
});
```

append:

```java
// Auto-register @BPFTailCallTable slots. Emits, for each table:
//   <fieldName>.register(<ordinal>, getProgramByName("<methodName>"));
for (var table : code.tp.tailCallTables()) {
    for (var reg : table.registrations()) {
        constructor.addStatement(
                "$L.register($L, getProgramByName($S))",
                table.fieldName(), reg.ordinal(), reg.methodName());
    }
}
```

- [ ] **Step 4: Rebuild bpf-processor and rerun the test**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-processor -am -DskipTests install && ./mvnw -pl bpf-compiler-plugin-test -am -Dtest=TailCallTableCodegenTest test'`
Expected: PASS.

- [ ] **Step 5: Rerun the whole compiler-plugin-test module to catch regressions**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-compiler-plugin-test -am test'`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/Processor.java \
        bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/TailCallTableCodegenTest.java \
        bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/compiler/InMemoryJavaCompiler.java
git commit -m "Processor: emit register(ordinal, getProgramByName(name)) for tail-call slots

For every @BPFTailCallTable field, append register() statements to the
generated ProgramImpl constructor — one per matching @TailCallSlot method.
Slots are populated automatically at load time."
```

---

### Task 4: `BPFProgArray.replaceSlot(int, ProgramHandle)` freplace hot-swap

Add a runtime method that replaces the program at a slot via libbpf's `bpf_program__attach_freplace`. The API is: (a) load a new `EXT`-type program pointing at the target program in `getProgramByName`, (b) attach freplace which pins it and replaces the slot's entrypoint. Feature-gate on `Features.hasProgramType(EXT)`.

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java`
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/map/BPFProgArrayReplaceSlotUnitTest.java` (JVM-only: feature-gate + argument-validation coverage)

- [ ] **Step 1: Write the failing unit test**

```java
package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.map.BPFMap.FileDescriptor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JVM-only sanity coverage of {@link BPFProgArray#replaceSlot}. Does not
 * hit the kernel — kernel-side attachment is covered by
 * {@code bpf/src/test/java/me/bechberger/ebpf/bpf/TailCallReplaceSlotTest.java}.
 */
public class BPFProgArrayReplaceSlotUnitTest {

    @Test
    public void replaceSlotRejectsOutOfBounds() {
        // A dummy fd (-1) is fine — bounds check runs before syscall.
        BPFProgArray arr = new BPFProgArray(new FileDescriptor(-1), 2);
        assertThrows(BPFError.class, () -> arr.replaceSlot(99, null),
                "slot 99 with maxEntries=2 must throw");
        assertThrows(BPFError.class, () -> arr.replaceSlot(-1, null),
                "slot -1 must throw");
    }

    @Test
    public void replaceSlotRejectsNullHandle() {
        BPFProgArray arr = new BPFProgArray(new FileDescriptor(-1), 2);
        assertThrows(BPFError.class, () -> arr.replaceSlot(0, null),
                "null handle must throw");
    }
}
```

- [ ] **Step 2: Run the failing test on thinkstation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf -am -Dtest=BPFProgArrayReplaceSlotUnitTest test'`
Expected: FAIL — `replaceSlot` does not exist.

- [ ] **Step 3: Add the `replaceSlot` method to `BPFProgArray.java`**

Insert at end of the class body:

```java
    /**
     * Hot-swap the program at {@code slot} for {@code newHandle} using libbpf's
     * {@code freplace} facility (kernel ≥ 5.10, requires {@link
     * me.bechberger.ebpf.bpf.features.BPFProgramType#EXT}). The new program's
     * BPF program type must be {@code BPF_PROG_TYPE_EXT}; typically it is
     * loaded via {@code SEC("freplace/<target>")}.
     *
     * <p>The freplace mechanism transparently redirects execution; the old
     * program remains loaded but is no longer reachable through this slot.
     * The returned link keeps the freplace alive — closing it restores the
     * original slot binding.
     *
     * @param slot      slot index (0 ≤ slot &lt; maxEntries)
     * @param newHandle handle of an {@code EXT}-type program in the same
     *                  {@code BPFProgram} object
     * @return a link owning the freplace attachment
     * @throws BPFError if the kernel lacks {@code BPF_PROG_TYPE_EXT}, the slot
     *                  is out of range, {@code newHandle} is null, or the
     *                  {@code bpf_program__attach_freplace} syscall fails
     */
    public me.bechberger.ebpf.bpf.BPFLink replaceSlot(int slot,
                                                     BPFProgram.ProgramHandle newHandle) {
        if (slot < 0 || slot >= maxEntries) {
            throw new BPFError("Program slot " + slot + " out of bounds [0, "
                    + maxEntries + ")", -1);
        }
        if (newHandle == null) {
            throw new BPFError("replaceSlot: newHandle is null", -1);
        }
        if (!me.bechberger.ebpf.bpf.features.Features.hasProgramType(
                me.bechberger.ebpf.bpf.features.BPFProgramType.EXT)) {
            throw new BPFError("freplace hot-swap requires BPF_PROG_TYPE_EXT "
                    + "(kernel ≥ 5.10) — not supported on this kernel", -1);
        }
        // libbpf: struct bpf_link *bpf_program__attach_freplace(
        //             struct bpf_program *prog, int target_fd, const char *attach_func_name);
        // We swap the ENTIRE slot binding: target_fd is the prog-array fd,
        // attach_func_name is null (libbpf resolves via the EXT program's
        // set_attach_target).
        var arena = java.lang.foreign.Arena.ofConfined();
        try {
            java.lang.foreign.MemorySegment nameSeg =
                    java.lang.foreign.MemorySegment.NULL;
            java.lang.foreign.MemorySegment linkPtr =
                    me.bechberger.ebpf.bpf.raw.Lib.bpf_program__attach_freplace(
                            newHandle.prog(), fd.fd(), nameSeg);
            if (linkPtr == null || linkPtr.address() == 0) {
                throw new BPFError("bpf_program__attach_freplace failed for slot "
                        + slot, -1);
            }
            return new me.bechberger.ebpf.bpf.BPFLink(linkPtr);
        } finally {
            arena.close();
        }
    }
```

If `Lib.bpf_program__attach_freplace` is not present in the generated `Lib.java`, extend `rawbpf` to re-run `jextract` including the symbol. Symbol availability check:

Run: `ssh thinkstation 'nm -D /usr/lib/x86_64-linux-gnu/libbpf.so | grep bpf_program__attach_freplace'`
Expected: one `T` entry.

If the symbol is missing from `Lib.java`, add it via `HandlerWithErrno` in `BPFProgArray` directly, mirroring the pattern used for `bpf_program__attach` in `BPFProgram.java` (line 1164):

```java
    private static final me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno<
            java.lang.foreign.MemorySegment> BPF_PROGRAM__ATTACH_FREPLACE =
            new me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno<>(
                    "bpf_program__attach_freplace",
                    java.lang.foreign.FunctionDescriptor.of(
                            me.bechberger.ebpf.shared.PanamaUtil.POINTER,
                            me.bechberger.ebpf.shared.PanamaUtil.POINTER,
                            java.lang.foreign.ValueLayout.JAVA_INT,
                            me.bechberger.ebpf.shared.PanamaUtil.POINTER));
```

and replace the raw call with `BPF_PROGRAM__ATTACH_FREPLACE.call(newHandle.prog(), fd.fd(), nameSeg)`.

- [ ] **Step 4: Rebuild the bpf module and rerun the test**

The `bpf` jar-with-dependencies bundles the compiler plugin. Full rebuild:

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-processor,bpf-compiler-plugin,bpf -am -DskipTests install && ./mvnw -pl bpf -Dtest=BPFProgArrayReplaceSlotUnitTest test'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/map/BPFProgArrayReplaceSlotUnitTest.java
git commit -m "BPFProgArray: add replaceSlot() freplace hot-swap

Wraps libbpf's bpf_program__attach_freplace to hot-swap a slot's target
program without unloading. Feature-gated on BPF_PROG_TYPE_EXT (kernel
5.10+); JVM-only tests cover bounds, null, and feature-gate paths."
```

---

### Task 5: `HelloTailCall` XDP sample

A profiler-style XDP tail-call chain: `parseEth -> parseIp -> count`, all wired via `@BPFTailCallTable` and `@TailCallSlot`. The user runs the sample, sends `ping -c 5 127.0.0.1`, and observes packet counts by slot.

**Files:**
- Create: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloTailCall.java`

- [ ] **Step 1: Write the sample source**

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFTailCallTable;
import me.bechberger.ebpf.annotations.bpf.TailCallSlot;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.bpf.map.BPFProgArray;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

/**
 * A 3-stage XDP tail-call chain wired via {@link BPFTailCallTable} and
 * {@link TailCallSlot}. Each stage is a sub-program; the entry point
 * dispatches to the first stage.
 *
 * <p>Stages:
 * <ol>
 *   <li>{@link Slot#PARSE_ETH} — bumps {@code parseEthCalls}, tail-calls PARSE_IP.</li>
 *   <li>{@link Slot#PARSE_IP} — bumps {@code parseIpCalls}, tail-calls COUNT.</li>
 *   <li>{@link Slot#COUNT}   — bumps {@code countCalls} and returns XDP_PASS.</li>
 * </ol>
 *
 * <p>Slot registration is emitted automatically by the annotation processor —
 * no manual {@code progs.register(...)} calls in {@code main}.
 *
 * <p>Usage:
 * <pre>
 *   sudo ./run.sh HelloTailCall
 *   # in another shell:
 *   ping -c 5 127.0.0.1
 * </pre>
 */
@BPF(license = "GPL")
public abstract class HelloTailCall extends BPFProgram implements XDPHook {

    public enum Slot { PARSE_ETH, PARSE_IP, COUNT }

    @BPFTailCallTable(slots = Slot.class)
    @BPFMapDefinition(maxEntries = 3)
    BPFProgArray dispatch;

    final GlobalVariable<@Unsigned Integer> parseEthCalls = new GlobalVariable<>(0);
    final GlobalVariable<@Unsigned Integer> parseIpCalls  = new GlobalVariable<>(0);
    final GlobalVariable<@Unsigned Integer> countCalls    = new GlobalVariable<>(0);

    @BPFFunction(section = "xdp")
    @TailCallSlot("PARSE_ETH")
    public xdp_action parseEth(Ptr<xdp_md> ctx) {
        parseEthCalls.set(parseEthCalls.get() + 1);
        dispatch.tailCall(ctx, Slot.PARSE_IP.ordinal());
        return xdp_action.XDP_PASS; // unreachable — tailCall never returns
    }

    @BPFFunction(section = "xdp")
    @TailCallSlot("PARSE_IP")
    public xdp_action parseIp(Ptr<xdp_md> ctx) {
        parseIpCalls.set(parseIpCalls.get() + 1);
        dispatch.tailCall(ctx, Slot.COUNT.ordinal());
        return xdp_action.XDP_PASS;
    }

    @BPFFunction(section = "xdp")
    @TailCallSlot("COUNT")
    public xdp_action count(Ptr<xdp_md> ctx) {
        countCalls.set(countCalls.get() + 1);
        return xdp_action.XDP_PASS;
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        dispatch.tailCall(ctx, Slot.PARSE_ETH.ordinal());
        return xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (HelloTailCall program = BPFProgram.load(HelloTailCall.class)) {
            // No manual register(...) calls — the processor did it in the ctor.
            program.xdpAttach();
            for (int i = 0; i < 30; i++) {
                System.out.printf("parseEth=%d parseIp=%d count=%d%n",
                        program.parseEthCalls.get(),
                        program.parseIpCalls.get(),
                        program.countCalls.get());
                Thread.sleep(1000);
            }
        }
    }
}
```

- [ ] **Step 2: Build the samples module on thinkstation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-processor,bpf-compiler-plugin,bpf -am -DskipTests install && ./mvnw -pl bpf-samples -am -DskipTests compile'`
Expected: BUILD SUCCESS. `bpf-samples/target/generated-sources/annotations/me/bechberger/ebpf/samples/HelloTailCallImpl.java` should exist and contain three `dispatch.register(...)` lines.

- [ ] **Step 3: Verify the generated Impl contains the expected registrations**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && grep -c "dispatch.register" bpf-samples/target/generated-sources/annotations/me/bechberger/ebpf/samples/HelloTailCallImpl.java'`
Expected: `3`.

- [ ] **Step 4: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloTailCall.java
git commit -m "Sample: HelloTailCall XDP tail-call chain via @BPFTailCallTable

3-stage tail-call chain (parseEth -> parseIp -> count) driven purely by
the annotation surface: the enum Slot lists the slots, @TailCallSlot binds
each method, and the processor emits the register() calls into ctor."
```

---

### Task 6: vng-verified smoke test for `HelloTailCall`

Real-kernel test: load `HelloTailCall`, force loopback traffic, assert each stage fires ≥ N times.

**Files:**
- Create: `bpf-samples/src/test/java/me/bechberger/ebpf/samples/HelloTailCallSmokeTest.java`

- [ ] **Step 1: Write the failing test**

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.NetworkUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real-kernel smoke test for the {@link HelloTailCall} tail-call chain.
 *
 * <p>Loads the sample, attaches XDP to the loopback interface, blasts UDP
 * packets at itself, and asserts every slot ran ≥ 5 times. Any missing
 * slot means the auto-registration codegen (Task 3) did not run.
 */
public class HelloTailCallSmokeTest {

    @Test
    @Timeout(30)
    public void tailCallChainAdvancesAllThreeSlots() throws Exception {
        try (HelloTailCall program = BPFProgram.load(HelloTailCall.class)) {
            int loIndex = NetworkUtil.getNetworkInterfaceIndexes(true).stream()
                    .findFirst().orElseThrow();
            program.xdpAttach(loIndex);

            blastLoopbackUdp(50);

            long deadline = System.currentTimeMillis() + 5000;
            while (System.currentTimeMillis() < deadline
                    && program.countCalls.get() < 5) {
                Thread.sleep(50);
            }

            int e = program.parseEthCalls.get();
            int i = program.parseIpCalls.get();
            int c = program.countCalls.get();
            assertTrue(e >= 5, "parseEth < 5: " + e);
            assertTrue(i >= 5, "parseIp < 5: " + i);
            assertTrue(c >= 5, "count < 5: " + c);
            // Chain invariant — each stage is bounded above by the previous.
            assertTrue(e >= i, "parseEth (" + e + ") < parseIp (" + i + ")");
            assertTrue(i >= c, "parseIp (" + i + ") < count (" + c + ")");
        }
    }

    /** Sends {@code count} tiny UDP packets to 127.0.0.1:1 (discard) to drive XDP. */
    private static void blastLoopbackUdp(int count) throws IOException {
        try (DatagramSocket sock = new DatagramSocket()) {
            byte[] payload = new byte[8];
            InetAddress lo = InetAddress.getByName("127.0.0.1");
            for (int i = 0; i < count; i++) {
                sock.send(new DatagramPacket(payload, payload.length, lo, 1));
            }
        }
    }
}
```

- [ ] **Step 2: Rsync mac->thinkstation**

Run:
```
rsync -av --delete \
  --exclude .git --exclude 'target/' --exclude '*.png' \
  --exclude .playwright-mcp --exclude .claude \
  /Users/i560383_1/code/experiments/hello-ebpf/ \
  thinkstation:/home/i560383/code/experiments/hello-ebpf/
```

- [ ] **Step 3: Rebuild plugin+bpf under sudo m2** (smoke test runs under sudo/vng which uses `/root/.m2`)

Run:
```
ssh thinkstation 'echo Ilikemycat | sudo -S HOME=/root JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn /home/i560383/code/experiments/hello-ebpf/mvnw -f /home/i560383/code/experiments/hello-ebpf/pom.xml -pl bpf-processor,bpf-compiler-plugin,bpf,bpf-samples -am -DskipTests install'
```
Also mirror to user m2:
```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-processor,bpf-compiler-plugin,bpf,bpf-samples -am -DskipTests install'
```

- [ ] **Step 4: Run under vng**

Run:
```
ssh thinkstation "bash -lc 'mkdir -p /tmp/vng-test-logs && cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl bpf-samples -Dtest=HelloTailCallSmokeTest test' 2>&1 | tee /tmp/vng-test-logs/HelloTailCallSmokeTest.log"
```
Expected: 1 test passes.

If it fails: cat `/tmp/vng-test-logs/HelloTailCallSmokeTest.log` and inspect. Common failures — kernel too old (bump vmlinuz path), or `progs.register` not emitted (rebuild `bpf` after touching processor: the bpf jar-with-dependencies bundles the plugin).

- [ ] **Step 5: Commit**

```bash
git add bpf-samples/src/test/java/me/bechberger/ebpf/samples/HelloTailCallSmokeTest.java
git commit -m "Real-kernel test: HelloTailCall tail-call chain smoke test

Drives loopback UDP traffic and asserts each of the three @TailCallSlot
methods (parseEth/parseIp/count) fires at least 5 times, plus the chain
invariant parseEth >= parseIp >= count. vng-only."
```

---

### Task 7: vng-verified freplace hot-swap test

Real-kernel test for `replaceSlot`: load a program that tail-calls slot A, verify slot A ran, freplace A with B, drive more traffic, verify B ran.

**Files:**
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/TailCallReplaceSlotTest.java`

- [ ] **Step 1: Write the failing test**

```java
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFProgArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Real-kernel test for {@link BPFProgArray#replaceSlot}. Slot 0 initially
 * points at {@code countA}; after {@code replaceSlot(0, countB)} more traffic
 * is routed through {@code countB}. Both counters must have advanced by test
 * end.
 */
public class TailCallReplaceSlotTest {

    @BPF(license = "GPL")
    public abstract static class Prog extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1)
        BPFProgArray progs;

        final GlobalVariable<Integer> callsA = new GlobalVariable<>(0);
        final GlobalVariable<Integer> callsB = new GlobalVariable<>(0);

        @BPFFunction(section = "kprobe/do_sys_openat2")
        int countA(Ptr<PtDefinitions.pt_regs> ctx) {
            callsA.set(callsA.get() + 1);
            return 0;
        }

        // Loaded as EXT program: replaces countA on demand.
        @BPFFunction(section = "freplace/countA")
        int countB(Ptr<PtDefinitions.pt_regs> ctx) {
            callsB.set(callsB.get() + 1);
            return 0;
        }

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            progs.tailCall(ctx, 0);
            return 0;
        }
    }

    @Test
    @Timeout(30)
    public void replaceSlotHotSwapsTarget() throws InterruptedException {
        try (Prog p = BPFProgram.load(Prog.class)) {
            p.progs.register(0, p.getProgramByName("countA"));
            p.autoAttachPrograms();

            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);
            int aBefore = p.callsA.get();
            int bBefore = p.callsB.get();
            assertTrue(aBefore >= 3, "countA should have fired: " + aBefore);
            assertTrue(bBefore == 0, "countB must be 0 before replaceSlot: " + bBefore);

            // Hot-swap
            var link = p.progs.replaceSlot(0, p.getProgramByName("countB"));
            assertTrue(link != null);

            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);
            int aAfter = p.callsA.get();
            int bAfter = p.callsB.get();
            assertTrue(bAfter >= 3, "countB should have fired after swap: " + bAfter);
            // countA MAY still tick if the kernel takes a moment to route through
            // the ext program, so we only assert countB advanced strictly.
            assertTrue(bAfter > bBefore, "callsB must have advanced: "
                    + bBefore + " -> " + bAfter);
        }
    }
}
```

- [ ] **Step 2: Rsync + rebuild + run under vng**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-processor,bpf-compiler-plugin,bpf -am -DskipTests install'
ssh thinkstation 'echo Ilikemycat | sudo -S HOME=/root JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn /home/i560383/code/experiments/hello-ebpf/mvnw -f /home/i560383/code/experiments/hello-ebpf/pom.xml -pl bpf-processor,bpf-compiler-plugin,bpf -am -DskipTests install'
ssh thinkstation "bash -lc 'mkdir -p /tmp/vng-test-logs && cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl bpf -Dtest=TailCallReplaceSlotTest test' 2>&1 | tee /tmp/vng-test-logs/TailCallReplaceSlotTest.log"
```
Expected: 1 test passes.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/TailCallReplaceSlotTest.java
git commit -m "Real-kernel test: BPFProgArray.replaceSlot freplace hot-swap

Loads a kprobe/tail-call program whose slot 0 is countA, verifies countA
fires, calls replaceSlot(0, countB) using a SEC(\"freplace/countA\")
program, then verifies countB fires afterwards. vng-only, requires
BPF_PROG_TYPE_EXT."
```

---

### Task 8: Docs — `docs/tail-calls.md` + README link

**Files:**
- Create: `docs/tail-calls.md`
- Modify: `README.md`

- [ ] **Step 1: Write `docs/tail-calls.md`**

```markdown
# Tail calls in hello-ebpf

BPF programs cannot recurse or exceed the verifier's instruction budget, so
long dispatch chains are split into stages connected by **tail calls**:
`bpf_tail_call(ctx, &prog_array, slot)` transfers execution to the program
at `prog_array[slot]` and never returns. hello-ebpf gives you three surfaces
for this pattern:

1. **Raw `BPFProgArray`** — the primitive. `progs.register(slot, handle)`
   plus `progs.tailCall(ctx, slot)`. See
   [`TailCallDemo.java`](../bpf-samples/src/main/java/me/bechberger/ebpf/samples/TailCallDemo.java).
2. **`@BPFTailCallTable`** — auto-registers slots from an enum. This page.
3. **`BPFProgArray.replaceSlot`** — freplace-based hot-swap of a live slot.

## `@BPFTailCallTable` in 60 seconds

```java
@BPF(license = "GPL")
public abstract class HelloTailCall extends BPFProgram implements XDPHook {

    public enum Slot { PARSE_ETH, PARSE_IP, COUNT }

    @BPFTailCallTable(slots = Slot.class)
    @BPFMapDefinition(maxEntries = 3)
    BPFProgArray dispatch;

    @BPFFunction(section = "xdp")
    @TailCallSlot("PARSE_ETH")
    public xdp_action parseEth(Ptr<xdp_md> ctx) { /* ... */ }

    @BPFFunction(section = "xdp")
    @TailCallSlot("PARSE_IP")
    public xdp_action parseIp(Ptr<xdp_md> ctx) { /* ... */ }

    @BPFFunction(section = "xdp")
    @TailCallSlot("COUNT")
    public xdp_action count(Ptr<xdp_md> ctx) { /* ... */ }
}
```

The annotation processor emits three lines into the generated
`HelloTailCallImpl` constructor, so `main()` needs no manual
`register(...)` calls:

```java
dispatch.register(0, getProgramByName("parseEth"));
dispatch.register(1, getProgramByName("parseIp"));
dispatch.register(2, getProgramByName("count"));
```

## Rules

- `maxEntries` on the sibling `@BPFMapDefinition` must equal the enum
  constant count.
- `@TailCallSlot("X")` — `X` must be the exact name of a constant of the
  target table's `slots()` enum.
- If a class declares more than one `@BPFTailCallTable`, disambiguate with
  `@TailCallSlot(value="A", table="<fieldName>")`.
- Slot index = `Enum.ordinal()`. Reorder the enum only if you understand
  every downstream `.ordinal()` reference.

## Compile-time errors (excerpt)

- Non-`BPFProgArray` field: `@BPFTailCallTable only applies to BPFProgArray fields`
- Missing sibling: `@BPFTailCallTable requires @BPFMapDefinition on the same field`
- Mismatch: `slots enum has N constant(s) but @BPFMapDefinition(maxEntries=M) disagrees`
- Bad name: `@TailCallSlot("Z") — no such constant in enum <FQN>. Known: [A, B, C]`

## Hot-swap via freplace

```java
var link = program.dispatch.replaceSlot(0, program.getProgramByName("newParseEth"));
// ... traffic now flows through newParseEth via BPF_PROG_TYPE_EXT ...
link.close(); // restores the original slot binding
```

Requires kernel ≥ 5.10 and `BPF_PROG_TYPE_EXT` support — guarded by
`Features.hasProgramType(BPFProgramType.EXT)`.

The replacement program must be declared with
`SEC("freplace/<target-name>")`, e.g.:

```java
@BPFFunction(section = "freplace/parseEth")
public xdp_action newParseEth(Ptr<xdp_md> ctx) { /* ... */ }
```

## See also

- [`HelloTailCall.java`](../bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloTailCall.java) — canonical sample.
- [`BPFProgArray.java`](../bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java) — the underlying primitive.
- Feature detection: [`Features`](../bpf/src/main/java/me/bechberger/ebpf/bpf/features/Features.java).
```

- [ ] **Step 2: Add a bullet under Features in `README.md`**

Locate the Features section (line ~60) and insert after the existing struct_ops bullet (line 63):

```
- **Tail-call tables** — declare an enum, mark methods with `@TailCallSlot`, and slots auto-register at load; freplace hot-swap included. [See docs/tail-calls.md](docs/tail-calls.md).
```

- [ ] **Step 3: Commit**

```bash
git add docs/tail-calls.md README.md
git commit -m "Docs: tail-calls.md and README link under Features

One-page walkthrough of @BPFTailCallTable, @TailCallSlot, and the
freplace hot-swap escape hatch, with pointers to the sample and primitive."
```

---

### Task 9: Verification sweep + final polish

Rebuild everything from clean, run the full compiler-plugin-test module, and run both vng-verified tests end-to-end.

- [ ] **Step 1: Clean build on thinkstation**

Run:
```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw clean install -DskipTests'
```
Expected: BUILD SUCCESS.

- [ ] **Step 2: Full compiler-plugin-test module**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && ./mvnw -pl bpf-compiler-plugin-test -am test'`
Expected: all tests pass (includes 5 new `TailCallTableCompileErrorTest` + 1 `TailCallTableCodegenTest` + all pre-existing).

- [ ] **Step 3: Sudo m2 mirror install**

Run:
```
ssh thinkstation 'echo Ilikemycat | sudo -S HOME=/root JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn /home/i560383/code/experiments/hello-ebpf/mvnw -f /home/i560383/code/experiments/hello-ebpf/pom.xml -pl bpf-processor,bpf-compiler-plugin,bpf,bpf-samples -am -DskipTests install'
```

- [ ] **Step 4: vng — HelloTailCallSmokeTest**

Run:
```
ssh thinkstation "bash -lc 'mkdir -p /tmp/vng-test-logs && cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl bpf-samples -Dtest=HelloTailCallSmokeTest test' 2>&1 | tee /tmp/vng-test-logs/HelloTailCallSmokeTest-final.log"
```
Expected: PASS.

- [ ] **Step 5: vng — TailCallReplaceSlotTest**

Run:
```
ssh thinkstation "bash -lc 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl bpf -Dtest=TailCallReplaceSlotTest test' 2>&1 | tee /tmp/vng-test-logs/TailCallReplaceSlotTest-final.log"
```
Expected: PASS.

- [ ] **Step 6: vng — existing TailCallTest regression check** (verify we did not break the older primitive-style tests)

Run:
```
ssh thinkstation "bash -lc 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl bpf -Dtest=TailCallTest test' 2>&1 | tee /tmp/vng-test-logs/TailCallTest-regression.log"
```
Expected: PASS.

- [ ] **Step 7: Commit final polish** (if any leftover formatting/javadoc from prior tasks needs a tidy-up)

```bash
git status
# If clean, no commit needed.
# Otherwise:
git add <files>
git commit -m "Polish: docs and diagnostics wording

Final tidy after verification sweep — no behaviour changes."
```

---

## Verification (final executor checklist)

Run in order, from mac:

1. `rsync -av --delete --exclude .git --exclude 'target/' --exclude '*.png' --exclude .playwright-mcp --exclude .claude /Users/i560383_1/code/experiments/hello-ebpf/ thinkstation:/home/i560383/code/experiments/hello-ebpf/`
2. `ssh thinkstation './mvnw -pl bpf-processor,bpf-compiler-plugin,bpf,bpf-samples -am -DskipTests install'`
3. `ssh thinkstation 'echo Ilikemycat | sudo -S HOME=/root JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn /home/i560383/code/experiments/hello-ebpf/mvnw -f /home/i560383/code/experiments/hello-ebpf/pom.xml -pl bpf-processor,bpf-compiler-plugin,bpf,bpf-samples -am -DskipTests install'`
4. `ssh thinkstation './mvnw -pl bpf-compiler-plugin-test -am test'`  — expects `TailCallTableCompileErrorTest` (5), `TailCallTableCodegenTest` (1) and every pre-existing test to pass.
5. `ssh thinkstation "bash -lc 'mkdir -p /tmp/vng-test-logs && cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl bpf-samples -Dtest=HelloTailCallSmokeTest test' 2>&1 | tee /tmp/vng-test-logs/HelloTailCallSmokeTest.log"`
6. `ssh thinkstation "bash -lc 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl bpf -Dtest=TailCallReplaceSlotTest test' 2>&1 | tee /tmp/vng-test-logs/TailCallReplaceSlotTest.log"`
7. `ssh thinkstation "bash -lc 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl bpf -Dtest=TailCallTest test' 2>&1 | tee /tmp/vng-test-logs/TailCallTest-regression.log"` — regression on the primitive-style test from before the feature.

**Execution constraints:**
- All builds/tests run on thinkstation. Never build on mac.
- Sudo commands need `HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn` (or `HOME=/root` when installing to the root m2 for vng).
- Pipe sudo password via `echo Ilikemycat | sudo -S <cmd>` — do not rely on interactive prompts.
- vng runner is `/home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl <module> -Dtest=<TestName> test`. Log to `/tmp/vng-test-logs/<class>.log`, not inside the repo — the vng CoW overlay discards in-repo writes.
- After any change to `bpf-processor` or `bpf-compiler-plugin`, rebuild `bpf` too — the `bpf` jar-with-dependencies bundles plugin classes and will otherwise shadow the update.
- rsync excludes: `.git`, `target/`, `*.png`, `.playwright-mcp`, `.claude`. Mac is the authoritative source.
- Kernel floor: 6.14+ (test kernel `/boot/vmlinuz-6.17.0-35-generic`).
- No emojis anywhere.

---
