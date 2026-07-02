# @StructOps Sub-Plan B: Plugin codegen + `StructOpsAttach` runtime + `BPFProgram.load()` wiring

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consume the pure-data foundation from Sub-plan A (`@StructOps`, marker interfaces, JSON layouts) to drive end-to-end BPF program generation and attach for arbitrary struct_ops kinds. After this sub-plan, a class `implements TcpCongestionControl` (added in Sub-plan A) actually produces working C, registers with the kernel's TCP CC list, and detaches on close — smoke-tested with a minimal test class *not yet* backed by a full user-facing sample (that's Sub-plan D's `HelloCubicSample`).

**Architecture:** Reuse the existing plugin machinery rather than inventing new codegen paths. The plugin already knows how to (a) synthesise a `BPFFunction` from an attach-shorthand annotation via `CompilerPlugin.synthesizeBPFFunction`, and (b) wrap a method body with a header template (`BPF_PROG(...)`) via `Translator`. We add a discovery step that walks `@BPF` class interfaces, matches each interface method to a BTF field, and produces a synthesised `BPFFunction` with `section = "<prefix><field>"` and `headerTemplate = "<ret> BPF_PROG($name, <args>)"`. A separate pass emits the `SEC(".struct_ops.link")` struct instance as a synthetic top-level declaration. At runtime, `StructOpsAttach.attachAll(program)` reads a compile-time-generated `StructOpsManifest` and calls `bpf_map__attach_struct_ops` (already wired at `BPFProgram.java:1881`) for each declared instance. `BPFProgram.load()` invokes `attachAll` after `bpf_object__load` and gates each attach on `Features.hasStructOps(...)`.

**Tech Stack:** Java 25, javac plugin API, Panama FFI (existing `HandlerWithErrno` shape), JUnit 5, AssertJ.

**Reference spec:** `docs/superpowers/specs/2026-07-02-struct-ops-design.md` §5.4, §6, §8-9, §11, §19 step 3-4.

**Depends on:** Sub-plan A (`2026-07-02-struct-ops-A-foundation.md`) landed and merged.

---

## File Structure

**New files (compiler plugin):**

- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscovery.java` — walks a `@BPF` class's interfaces, collects `@StructOps`-annotated ones + overridden methods.
- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsValidator.java` — matches overridden methods to BTF fields; emits diagnostics for mismatches.
- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java` — builds synthetic `BPFFunction` proxies + the struct-instance decl for each overridden method / discovered instance.
- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsManifestWriter.java` — emits a companion Java class next to `BPFImpl` that lists each `(kernelName, mapName)` pair.
- Tests under `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/`:
  - `StructOpsDiscoveryTest.java`
  - `StructOpsValidatorTest.java`
  - `StructOpsSynthesizerTest.java`
  - `StructOpsCodegenTest.java` — end-to-end: fixture `@BPF` class → generated `.c` contains expected sections.

**New files (runtime):**

- `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsAttach.java` — the runtime attach walker.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsInfo.java` — public record.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsManifest.java` — SPI: interface the plugin-emitted companion class implements.
- Tests:
  - `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/StructOpsAttachTest.java` — real-kernel: minimal TCP CC.

**Modified files:**

- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java` — hook the discovery + synthesis pipeline into the compilation flow after existing `@BPFFunction` processing.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — call `StructOpsAttach.attachAll(this)` from both `load` paths; store `structOpsInfo` on the instance; add `BPFLoadError.StructOpsAttachFailed`. Add `Features.hasStructOps` gating.

**Decomposition rationale:** `StructOpsDiscovery` and `StructOpsValidator` are separate because discovery is "what interfaces exist" (a pure walk of `TypeElement.getInterfaces()`) while validation is "do the types line up" (BTF cross-check + diagnostic emission). Separating them means the discovery test is a plain reflection test with no BTF dependency, and the validator test can feed synthetic types without a real class. `StructOpsSynthesizer` is separate again because it consumes both outputs and *only* builds proxies — no decision logic. Small, focused files.

---

## Tasks

### Task 1: `StructOpsDiscovery` — walk `@BPF` class interfaces

**Files:**
- Create: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscovery.java`
- Test: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscoveryTest.java`

Given a `@BPF` class element, returns the list of `(interface, overriddenMethods)` where interface is annotated `@StructOps`. Only *directly-implemented* interfaces on the `@BPF` class are considered — the spec is explicit that we do not follow chains (§3, non-goals).

- [ ] **Step 1: Write the failing test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;
import me.bechberger.ebpf.bpf.compiler.testutil.CompilerFixture;

import javax.lang.model.element.TypeElement;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Uses the same in-process javac fixture the other plugin tests use. */
class StructOpsDiscoveryTest {

    @Test
    void findsSingleAnnotatedInterface() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            @BPF
            abstract class MyCC extends BPFProgram implements TcpCongestionControl {
                @Override public int ssthresh(me.bechberger.ebpf.type.Ptr<
                    me.bechberger.ebpf.runtime.NetworkingDefinitions.sock> sk) { return 42; }
                @Override public String name() { return "test_cc"; }
            }
            """;
        var fixture = CompilerFixture.compile("p.MyCC", src);
        TypeElement cls = fixture.getClass("p.MyCC");
        var result = StructOpsDiscovery.discover(cls, fixture.env());
        assertThat(result).hasSize(1);
        var kind = result.get(0);
        assertThat(kind.kernelName()).isEqualTo("tcp_congestion_ops");
        assertThat(kind.overriddenMethods()).extracting("getSimpleName")
                .containsExactlyInAnyOrder("ssthresh", "name");
    }

    @Test
    void classWithNoStructOpsInterfaceReturnsEmpty() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.BPFProgram;
            @BPF abstract class Plain extends BPFProgram {}
            """;
        var fixture = CompilerFixture.compile("p.Plain", src);
        var result = StructOpsDiscovery.discover(fixture.getClass("p.Plain"), fixture.env());
        assertThat(result).isEmpty();
    }

    @Test
    void ignoresIndirectInterface() {
        // A class implements interface X, X extends TcpCongestionControl — we do NOT follow.
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            interface Middle extends TcpCongestionControl {}
            @BPF abstract class Indirect extends BPFProgram implements Middle {}
            """;
        var fixture = CompilerFixture.compile("p.Indirect", src);
        var result = StructOpsDiscovery.discover(fixture.getClass("p.Indirect"), fixture.env());
        // Expected: empty, because Middle isn't @StructOps-annotated (the spec forbids
        // following the chain).  Alternatively the plugin could emit a warning — decide
        // later; the initial behaviour is silently ignore.
        assertThat(result).isEmpty();
    }
}
```

**Note on `CompilerFixture`:** the existing plugin-test module already has a compile fixture — search `bpf-compiler-plugin-test/src/test` for `CompilerPluginTest` or similar; those tests demonstrate the pattern. If a general-purpose `CompilerFixture` doesn't exist as a reusable utility, the implementer should extract one (search for the compilation harness in `CompilerPluginTest` and factor it out into a `testutil/` package). This factoring is a legitimate part of Task 1 and should be included in the commit.

- [ ] **Step 2: Run test — expect FAIL**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test -Dtest=StructOpsDiscoveryTest test 2>&1 | tail -25'
```
Expected: compile failure — `StructOpsDiscovery` missing.

- [ ] **Step 3: Implement**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.annotations.bpf.StructOps;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.ElementFilter;
import java.util.ArrayList;
import java.util.List;

/**
 * Walks a {@code @BPF} class's directly-implemented interfaces and returns
 * one {@link Kind} per interface annotated {@code @StructOps}. Indirect
 * interfaces (an interface that extends a {@code @StructOps} interface
 * without being annotated itself) are silently ignored — the spec is
 * explicit that we do not follow chains.
 */
public final class StructOpsDiscovery {

    private StructOpsDiscovery() {}

    /**
     * @param kernelName        the annotation's {@code value()} — e.g. "tcp_congestion_ops"
     * @param iface             the interface type element
     * @param sectionPrefix     annotation's {@code sectionPrefix()} — e.g. "struct_ops/"
     * @param instanceName      annotation's {@code instanceName()} — empty means use class name
     * @param overriddenMethods the interface methods the concrete class overrode.
     *                          Un-overridden defaults are excluded (kernel accepts NULL for optional slots).
     */
    public record Kind(
            String kernelName,
            TypeElement iface,
            String sectionPrefix,
            String instanceName,
            List<ExecutableElement> overriddenMethods) {}

    public static List<Kind> discover(TypeElement bpfClass, ProcessingEnvironment env) {
        List<Kind> out = new ArrayList<>();
        for (TypeMirror ifMirror : bpfClass.getInterfaces()) {
            if (!(ifMirror instanceof DeclaredType dt)) continue;
            TypeElement iface = (TypeElement) dt.asElement();
            StructOps ann = iface.getAnnotation(StructOps.class);
            if (ann == null) continue;
            List<ExecutableElement> overridden = collectOverriddenMethods(iface, bpfClass, env);
            out.add(new Kind(
                    ann.value(),
                    iface,
                    ann.sectionPrefix(),
                    ann.instanceName(),
                    overridden));
        }
        return out;
    }

    /**
     * Returns the interface methods that the concrete class overrides.
     * A default method is considered overridden if the class declares a
     * method with matching name+erasure and does NOT carry the ABSTRACT
     * modifier.
     */
    private static List<ExecutableElement> collectOverriddenMethods(
            TypeElement iface, TypeElement bpfClass, ProcessingEnvironment env) {
        var elements = env.getElementUtils();
        var types = env.getTypeUtils();
        var declaredIn = ElementFilter.methodsIn(bpfClass.getEnclosedElements());
        List<ExecutableElement> out = new ArrayList<>();
        for (ExecutableElement m : ElementFilter.methodsIn(iface.getEnclosedElements())) {
            if (m.getModifiers().contains(Modifier.STATIC)) continue;
            for (ExecutableElement candidate : declaredIn) {
                if (candidate.getModifiers().contains(Modifier.ABSTRACT)) continue;
                if (!candidate.getSimpleName().contentEquals(m.getSimpleName())) continue;
                if (elements.overrides(candidate, m, bpfClass)) {
                    out.add(m);   // return the INTERFACE method (canonical) — the concrete one is looked up by name in later stages
                    break;
                }
            }
        }
        return out;
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test -Dtest=StructOpsDiscoveryTest test 2>&1 | tail -20'
```
Expected: 3/3 pass.

- [ ] **Step 5: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscovery.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscoveryTest.java
# plus the CompilerFixture extraction if that was needed
git commit -m "feat(plugin): StructOpsDiscovery walks @BPF class interfaces"
```

---

### Task 2: `StructOpsValidator` — BTF field matching + diagnostics

**Files:**
- Create: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsValidator.java`
- Test: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsValidatorTest.java`

Rules from spec §6:
- camelCase → snake_case. `congAvoid` → `cong_avoid`. `hidRawEvent` → `hid_raw_event`. Leading char stays. Numeric suffixes are regular chars (`send2` → `send2`).
- Return type check: Java `void` ↔ BTF `void`; `int`/`long`/`short`/`byte` ↔ BTF integer widths; `Ptr<X>` ↔ `struct X *` (or `X *`); `String` ↔ `char[N]`.
- Arg-count mismatch → error.
- Method-not-in-BTF → error at method site.

- [ ] **Step 1: Write the failing test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;
import me.bechberger.ebpf.bpf.compiler.testutil.CompilerFixture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StructOpsValidatorTest {

    @Test
    void camelToSnake() {
        assertThat(StructOpsValidator.camelToSnake("congAvoid")).isEqualTo("cong_avoid");
        assertThat(StructOpsValidator.camelToSnake("selectCpu")).isEqualTo("select_cpu");
        assertThat(StructOpsValidator.camelToSnake("hidRawEvent")).isEqualTo("hid_raw_event");
        assertThat(StructOpsValidator.camelToSnake("undoCwnd")).isEqualTo("undo_cwnd");
        assertThat(StructOpsValidator.camelToSnake("name")).isEqualTo("name");
        assertThat(StructOpsValidator.camelToSnake("send2")).isEqualTo("send2");
        // Consecutive capitals: rare, but the rule from spec §6.1 point 2:
        assertThat(StructOpsValidator.camelToSnake("acpiInit")).isEqualTo("acpi_init");
    }

    @Test
    void validateHappyPathTcpCong() {
        // Uses the real TcpCongestionControl and a fixture class overriding it correctly.
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.NetworkingDefinitions.sock;
            @BPF abstract class OK extends BPFProgram implements TcpCongestionControl {
                @Override public int ssthresh(Ptr<sock> sk) { return 1; }
                @Override public String name() { return "ok"; }
            }
            """;
        var fixture = CompilerFixture.compile("p.OK", src);
        // Should compile clean.
        assertThat(fixture.errors()).isEmpty();
    }

    @Test
    void wrongReturnTypeDiagnosed() {
        // Override ssthresh with void return — BTF says __u32.
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.NetworkingDefinitions.sock;
            @BPF abstract class Bad extends BPFProgram implements TcpCongestionControl {
                // Java allows return-type covariance for `int` → this won't compile
                // as an @Override with different return.  Use a method whose BTF signature
                // demands a matching return the user gets wrong.
                // Instead, cook a case where the method IS present but the BTF disagrees.
                // Testing done in-process by feeding a hand-crafted layout — see fixture
                // helper `withStubLayout` below.
            }
            """;
        // Direct test with a hand-built layout+methodSymbol pair:
        var stubLayout = new StructOpsLayout("test_ops", "6.14", java.util.List.of(
                new StructOpsLayout.Field("do_thing", "function", "int",
                    java.util.List.of(new StructOpsLayout.Field.Arg("x", "int")))));
        var ex = assertThrows(StructOpsValidator.ValidationException.class,
                () -> StructOpsValidator.validateReturnType(
                    stubLayout.field("do_thing"), "void", "do_thing"));
        assertThat(ex.getMessage())
                .contains("do_thing")
                .contains("return type")
                .contains("void")
                .contains("int");
    }

    @Test
    void argCountMismatchDiagnosed() {
        var layoutField = new StructOpsLayout.Field("f", "function", "void",
                java.util.List.of(
                    new StructOpsLayout.Field.Arg("a", "int"),
                    new StructOpsLayout.Field.Arg("b", "int")));
        var ex = assertThrows(StructOpsValidator.ValidationException.class,
                () -> StructOpsValidator.validateArgCount(layoutField, 1, "f"));
        assertThat(ex.getMessage())
                .contains("expected 2 args, method has 1")
                .contains("'f'");
    }

    @Test
    void unknownMethodDiagnosed() {
        var layout = new StructOpsLayout("tcp_congestion_ops", "5.6", java.util.List.of(
                new StructOpsLayout.Field("ssthresh", "function", "int", java.util.List.of())));
        var ex = assertThrows(StructOpsValidator.ValidationException.class,
                () -> StructOpsValidator.validateFieldExists(layout, "fooBar"));
        assertThat(ex.getMessage())
                .contains("fooBar")
                .contains("no matching field")
                .contains("tcp_congestion_ops");
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

Same command shape as Task 1 step 2 with `-Dtest=StructOpsValidatorTest`.

- [ ] **Step 3: Implement**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

/**
 * Method-to-BTF-field validation for {@code @StructOps} interfaces.
 * Pure functions on top of {@link StructOpsLayout} data; produces
 * {@link ValidationException}s that callers translate to javac diagnostics
 * at the method source position.
 */
public final class StructOpsValidator {

    private StructOpsValidator() {}

    public static final class ValidationException extends RuntimeException {
        public ValidationException(String msg) { super(msg); }
    }

    /** camelCase → snake_case per spec §6.1. */
    public static String camelToSnake(String s) {
        var sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isUpperCase(c)) {
                if (i > 0) sb.append('_');
                sb.append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Throws if the layout has no field with {@code fieldName} (already lowered).
     * Message names the kernel struct so users know what to search.
     */
    public static void validateFieldExists(StructOpsLayout layout, String fieldName) {
        if (!layout.hasField(fieldName)) {
            throw new ValidationException(
                    "method '" + fieldName + "' has no matching field in kernel struct '"
                            + layout.kernelName() + "'");
        }
    }

    /**
     * Compares the BTF return type against a rendered Java return type
     * (the caller lowers Java types to their C equivalent — see
     * {@code StructOpsSynthesizer} for the mapping table).
     */
    public static void validateReturnType(
            StructOpsLayout.Field field, String javaReturnRendered, String fieldName) {
        if (!typesMatch(field.returnType(), javaReturnRendered)) {
            throw new ValidationException(
                    "method '" + fieldName + "' return type '" + javaReturnRendered
                            + "' does not match BTF field '" + fieldName
                            + "' return type '" + field.returnType() + "'");
        }
    }

    public static void validateArgCount(StructOpsLayout.Field field, int javaArgCount, String fieldName) {
        int expected = field.args().size();
        if (javaArgCount != expected) {
            throw new ValidationException(
                    "expected " + expected + " args, method has " + javaArgCount
                            + " for field '" + fieldName + "'");
        }
    }

    public static void validateArgType(
            StructOpsLayout.Field.Arg btfArg, String javaArgRendered,
            int argIndex, String fieldName) {
        if (!typesMatch(btfArg.type(), javaArgRendered)) {
            throw new ValidationException(
                    "method '" + fieldName + "' arg " + argIndex + " (" + btfArg.name()
                            + ") type '" + javaArgRendered + "' does not match BTF type '"
                            + btfArg.type() + "'");
        }
    }

    /**
     * Lightweight type comparison: normalizes whitespace + trailing star spacing,
     * then compares. Bear in mind BTF renders {@code "struct task_struct *"}
     * while the caller renders {@code "struct task_struct *"} the same way,
     * so exact string equality after normalization suffices for the four supported
     * kinds. If a mismatch surfaces in real use, tighten this here rather than
     * silently coercing.
     */
    private static boolean typesMatch(String btfType, String rendered) {
        return normalise(btfType).equals(normalise(rendered));
    }

    private static String normalise(String t) {
        return t.replaceAll("\\s+", " ").replace(" *", "*").trim();
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsValidator.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsValidatorTest.java
git commit -m "feat(plugin): StructOpsValidator with camelToSnake + BTF type checks"
```

---

### Task 3: Java→C type-rendering table

**Files:**
- Create: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/JavaToCTypeRenderer.java`
- Test: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/JavaToCTypeRendererTest.java`

Extract the Java→C mapping into its own class so the validator can render Java signatures for comparison and the synthesizer can render args for the `BPF_PROG(...)` header.

- [ ] **Step 1: Failing test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class JavaToCTypeRendererTest {

    @Test
    void primitives() {
        var r = new JavaToCTypeRenderer();
        assertThat(r.render("void")).isEqualTo("void");
        assertThat(r.render("int")).isEqualTo("int");
        assertThat(r.render("long")).isEqualTo("long");
        // Unsigned annotations translate to the correct u<width>.
        assertThat(r.renderWithAnnotation("int", true)).isEqualTo("__u32");
        assertThat(r.renderWithAnnotation("long", true)).isEqualTo("__u64");
        assertThat(r.renderWithAnnotation("short", true)).isEqualTo("__u16");
        assertThat(r.renderWithAnnotation("byte", true)).isEqualTo("__u8");
        assertThat(r.render("boolean")).isEqualTo("bool");
    }

    @Test
    void ptrGenericsUnwrapToStructPointer() {
        var r = new JavaToCTypeRenderer();
        assertThat(r.render("me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.NetworkingDefinitions.sock>"))
                .isEqualTo("struct sock *");
        assertThat(r.render("me.bechberger.ebpf.type.Ptr<me.bechberger.ebpf.runtime.TaskDefinitions.task_struct>"))
                .isEqualTo("struct task_struct *");
    }

    @Test
    void stringRendersAsCharArrayForDataFields() {
        var r = new JavaToCTypeRenderer();
        // The BTF field's exact type wins for `String` → the renderer just
        // returns "char *" here; the synthesizer uses the BTF field type
        // (`char[16]`) as the emit type in the struct instance.
        assertThat(r.render("java.lang.String")).isEqualTo("char *");
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

- [ ] **Step 3: Implement**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

/**
 * Renders Java type strings (as they appear in erased method signatures)
 * to the C strings the plugin emits in {@code BPF_PROG(...)} headers and
 * compares against BTF field types.
 *
 * <p>Deliberately narrow: covers the primitives, {@code Ptr<X>}, and
 * {@code String}. Other types produce a runtime error — the four supported
 * struct_ops kinds do not use anything else.
 */
public final class JavaToCTypeRenderer {

    public String render(String javaType) {
        return renderWithAnnotation(javaType, false);
    }

    public String renderWithAnnotation(String javaType, boolean unsigned) {
        return switch (javaType) {
            case "void" -> "void";
            case "int"     -> unsigned ? "__u32" : "int";
            case "long"    -> unsigned ? "__u64" : "long";
            case "short"   -> unsigned ? "__u16" : "short";
            case "byte"    -> unsigned ? "__u8"  : "signed char";
            case "boolean" -> "bool";
            case "java.lang.String" -> "char *";
            default -> {
                // Ptr<X>: extract X and render as "struct <X_simple> *"
                if (javaType.startsWith("me.bechberger.ebpf.type.Ptr<")
                        && javaType.endsWith(">")) {
                    String inner = javaType.substring(
                            "me.bechberger.ebpf.type.Ptr<".length(),
                            javaType.length() - 1);
                    // "me.bechberger.ebpf.runtime.NetworkingDefinitions.sock" → "sock"
                    int dot = inner.lastIndexOf('.');
                    String simple = (dot >= 0) ? inner.substring(dot + 1) : inner;
                    yield "struct " + simple + " *";
                }
                throw new IllegalArgumentException("unsupported Java type: " + javaType);
            }
        };
    }
}
```

- [ ] **Step 4: Run test — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/JavaToCTypeRenderer.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/JavaToCTypeRendererTest.java
git commit -m "feat(plugin): JavaToCTypeRenderer for Ptr<X> and primitives"
```

---

### Task 4: `StructOpsSynthesizer` — build synthetic `BPFFunction` proxies + struct-instance decl

**Files:**
- Create: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java`
- Test: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizerTest.java`

For each `StructOpsDiscovery.Kind`:
1. For each overridden `ExecutableElement`, produce a `SynthFunction(methodSymbol, syntheticBPFFunction)` that the existing plugin machinery will consume as if the method had been directly annotated `@BPFFunction(section = "…", headerTemplate = "…")`.
2. Produce a single `SynthInstance` C snippet — the `SEC(".struct_ops.link") struct <kind> <name> = { .field = field, … };` declaration.

The synthesized `BPFFunction` uses a `java.lang.reflect.Proxy` in exactly the same shape `CompilerPlugin.synthesizeBPFFunction` uses today (see `CompilerPlugin.java:413`).

- [ ] **Step 1: Failing test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;
import me.bechberger.ebpf.bpf.compiler.testutil.CompilerFixture;

import static org.assertj.core.api.Assertions.assertThat;

class StructOpsSynthesizerTest {

    @Test
    void synthesizesSectionAndHeader() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            import me.bechberger.ebpf.type.Ptr;
            import me.bechberger.ebpf.runtime.NetworkingDefinitions.sock;
            @BPF abstract class Cc extends BPFProgram implements TcpCongestionControl {
                @Override public int ssthresh(Ptr<sock> sk) { return 42; }
            }
            """;
        var fixture = CompilerFixture.compile("p.Cc", src);
        var cls = fixture.getClass("p.Cc");
        var kinds = StructOpsDiscovery.discover(cls, fixture.env());
        var result = new StructOpsSynthesizer(fixture.env()).synthesize(cls, kinds);

        assertThat(result.functions()).hasSize(1);
        var fn = result.functions().get(0);
        assertThat(fn.bpfFunction().section()).isEqualTo("struct_ops/ssthresh");
        assertThat(fn.bpfFunction().headerTemplate())
                .isEqualTo("__u32 BPF_PROG($name, struct sock *sk)");

        assertThat(result.instances()).hasSize(1);
        var inst = result.instances().get(0);
        assertThat(inst.kernelName()).isEqualTo("tcp_congestion_ops");
        assertThat(inst.mapName()).isEqualTo("Cc");
        assertThat(inst.cSource())
                .contains("SEC(\".struct_ops.link\")")
                .contains("struct tcp_congestion_ops Cc")
                .contains(".ssthresh")
                .contains("(void *)ssthresh");
    }

    @Test
    void dataFieldRendersAsInitializerNotProgram() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
            import me.bechberger.ebpf.bpf.BPFProgram;
            @BPF abstract class Named extends BPFProgram implements TcpCongestionControl {
                @Override public String name() { return "hellocc"; }
            }
            """;
        var fixture = CompilerFixture.compile("p.Named", src);
        var cls = fixture.getClass("p.Named");
        var kinds = StructOpsDiscovery.discover(cls, fixture.env());
        var result = new StructOpsSynthesizer(fixture.env()).synthesize(cls, kinds);

        // "name" is a data field → no synthesized program, no BPF_PROG wrapping.
        assertThat(result.functions()).isEmpty();
        assertThat(result.instances()).hasSize(1);
        assertThat(result.instances().get(0).cSource())
                .contains(".name = \"hellocc\"");
    }

    @Test
    void instanceNameOverrideRespected() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.annotations.bpf.StructOps;
            import me.bechberger.ebpf.bpf.BPFProgram;

            @StructOps(value = "sched_ext_ops", instanceName = "my_sched")
            interface CustomSchedOps {}

            @BPF abstract class Sched extends BPFProgram implements CustomSchedOps {}
            """;
        var fixture = CompilerFixture.compile("p.Sched", src);
        var cls = fixture.getClass("p.Sched");
        var kinds = StructOpsDiscovery.discover(cls, fixture.env());
        var result = new StructOpsSynthesizer(fixture.env()).synthesize(cls, kinds);
        assertThat(result.instances().get(0).mapName()).isEqualTo("my_sched");
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

- [ ] **Step 3: Implement**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.Unsigned;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

/**
 * Turns {@link StructOpsDiscovery.Kind}s into (a) synthesized
 * {@link BPFFunction} proxies attached to concrete methods and (b)
 * {@code SEC(".struct_ops.link")} struct instance C declarations.
 *
 * <p>Reuses the same shape as
 * {@code CompilerPlugin.synthesizeBPFFunction} so downstream translation
 * treats these as regular {@code @BPFFunction} methods.
 */
public final class StructOpsSynthesizer {

    public record SynthFunction(ExecutableElement method, BPFFunction bpfFunction) {}
    public record SynthInstance(String kernelName, String mapName, String cSource) {}
    public record Result(List<SynthFunction> functions, List<SynthInstance> instances) {}

    private final ProcessingEnvironment env;
    private final JavaToCTypeRenderer renderer = new JavaToCTypeRenderer();

    public StructOpsSynthesizer(ProcessingEnvironment env) {
        this.env = env;
    }

    public Result synthesize(TypeElement bpfClass, List<StructOpsDiscovery.Kind> kinds) {
        List<SynthFunction> functions = new ArrayList<>();
        List<SynthInstance> instances = new ArrayList<>();

        for (var kind : kinds) {
            StructOpsLayout layout = StructOpsLayout.load(kind.kernelName());
            String mapName = kind.instanceName().isEmpty()
                    ? bpfClass.getSimpleName().toString()
                    : kind.instanceName();

            List<String> initializerLines = new ArrayList<>();

            for (ExecutableElement m : kind.overriddenMethods()) {
                String fieldName = StructOpsValidator.camelToSnake(m.getSimpleName().toString());
                StructOpsValidator.validateFieldExists(layout, fieldName);
                StructOpsLayout.Field field = layout.field(fieldName);

                if ("data".equals(field.kind())) {
                    // Data field → literal initializer, no synthesized program.
                    initializerLines.add(renderDataInitializer(bpfClass, m, field));
                } else {
                    // Function field → produce a synthetic @BPFFunction.
                    String section = kind.sectionPrefix() + fieldName;
                    String header = renderHeader(field, m);
                    functions.add(new SynthFunction(m,
                            makeProxy(section, header)));
                    initializerLines.add("    ." + fieldName + " = (void *)" + fieldName);
                }
            }

            String cSource = ""
                    + "SEC(\".struct_ops.link\")\n"
                    + "struct " + kind.kernelName() + " " + mapName + " = {\n"
                    + String.join(",\n", initializerLines) + (initializerLines.isEmpty() ? "" : ",")
                    + "\n};\n";
            instances.add(new SynthInstance(kind.kernelName(), mapName, cSource));
        }
        return new Result(functions, instances);
    }

    /** Renders "__u32 BPF_PROG($name, struct sock *sk, __u32 ack, __u32 acked)". */
    private String renderHeader(StructOpsLayout.Field field, ExecutableElement m) {
        // Return type: prefer BTF's returnType directly — the validator has already
        // confirmed it matches the Java method.  Falling back to Java's rendering
        // keeps us in a single source of truth.
        String ret = field.returnType();
        var params = m.getParameters();
        var argParts = new ArrayList<String>(params.size());
        for (int i = 0; i < params.size(); i++) {
            var p = params.get(i);
            String javaType = p.asType().toString();
            boolean unsigned = p.getAnnotation(Unsigned.class) != null;
            String cType = renderer.renderWithAnnotation(javaType, unsigned);
            argParts.add(cType + " " + p.getSimpleName());
        }
        String args = String.join(", ", argParts);
        return ret + " BPF_PROG($name" + (args.isEmpty() ? "" : ", " + args) + ")";
    }

    /** For a data field like `name`, emit `.name = "hellocc"`. */
    private String renderDataInitializer(TypeElement bpfClass, ExecutableElement m,
                                         StructOpsLayout.Field field) {
        // The concrete method's body is `return "hellocc"`.  We read the string
        // literal directly via the ExecutableElement's tree.
        String literal = extractStringReturnLiteral(m);
        if (literal == null) {
            env.getMessager().printMessage(
                    javax.tools.Diagnostic.Kind.ERROR,
                    "@StructOps data field '" + field.name()
                            + "' must be initialised with a String literal — dynamic values not supported",
                    m);
            return "    ." + field.name() + " = \"\"";
        }
        return "    ." + field.name() + " = \"" + literal + "\"";
    }

    /**
     * Extracts the single string literal returned by a method of the shape
     * {@code default String name() { return "…"; }}. Returns null if the
     * method body is anything else — caller emits a diagnostic in that case.
     *
     * <p>Uses javac's Trees API — see how CompilerPlugin.evalStringTree works
     * (CompilerPlugin.java:923 area). Reuse that helper if it's already
     * public/package-accessible.
     */
    private String extractStringReturnLiteral(ExecutableElement m) {
        // Implemented in Step 4 below using the Trees API.  Two-step split
        // keeps the initial scaffolding compilable while its BTF-shape
        // producer is being landed in a separate commit alongside the
        // Trees-based extractor.
        return me.bechberger.ebpf.bpf.compiler.util.TreeConstants
                .stringReturnLiteral(env, m)
                .orElse(null);
    }

    private BPFFunction makeProxy(String section, String headerTemplate) {
        // Same shape as CompilerPlugin.synthesizeBPFFunction (CompilerPlugin.java:413).
        return (BPFFunction) Proxy.newProxyInstance(
                BPFFunction.class.getClassLoader(),
                new Class[]{BPFFunction.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "section"        -> section;
                    case "headerTemplate" -> headerTemplate;
                    case "annotationType" -> BPFFunction.class;
                    case "toString"       -> "@BPFFunction(section=\"" + section + "\")";
                    case "hashCode"       -> section.hashCode();
                    case "equals"         -> args[0] == proxy;
                    default               -> method.getDefaultValue();
                });
    }
}
```

- [ ] **Step 4: Implement `TreeConstants.stringReturnLiteral` in a preceding commit**

Create `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/util/TreeConstants.java` with:

```java
package me.bechberger.ebpf.bpf.compiler.util;

import com.sun.source.tree.*;
import com.sun.source.util.Trees;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.ExecutableElement;
import java.util.Optional;

/** Compile-time constant extraction from method bodies. */
public final class TreeConstants {

    private TreeConstants() {}

    /**
     * If {@code m}'s body is exactly {@code return "literal";}, returns
     * the literal string. Otherwise returns empty.
     */
    public static Optional<String> stringReturnLiteral(
            ProcessingEnvironment env, ExecutableElement m) {
        var trees = Trees.instance(env);
        var mt = trees.getTree(m);
        if (mt == null || mt.getBody() == null) return Optional.empty();
        var stmts = mt.getBody().getStatements();
        if (stmts.size() != 1) return Optional.empty();
        if (!(stmts.get(0) instanceof ReturnTree rt)) return Optional.empty();
        if (!(rt.getExpression() instanceof LiteralTree lit)) return Optional.empty();
        if (lit.getKind() != Tree.Kind.STRING_LITERAL) return Optional.empty();
        return Optional.of((String) lit.getValue());
    }
}
```

Grep first for an existing `evalStringTree` (or similar) in `CompilerPlugin.java` — if one already does this, use it instead of creating `TreeConstants`. Adjust the `extractStringReturnLiteral` call above to match whatever helper actually lands.

- [ ] **Step 5: Run test — expect PASS**

- [ ] **Step 6: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizerTest.java
git commit -m "feat(plugin): StructOpsSynthesizer emits BPF_PROG headers + struct instance"
```

---

### Task 5: `StructOpsManifest` SPI + writer

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsManifest.java`
- Create: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsManifestWriter.java`

`StructOpsManifest` is a runtime SPI — a small interface the plugin implements in the emitted companion class. The runtime attach walker consumes it without reflection.

- [ ] **Step 1: Write the interface**

```java
package me.bechberger.ebpf.bpf.structops;

import java.util.List;

/**
 * SPI: the compiler plugin emits an implementation of this alongside
 * {@code BPFImpl}. {@link StructOpsAttach#attachAll} reads it at runtime
 * to know which struct_ops maps to attach without reflecting over the
 * class's Java interfaces.
 *
 * <p>Companion class naming: for user class {@code Foo}, the plugin emits
 * {@code FooStructOpsManifest} in the same package.
 */
public interface StructOpsManifest {

    /**
     * One entry per {@code @StructOps} interface implemented by the user's class.
     *
     * @param kernelName the kernel struct_ops kind (e.g. "tcp_congestion_ops")
     * @param mapName    the C-side instance variable name — matches
     *                   {@code bpf_object__find_map_by_name}
     * @param since      minimum kernel version (from the JSON layout;
     *                   fed into {@code BPFLoadError.UnsupportedKernel} on miss)
     */
    record Entry(String kernelName, String mapName, String since) {}

    List<Entry> entries();
}
```

- [ ] **Step 2: Write the manifest writer**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import javax.lang.model.element.TypeElement;
import java.util.List;

/**
 * Emits a public final class next to {@code BPFImpl} that implements
 * {@code StructOpsManifest}. The runtime uses it as an SPI to know which
 * struct_ops instances to attach without reflection.
 *
 * <p>File shape (example for a class {@code p.Cc}):
 * <pre>{@code
 * package p;
 * public final class CcStructOpsManifest
 *     implements me.bechberger.ebpf.bpf.structops.StructOpsManifest {
 *     private static final java.util.List<Entry> ENTRIES = java.util.List.of(
 *         new Entry("tcp_congestion_ops", "Cc", "5.6")
 *     );
 *     public java.util.List<Entry> entries() { return ENTRIES; }
 * }
 * }</pre>
 */
public final class StructOpsManifestWriter {

    /**
     * @param bpfClass      the user's {@code @BPF} class
     * @param instances     one {@link StructOpsSynthesizer.SynthInstance} per interface
     * @param layoutsByKind kernel-name → layout (for {@code since} lookup)
     * @return              the Java source text to write to
     *                      {@code <package>/<ClassName>StructOpsManifest.java}
     */
    public String render(TypeElement bpfClass,
                         List<StructOpsSynthesizer.SynthInstance> instances,
                         java.util.Map<String, StructOpsLayout> layoutsByKind) {
        String pkg = env(bpfClass);
        String className = bpfClass.getSimpleName().toString() + "StructOpsManifest";
        StringBuilder sb = new StringBuilder();
        if (!pkg.isEmpty()) sb.append("package ").append(pkg).append(";\n\n");
        sb.append("public final class ").append(className)
          .append(" implements me.bechberger.ebpf.bpf.structops.StructOpsManifest {\n");
        sb.append("    private static final java.util.List<Entry> ENTRIES = java.util.List.of(\n");
        for (int i = 0; i < instances.size(); i++) {
            var inst = instances.get(i);
            String since = layoutsByKind.get(inst.kernelName()).since();
            sb.append("        new Entry(\"").append(inst.kernelName()).append("\", \"")
              .append(inst.mapName()).append("\", \"").append(since).append("\")");
            if (i + 1 < instances.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("    );\n");
        sb.append("    public java.util.List<Entry> entries() { return ENTRIES; }\n");
        sb.append("}\n");
        return sb.toString();
    }

    private String env(TypeElement bpfClass) {
        var enclosing = bpfClass.getEnclosingElement();
        return (enclosing instanceof javax.lang.model.element.PackageElement pe)
                ? pe.getQualifiedName().toString()
                : "";
    }
}
```

- [ ] **Step 3: Failing unit test**

```java
// bpf-compiler-plugin-test/src/test/java/…/StructOpsManifestWriterTest.java
@Test
void rendersExpectedShape() {
    var writer = new StructOpsManifestWriter();
    var fixture = CompilerFixture.compile("p.Cc",
        "package p; import me.bechberger.ebpf.annotations.bpf.*;"
      + " import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;"
      + " import me.bechberger.ebpf.bpf.BPFProgram;"
      + " @BPF abstract class Cc extends BPFProgram implements TcpCongestionControl {}");
    var cls = fixture.getClass("p.Cc");
    var instances = java.util.List.of(
        new StructOpsSynthesizer.SynthInstance("tcp_congestion_ops", "Cc", "..."));
    var layouts = java.util.Map.of("tcp_congestion_ops",
        StructOpsLayout.load("tcp_congestion_ops"));
    String src = writer.render(cls, instances, layouts);

    org.assertj.core.api.Assertions.assertThat(src)
        .contains("package p;")
        .contains("public final class CcStructOpsManifest")
        .contains("implements me.bechberger.ebpf.bpf.structops.StructOpsManifest")
        .contains("new Entry(\"tcp_congestion_ops\", \"Cc\", \"5.6\")");
}
```

- [ ] **Step 4: Run test — expect PASS after writer + interface land**

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsManifest.java
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsManifestWriter.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsManifestWriterTest.java
git commit -m "feat(plugin): StructOpsManifest SPI + companion-class writer"
```

---

### Task 6: Wire into `CompilerPlugin`

**Files:**
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java`

Point of integration: existing `processBPFClass(...)` (or wherever the @BPF class is walked; find it via `grep -n "processBPFClass\|processBPFProgram\|processBPF\b" CompilerPlugin.java`). After the existing @BPFFunction discovery step, but before translation:

1. Run `StructOpsDiscovery.discover(...)`.
2. Run `StructOpsValidator.*` on each `(field, method)` pair — on `ValidationException`, emit a javac ERROR at the method site (`m.getSimpleName()` position or the enclosing method's tree).
3. Run `StructOpsSynthesizer.synthesize(...)`.
4. Register each `SynthFunction.bpfFunction()` as the effective annotation for its `ExecutableElement` — extend the existing `synthesizeBPFFunction`-style cache. If `getEffectiveBPFFunction` uses a `Map<MethodSymbol, BPFFunction>`, add the synthesized entries to it.
5. Emit each `SynthInstance.cSource()` as a synthetic top-level declaration — the existing pipeline has a `syntheticDecls` list (`CompilerPlugin.java:906`). Prepend or append to that list.
6. Call `StructOpsManifestWriter.render(...)` and write the resulting source via the annotation-processor `Filer`.

- [ ] **Step 1: Read the relevant CompilerPlugin sections first**

```
sed -n '340,420p' bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java
sed -n '880,920p' bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java
```

Locate the exact insertion points before editing.

- [ ] **Step 2: Add the discovery → validation → synthesis pipeline**

```java
// Somewhere in processBPFClass, after existing @BPFFunction collection:
var structOpsKinds = StructOpsDiscovery.discover(bpfClassElement, env());
var layoutsByKind = new HashMap<String, StructOpsLayout>();
for (var kind : structOpsKinds) {
    var layout = StructOpsLayout.load(kind.kernelName());
    layoutsByKind.put(kind.kernelName(), layout);
    for (var m : kind.overriddenMethods()) {
        String fieldName = StructOpsValidator.camelToSnake(m.getSimpleName().toString());
        try {
            StructOpsValidator.validateFieldExists(layout, fieldName);
            var field = layout.field(fieldName);
            StructOpsValidator.validateArgCount(field, m.getParameters().size(), fieldName);
            var renderer = new JavaToCTypeRenderer();
            // Return type
            String ret = renderer.render(m.getReturnType().toString());
            StructOpsValidator.validateReturnType(field, ret, fieldName);
            // Args
            for (int i = 0; i < m.getParameters().size(); i++) {
                var p = m.getParameters().get(i);
                boolean unsigned = p.getAnnotation(me.bechberger.ebpf.annotations.Unsigned.class) != null;
                String rArg = renderer.renderWithAnnotation(p.asType().toString(), unsigned);
                StructOpsValidator.validateArgType(field.args().get(i), rArg, i, fieldName);
            }
        } catch (StructOpsValidator.ValidationException ex) {
            env().getMessager().printMessage(
                    javax.tools.Diagnostic.Kind.ERROR, ex.getMessage(), m);
        }
    }
}
var synth = new StructOpsSynthesizer(env()).synthesize(bpfClassElement, structOpsKinds);
// Register synthesized BPFFunctions
for (var sf : synth.functions()) {
    // Depends on how getEffectiveBPFFunction is backed — see line ~343 of CompilerPlugin.
    // If it's a private map, add a setter or make the field package-private for this pass.
    registerSynthesizedBPFFunction((MethodSymbol) sf.method(), sf.bpfFunction());
}
// Store the SEC(".struct_ops.link") snippets as synthetic decls.  The existing
// syntheticDecls list is a List<FuncDecl>; a data decl doesn't fit the shape.
// Simplest: append the snippet to the `code` string just before the emit at
// CompilerPlugin.java:1024 (`code + implAnn.after()`).  Concretely, keep a
// `structOpsInstanceSnippets` List<String> field, and just before the final
// `code = combineCode(...) + implAnn.after()` append them:
//     code = code + "\n\n" + String.join("\n\n", structOpsInstanceSnippets);

// Emit the manifest class via Filer
if (!structOpsKinds.isEmpty()) {
    var manifestSrc = new StructOpsManifestWriter().render(
            bpfClassElement, synth.instances(), layoutsByKind);
    String pkg = ((PackageElement) bpfClassElement.getEnclosingElement())
            .getQualifiedName().toString();
    String fqn = pkg + (pkg.isEmpty() ? "" : ".")
            + bpfClassElement.getSimpleName() + "StructOpsManifest";
    try (var w = env().getFiler().createSourceFile(fqn).openWriter()) {
        w.write(manifestSrc);
    } catch (java.io.IOException e) {
        env().getMessager().printMessage(
            javax.tools.Diagnostic.Kind.ERROR,
            "failed to write " + fqn + ": " + e.getMessage(), bpfClassElement);
    }
}
```

Notes for the implementer:
- Reading and understanding the existing `getEffectiveBPFFunction` / `synthesizeBPFFunction` pair (CompilerPlugin.java:343 and :351) is required before adding the synthesized registration — the shape of that cache dictates where the synthesized entries land.
- `syntheticDecls` at line ~906 is a `List<FuncDecl>` — struct instances aren't function decls. The simpler route is appending the C snippet to the `code` string just before the `implAnn.after()` concatenation (CompilerPlugin.java:1024). Do this rather than shoehorning a struct decl into `FuncDecl`.

- [ ] **Step 3: Rebuild the plugin + bpf jar (both, per feedback memory)**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin,bpf -am install -DskipTests 2>&1 | tail -20'
```
Expected: BUILD SUCCESS.

- [ ] **Step 4: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/CompilerPlugin.java
git commit -m "feat(plugin): wire @StructOps discovery/validation/synthesis into pipeline"
```

---

### Task 7: End-to-end codegen test

**Files:**
- Create: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsCodegenTest.java`

- [ ] **Step 1: Test**

```java
@Test
void tcpCongMinimalEmits() {
    String src = """
        package p;
        import me.bechberger.ebpf.annotations.bpf.*;
        import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
        import me.bechberger.ebpf.bpf.BPFProgram;
        import me.bechberger.ebpf.type.Ptr;
        import me.bechberger.ebpf.runtime.NetworkingDefinitions.sock;
        @BPF abstract class HelloCc extends BPFProgram implements TcpCongestionControl {
            @Override public int ssthresh(Ptr<sock> sk) { return 42; }
            @Override public void congAvoid(Ptr<sock> sk, int ack, int acked) { }
            @Override public String name() { return "hellocc"; }
        }
        """;
    var result = CompilerFixture.compileAndGenerate("p.HelloCc", src);
    String c = result.generatedC();
    assertThat(c).contains("SEC(\"struct_ops/ssthresh\")");
    assertThat(c).contains("SEC(\"struct_ops/cong_avoid\")");
    assertThat(c).contains("BPF_PROG(ssthresh, struct sock *sk)");
    assertThat(c).contains("SEC(\".struct_ops.link\")");
    assertThat(c).contains("struct tcp_congestion_ops HelloCc = {");
    assertThat(c).contains(".ssthresh = (void *)ssthresh");
    assertThat(c).contains(".cong_avoid = (void *)cong_avoid");
    assertThat(c).contains(".name = \"hellocc\"");
    // Manifest class was emitted:
    assertThat(result.emittedSourceFiles())
        .anyMatch(f -> f.endsWith("HelloCcStructOpsManifest.java"));
}

@Test
void unknownMethodCompileError() {
    String src = """
        package p;
        import me.bechberger.ebpf.annotations.bpf.*;
        import me.bechberger.ebpf.annotations.bpf.StructOps;
        import me.bechberger.ebpf.bpf.BPFProgram;

        @StructOps("tcp_congestion_ops")
        interface Custom {
            default void wibbleWobble() {}   // no such BTF field
        }

        @BPF abstract class Bad extends BPFProgram implements Custom {
            @Override public void wibbleWobble() {}
        }
        """;
    var result = CompilerFixture.compile("p.Bad", src);
    assertThat(result.errorMessages())
        .anyMatch(m -> m.contains("wibble_wobble") && m.contains("no matching field"));
}
```

The fixture's `compileAndGenerate` should return not just diagnostics but the actual `.c` output — search `bpf-compiler-plugin-test` for how existing codegen assertions read the generated file (e.g. `CompilerPluginTest.testInArenaClassFieldEmitsArenaQualifier` at CompilerPluginTest.java:2510 reads generated C — follow that pattern).

- [ ] **Step 2: Run — expect PASS after Task 6 wiring**

- [ ] **Step 3: Commit**

```bash
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsCodegenTest.java
git commit -m "test(plugin): end-to-end @StructOps codegen for TCP CC"
```

---

### Task 8: `StructOpsInfo` + `StructOpsAttach` runtime

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsInfo.java`
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsAttach.java`

- [ ] **Step 1: Write `StructOpsInfo`**

```java
package me.bechberger.ebpf.bpf.structops;

/**
 * Post-attach diagnostic for a single {@code @StructOps} instance.
 * Available via {@code BPFProgram.structOpsInfo()}.
 *
 * @param kernelName kernel BTF type name (e.g. {@code "tcp_congestion_ops"})
 * @param mapName    C-side struct variable name (matches
 *                   {@code bpf_object__find_map_by_name})
 * @param mapFd      the map's file descriptor
 * @param bpfLinkId  the {@code bpf_map__attach_struct_ops} return; 0 if the
 *                   attach was rejected as unsupported and gracefully skipped
 */
public record StructOpsInfo(
        String kernelName,
        String mapName,
        int mapFd,
        long bpfLinkId) {}
```

- [ ] **Step 2: Write `StructOpsAttach`**

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.bpf.BPFProgram;

import java.util.ArrayList;
import java.util.List;

/**
 * Walks a {@code BPFProgram}'s companion {@link StructOpsManifest} and
 * attaches each declared struct_ops instance. Called by
 * {@link BPFProgram#load(Class)} after {@code bpf_object__load}.
 *
 * <p>Idempotent — a second call sees the recorded {@link StructOpsInfo}
 * for the map (via {@code program.structOpsInfo()}) and no-ops.
 */
public final class StructOpsAttach {

    private StructOpsAttach() {}

    public static List<StructOpsInfo> attachAll(BPFProgram program) {
        var manifest = loadManifest(program);
        if (manifest == null) return List.of();

        var already = program.structOpsInfo();
        if (already != null && !already.isEmpty()) return already;

        List<StructOpsInfo> attached = new ArrayList<>();
        for (var e : manifest.entries()) {
            // Feature gate — throws BPFLoadError.UnsupportedKernel on miss.
            program.enforceStructOpsFeature(e.kernelName(), e.since());
            // Reuse the existing attachStructOps FFI plumbing.
            program.attachStructOps(e.mapName());
            int fd = program.getMapDescriptorByName(e.mapName()).fd();
            attached.add(new StructOpsInfo(
                    e.kernelName(),
                    e.mapName(),
                    fd,
                    program.lastAttachedStructOpsLinkId()));
        }
        return attached;
    }

    /**
     * Loads the plugin-emitted companion class {@code <ClassName>StructOpsManifest}
     * from the same package as the user's class. Returns null if the class has
     * no {@code @StructOps} interfaces (no manifest was emitted).
     */
    private static StructOpsManifest loadManifest(BPFProgram program) {
        Class<?> userClass = program.getUserClass();
        String fqn = userClass.getName() + "StructOpsManifest";
        try {
            Class<?> mCls = Class.forName(fqn, true, userClass.getClassLoader());
            return (StructOpsManifest) mCls.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            return null;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                "failed to load " + fqn + " — this is a plugin bug", e);
        }
    }
}
```

`BPFProgram.getUserClass()`, `.enforceStructOpsFeature(...)`, `.lastAttachedStructOpsLinkId()`, and a getter for `.structOpsInfo()` all need to be added in Task 9.

- [ ] **Step 3: No test yet** — integration test in Task 10.

- [ ] **Step 4: Commit** (after Task 9 lands so this compiles clean)

Move the commit for Task 8 to happen after Task 9 wires the missing `BPFProgram` methods. Task 8's code will not compile standalone.

---

### Task 9: `BPFProgram` integration + `BPFLoadError.StructOpsAttachFailed`

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java`

- [ ] **Step 1: Add `BPFLoadError.StructOpsAttachFailed`**

Right next to `BPFLoadError.MissingKfunc` (added in the Features sub-plan):

```java
public static class StructOpsAttachFailed extends BPFLoadError {
    private final String kernelName;
    private final String detail;
    public StructOpsAttachFailed(String kernelName, String detail) {
        super("struct_ops attach failed for '" + kernelName + "': " + detail);
        this.kernelName = kernelName;
        this.detail = detail;
    }
    public String kernelName() { return kernelName; }
    public String detail()     { return detail; }
}
```

- [ ] **Step 2: Add the new `BPFProgram` accessors + hook**

```java
// Instance state
private List<StructOpsInfo> structOpsInfo = java.util.List.of();
private long lastAttachedStructOpsLinkId;
private Class<?> userClass;   // set in load(); needed by StructOpsAttach

public List<StructOpsInfo> structOpsInfo() { return structOpsInfo; }
public Class<?> getUserClass()             { return userClass; }
public long lastAttachedStructOpsLinkId()  { return lastAttachedStructOpsLinkId; }

/** Called by {@link StructOpsAttach}; throws
 *  {@link BPFLoadError.UnsupportedKernel} if the running kernel does not
 *  advertise the struct_ops kind. */
public void enforceStructOpsFeature(String kernelName, String since) {
    if (!me.bechberger.ebpf.bpf.features.Features.hasStructOps(kernelName)) {
        throw new BPFLoadError.UnsupportedKernel("struct_ops " + kernelName, since);
    }
}
```

Modify `attachStructOps(String name)` to record the link id:

```java
public void attachStructOps(String name) {
    var opsDescriptor = getMapDescriptorByName(name);
    if (opsDescriptor == null) {
        throw new BPFLoadError.StructOpsAttachFailed(name, "map not found");
    }
    var res = BPF_MAP__ATTACH_STRUCT_OPS.call(opsDescriptor.map());
    if (res.result() == MemorySegment.NULL && res.hasError()) {
        throw new BPFLoadError.StructOpsAttachFailed(name,
                "bpf_map__attach_struct_ops errno=" + res.err());
    }
    attachedStructOps.add(res.result());
    lastAttachedStructOpsLinkId = res.result().address();  // link is a pointer; address is fine as an id
}
```

- [ ] **Step 3: Call `StructOpsAttach.attachAll` from `load(...)`**

Both existing paths (single-arg `load(clazz)` and multi-arg `load(clazz, deps...)`) need the same hook. Add after the `enforceFeatureRequirements(clazz)` call already present (from the Features sub-plan) and after `bpf_object__load`:

```java
program.userClass = clazz;
program.structOpsInfo = me.bechberger.ebpf.bpf.structops.StructOpsAttach.attachAll(program);
```

- [ ] **Step 4: Commit — with Task 8's files**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java
git add bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsInfo.java
git add bpf/src/main/java/me/bechberger/ebpf/bpf/structops/StructOpsAttach.java
git commit -m "feat(bpf): StructOpsAttach + BPFProgram.load() wiring"
```

---

### Task 10: Real-kernel smoke test — minimal TCP CC

**Files:**
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/StructOpsAttachTest.java`

The whole point of the plumbing. A minimal `TcpCongestionControl` implementation loads on a real kernel and appears in the kernel's TCP CC list.

- [ ] **Step 1: Write the test**

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.NetworkingDefinitions.sock;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class StructOpsAttachTest {

    @BPF
    abstract static class HelloCcSample extends BPFProgram implements TcpCongestionControl {
        @Override public int ssthresh(Ptr<sock> sk)              { return 42; }
        @Override public void congAvoid(Ptr<sock> sk, int ack, int acked) { /* no-op */ }
        @Override public String name() { return "hellocc"; }
    }

    @Test
    void tcpCongregistrsAndUnregisters() throws Exception {
        String proc = "/proc/sys/net/ipv4/tcp_available_congestion_control";
        try (var prog = BPFProgram.load(HelloCcSample.class)) {
            var infos = prog.structOpsInfo();
            assertThat(infos).hasSize(1);
            assertThat(infos.get(0).kernelName()).isEqualTo("tcp_congestion_ops");
            assertThat(infos.get(0).mapName()).isEqualTo("HelloCcSample");
            String available = Files.readString(Path.of(proc));
            assertThat(available).contains("hellocc");
        }
        // After close, the algo should be gone:
        String after = Files.readString(Path.of(proc));
        assertThat(after).doesNotContain("hellocc");
    }
}
```

- [ ] **Step 2: Run under vng**

```
rsync -avz --delete --exclude=.git --exclude=target ./ thinkstation:/home/i560383/code/experiments/hello-ebpf/
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin,bpf -am install -DskipTests'
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf StructOpsAttachTest 2>&1 | tail -40'
```

Expected: PASS. If it fails, the most likely causes are:

1. **Missing `NetworkingDefinitions.sock`** — added as stub in Sub-plan A Task 7. Confirm it landed.
2. **BTF-type name mismatch** — `struct sock *` vs `sock *`. The validator's `typesMatch` normalization should handle both; if it doesn't, tighten `normalise()` in `StructOpsValidator`.
3. **Kernel too old** — thinkstation is 6.14+; tcp_congestion_ops has been stable for years.
4. **Manifest class not on the classpath** — annotation processing must run for both plugin compilation and user compilation. Verify `bpf-compiler-plugin` is on `annotationProcessorPath` for the `bpf` module test compile.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/structops/StructOpsAttachTest.java
git commit -m "test(bpf): real-kernel StructOpsAttachTest — tcp_congestion_ops"
```

---

### Task 11: `structOpsInfo` diagnostic + feature-gate coverage

**Files:**
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/StructOpsFeatureGateTest.java`

- [ ] **Step 1: Write test**

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.features.Features;
import me.bechberger.ebpf.bpf.features.ProbeKey;
import me.bechberger.ebpf.bpf.features.ProbeResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class StructOpsFeatureGateTest {

    // A private struct_ops kind we mark unsupported for the test.
    @StructOps("unlikely_ops")
    interface UnlikelyOps { default int foo() { return 0; } }

    @BPF abstract static class Prog extends BPFProgram implements UnlikelyOps {
        @Override public int foo() { return 1; }
    }

    @BeforeEach void setup() {
        Features.resetCacheForTest();
        Features.setDispatcherForTest(key ->
            (key instanceof ProbeKey.StructOpsKey s && "unlikely_ops".equals(s.name()))
                ? new ProbeResult.Unsupported("simulated")
                : new ProbeResult.Supported());
    }

    @AfterEach void reset() { Features.resetCacheForTest(); }

    @Test
    void unsupportedStructOpsThrowsUnsupportedKernel() {
        assertThrows(BPFProgram.BPFLoadError.UnsupportedKernel.class,
                () -> BPFProgram.load(Prog.class));
    }
}
```

`unlikely_ops` won't have a JSON layout — the plugin will emit a compile-time error (`unknown struct_ops kind`). So this test needs a real layout. Amend: use `hid_bpf_ops` (which has a layout) as the kind, and mark it unsupported via the dispatcher. The point is testing the load-time feature gate, not the compile-time kind check.

Revised test skeleton:

```java
@BPF abstract static class Prog extends BPFProgram implements HidBpfOps {
    @Override public int hidDeviceEvent(...) { return 0; }
}

@BeforeEach void setup() {
    Features.resetCacheForTest();
    Features.setDispatcherForTest(key ->
        (key instanceof ProbeKey.StructOpsKey s && "hid_bpf_ops".equals(s.name()))
            ? new ProbeResult.Unsupported("simulated")
            : new ProbeResult.Supported());
}

@Test
void unsupportedStructOpsThrowsUnsupportedKernel() {
    assertThrows(BPFProgram.BPFLoadError.UnsupportedKernel.class,
            () -> BPFProgram.load(Prog.class));
}
```

- [ ] **Step 2: Run + commit**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf StructOpsFeatureGateTest 2>&1 | tail -20'
```

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/structops/StructOpsFeatureGateTest.java
git commit -m "test(bpf): StructOpsFeatureGateTest for Features.hasStructOps"
```

---

## Verification

**End-to-end acceptance:**

1. **Plugin unit tests** (mac OK): `mvn -pl bpf-compiler-plugin,bpf-compiler-plugin-test test` — all new test classes pass. Specifically:
   - `StructOpsDiscoveryTest`
   - `StructOpsValidatorTest`
   - `JavaToCTypeRendererTest`
   - `StructOpsSynthesizerTest`
   - `StructOpsManifestWriterTest`
   - `StructOpsCodegenTest`

2. **Real-kernel smoke** (thinkstation via vng):
   - `StructOpsAttachTest.tcpCongregistrsAndUnregisters` — passes.
   - `StructOpsFeatureGateTest.unsupportedStructOpsThrowsUnsupportedKernel` — passes.

3. **Generated-C inspection** (thinkstation): after building, open the generated `.c` for `HelloCcSample`. Confirm:
   - One `SEC("struct_ops/ssthresh") … BPF_PROG(ssthresh, struct sock *sk) { … }` block.
   - One `SEC("struct_ops/cong_avoid") … BPF_PROG(cong_avoid, struct sock *sk, __u32 ack, __u32 acked) { … }` block.
   - No `SEC` block for `name()`.
   - `SEC(".struct_ops.link") struct tcp_congestion_ops HelloCcSample = { .ssthresh = (void *)ssthresh, .cong_avoid = (void *)cong_avoid, .name = "hellocc" };`.

4. **Existing schedulers still compile + attach**: nothing this sub-plan touches breaks the current `Scheduler` inline emission path.
   ```
   ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
     PATH=/home/i560383/.local/bin:$PATH \
     ./scripts/run-tests-vng.sh bpf-samples MinimalSchedulerSample 2>&1 | tail -25'
   ```
   Expected: same pass state as before this sub-plan.

## Out of scope (deferred to later sub-plans)

- **Sched-ext migration.** `Scheduler` still uses its inline `@BPFInterface(before=..., after=...)` template. Sub-plan C converts `Scheduler` to a `@StructOps("sched_ext_ops")` interface — its own concerns (parity round-trip test, delete `attachScheduler`, migrate every in-tree caller).
- **QdiscOps / HidBpfOps smoke tests.** Sub-plan D — those need `tc` setup / HID device probing that lives cleanly on its own.
- **`HelloCubicSample`.** Sub-plan D — user-facing sample with a real cubic derivation, `main()`, README.
- **Multi-kind class** (a class that implements both `TcpCongestionControl` AND `QdiscOps`). Spec §15 admits this is legal but flags it as not-especially-tested. Deferred until a real use case arrives.
- **Deprecation shim for external `attachScheduler` users**. Sub-plan C.
