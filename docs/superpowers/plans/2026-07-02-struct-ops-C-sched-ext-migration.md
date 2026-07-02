# @StructOps Sub-Plan C: sched-ext migration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retarget the existing `Scheduler` interface at the generic `@StructOps` pipeline landed in Sub-plans A + B. The bespoke `@BPFInterface(after = "SCX_OPS_DEFINE(sched_ops, …)")` block goes away; the plugin emits the equivalent `SEC(".struct_ops.link")` declaration from `@StructOps("sched_ext_ops", instanceName = "sched_ops")`. `attachScheduler()` becomes a thin deprecated shim over `BPFProgram.load()`'s automatic attach. All in-tree consumers move to the new shape while a parity test asserts byte-equivalent generated C between the old and new emission paths for a canonical scheduler.

**Architecture:** Preserve the `@BPFInterface(before = ...)` block — it emits kfunc externs, arena macros, and the `BPF_STRUCT_OPS_SLEEPABLE` / `SCX_OPS_DEFINE` macros that other parts of the runtime still expect. Delete only the `after = ...` clause, which is now the plugin's responsibility. Add a `@Sleepable` method-level marker so a scheduler method that used to be `struct_ops.s/<name>` (only `sched_init` today) can opt into the sleepable section without duplicating the sectionPrefix mechanism. Attach lifecycle moves entirely into `BPFProgram.load()` via `StructOpsAttach.attachAll(...)` (Sub-plan B Task 8); `attachScheduler()` becomes a no-op deprecated wrapper for one release, then deleted in a follow-up. `runSchedulerLoop()` remains the ergonomic entry point.

**Tech Stack:** Java 25, existing sched-ext test infra (thinkstation vng + `SchedulerSmokeTest`), no new external dependencies.

**Reference spec:** `docs/superpowers/specs/2026-07-02-struct-ops-design.md` §10 (Migration), §11 (Compiler plugin integration), and the migration guidance at lines 576-579 (keep `attachScheduler()` as a no-op wrapper).

**Depends on:** Sub-plans A (`2026-07-02-struct-ops-A-foundation.md`) and B (`2026-07-02-struct-ops-B-codegen-attach.md`) landed and merged.

---

## File Structure

**New files:**

- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/Sleepable.java` — method-level marker; presence flips the synthesized section from `struct_ops/<f>` to `struct_ops.s/<f>`.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/SchedulerCodegenParityTest.java` — reads the generated `.c` for a canonical `MinimalScheduler` before and after, asserts every relevant emitted line (SEC directives, BPF_PROG headers, SCX_OPS_DEFINE body) matches semantically.

**Modified files:**

- `bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java` — remove the `after = ...` block from `@BPFInterface`; add `@StructOps("sched_ext_ops", instanceName = "sched_ops")`; annotate `sched_init` with `@Sleepable`; delete or shim `attachScheduler()` per the strategy below.
- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java` — recognise `@Sleepable` and emit `struct_ops.s/<field>` instead of `struct_ops/<field>` for those methods.
- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java` — property placeholder passthrough: preserve `__property_extra_flags`, `__property_timeout_ms`, and `__property_sched_name` in the emitted `SEC(".struct_ops.link")` initializer body when they appear in the layout's default-value slots.
- `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerExtension.java`, `SchedulerSmokeTest.java`, `SchedulerBehaviorTest.java` — drop the explicit `sched.attachScheduler()` calls; assert `prog.structOpsInfo()` reports the sched_ext_ops entry instead.
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/SampleScheduler.java`, `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LockHolderBoostScheduler.java` — drop the explicit `attachScheduler()` calls in `main`.
- `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/sched_ext_ops.json` — landed in Sub-plan A; here we lock its exact contents against the current inline template by adding a parity test that regenerates from the same BTF source and diffs.

**Decomposition rationale:** The `@Sleepable` marker is a distinct, one-line annotation with a single decision (is this method's section prefix `struct_ops/` or `struct_ops.s/`?) — putting it in `annotations/` (rather than piling more state onto `@StructOps`) keeps the SPI surface stable and lets other struct_ops kinds adopt sleepable semantics without touching the top-level annotation. `SchedulerCodegenParityTest` lives in `bpf/` (not `bpf-compiler-plugin-test/`) because it needs the full annotation-processing pipeline including sched-ext-specific property substitution; the plugin-test module doesn't have that classpath.

---

## Tasks

### Task 1: `@Sleepable` marker annotation

**Files:**
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/Sleepable.java`
- Test: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/SleepableMarkerTest.java`

- [ ] **Step 1: Failing test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.bpf.compiler.testutil.CompilerFixture;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SleepableMarkerTest {

    @Test
    void sleepableFlipsSectionPrefixToStructOpsSDot() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.annotations.bpf.StructOps;
            import me.bechberger.ebpf.annotations.bpf.Sleepable;
            import me.bechberger.ebpf.bpf.BPFProgram;

            @StructOps("sched_ext_ops")
            interface Sched {
                default int schedInit() { return 0; }
            }
            @BPF abstract class S extends BPFProgram implements Sched {
                @Override @Sleepable public int schedInit() { return 0; }
            }
            """;
        var fixture = CompilerFixture.compile("p.S", src);
        var cls = fixture.getClass("p.S");
        var kinds = me.bechberger.ebpf.bpf.compiler.structops.StructOpsDiscovery
                .discover(cls, fixture.env());
        var result = new me.bechberger.ebpf.bpf.compiler.structops.StructOpsSynthesizer(fixture.env())
                .synthesize(cls, kinds);
        assertThat(result.functions()).hasSize(1);
        assertThat(result.functions().get(0).bpfFunction().section())
                .isEqualTo("struct_ops.s/sched_init");
    }

    @Test
    void nonSleepableKeepsStructOpsSlash() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.annotations.bpf.StructOps;
            import me.bechberger.ebpf.bpf.BPFProgram;

            @StructOps("sched_ext_ops")
            interface Sched {
                default int schedInit() { return 0; }
            }
            @BPF abstract class S extends BPFProgram implements Sched {
                @Override public int schedInit() { return 0; }
            }
            """;
        var fixture = CompilerFixture.compile("p.S", src);
        var cls = fixture.getClass("p.S");
        var kinds = me.bechberger.ebpf.bpf.compiler.structops.StructOpsDiscovery
                .discover(cls, fixture.env());
        var result = new me.bechberger.ebpf.bpf.compiler.structops.StructOpsSynthesizer(fixture.env())
                .synthesize(cls, kinds);
        assertThat(result.functions().get(0).bpfFunction().section())
                .isEqualTo("struct_ops/sched_init");
    }
}
```

- [ ] **Step 2: Run — expect FAIL** (annotation missing, synthesizer ignores it)

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test -Dtest=SleepableMarkerTest test 2>&1 | tail -20'
```

- [ ] **Step 3: Implement the annotation**

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks a {@code @StructOps} method whose BPF section should be emitted
 * as {@code struct_ops.s/<name>} (a sleepable variant) rather than the
 * default {@code struct_ops/<name>}.
 *
 * <p>The kernel accepts both prefixes for methods declared sleepable in
 * their BTF metadata (see {@code libbpf} {@code find_struct_ops_map}
 * lookup logic). Only sched-ext's {@code sched_init} needs this today,
 * but the marker is written generically so any future struct_ops kind
 * can opt in.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Sleepable {}
```

- [ ] **Step 4: Extend `StructOpsSynthesizer.synthesize(...)`**

In `renderHeader` / the section-computing branch (Sub-plan B Task 4), before assembling `section = kind.sectionPrefix() + fieldName`, check whether the concrete method carries `@Sleepable`. If so, override the prefix to `"struct_ops.s/"`. Concretely:

```java
// In the loop over kind.overriddenMethods():
ExecutableElement concrete = findConcreteMethodOnClass(bpfClass, m);
String prefix = kind.sectionPrefix();
if (concrete != null && concrete.getAnnotation(
        me.bechberger.ebpf.annotations.bpf.Sleepable.class) != null) {
    prefix = "struct_ops.s/";
}
String section = prefix + fieldName;
```

`findConcreteMethodOnClass` walks `ElementFilter.methodsIn(bpfClass.getEnclosedElements())` for a matching name + erasure; the discovery step already located the interface method (`m` here is the interface version), so the concrete version is the one the `@Sleepable` lives on.

- [ ] **Step 5: Run test — expect PASS** (both cases)

- [ ] **Step 6: Commit**

```bash
git add annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/Sleepable.java
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/SleepableMarkerTest.java
git commit -m "feat(annotations): @Sleepable flips synthesized section to struct_ops.s/"
```

---

### Task 2: Property-placeholder passthrough in `StructOpsSynthesizer`

**Files:**
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java`
- Test: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/PropertyPassthroughTest.java`

The current sched-ext `@BPFInterface(after = ...)` block hardcodes `.flags = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | (__property_extra_flags), .timeout_ms = __property_timeout_ms, .name = "__property_sched_name"`. These `__property_X` placeholders are resolved later by `BPFProgram.getPropertyValue(X)` via string substitution over the generated C. The plugin's struct-instance emitter must produce the same placeholders for these three fields so the property-substitution pass has something to substitute.

Approach: teach `StructOpsSynthesizer` a small **override table** — a `Map<String, String>` keyed by `(kernelName + "." + fieldName)` that supplies the literal C expression to use instead of the default `"(void *)<name>"` initializer. For sched-ext, seed:

- `"sched_ext_ops.flags"` → `"SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | (__property_extra_flags)"`
- `"sched_ext_ops.timeout_ms"` → `"__property_timeout_ms"`
- `"sched_ext_ops.name"` → `"\"__property_sched_name\""`

Emit those literally into the `SEC(".struct_ops.link")` initializer.

- [ ] **Step 1: Failing test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.bpf.compiler.testutil.CompilerFixture;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PropertyPassthroughTest {

    @Test
    void schedExtInitializerCarriesPropertyPlaceholders() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.bpf.Scheduler;
            import me.bechberger.ebpf.bpf.BPFProgram;
            @BPF abstract class MyS extends BPFProgram implements Scheduler {}
            """;
        var fixture = CompilerFixture.compile("p.MyS", src);
        var cls = fixture.getClass("p.MyS");
        var kinds = StructOpsDiscovery.discover(cls, fixture.env());
        var result = new StructOpsSynthesizer(fixture.env()).synthesize(cls, kinds);
        var inst = result.instances().get(0);
        assertThat(inst.cSource()).contains(".flags = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | (__property_extra_flags)");
        assertThat(inst.cSource()).contains(".timeout_ms = __property_timeout_ms");
        assertThat(inst.cSource()).contains(".name = \"__property_sched_name\"");
    }
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement**

Add a static map in `StructOpsSynthesizer`:

```java
/**
 * Kernel-specific override table: (kernelName + "." + fieldName) →
 * literal C expression to emit instead of the default "(void *)name"
 * / string literal. Populated only for kinds that use hello-ebpf's
 * property-substitution mechanism (currently just sched_ext_ops).
 *
 * <p>These placeholders are resolved at BPFProgram.load() time via
 * getPropertyValue() string substitution. The plugin's role is
 * verbatim passthrough.
 */
private static final java.util.Map<String, String> PROPERTY_OVERRIDES =
        java.util.Map.of(
            "sched_ext_ops.flags",
                "SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | (__property_extra_flags)",
            "sched_ext_ops.timeout_ms", "__property_timeout_ms",
            "sched_ext_ops.name",       "\"__property_sched_name\""
        );
```

In the initializer-emission loop for each `kind`, iterate the layout's *data* fields (kind == "data" or non-function) and for any key present in `PROPERTY_OVERRIDES`, emit `    .<fieldName> = <override>` — even if the user didn't override that method. This is because `flags`, `timeout_ms`, and `name` are not method-shaped on `Scheduler`; they're implicit.

Note: this diverges slightly from Sub-plan B's rule "iterate `kind.overriddenMethods()`". Extend the synthesizer's initializer-line collection to *also* walk `PROPERTY_OVERRIDES` for the current `kind.kernelName()` and emit any that aren't already covered by an overridden method:

```java
for (var entry : PROPERTY_OVERRIDES.entrySet()) {
    String[] parts = entry.getKey().split("\\.", 2);
    if (!parts[0].equals(kind.kernelName())) continue;
    String fname = parts[1];
    if (initializerLines.stream().anyMatch(l -> l.contains("." + fname + " ="))) continue;
    initializerLines.add("    ." + fname + " = " + entry.getValue());
}
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/PropertyPassthroughTest.java
git commit -m "feat(plugin): pass through sched-ext __property_ placeholders in initializer"
```

---

### Task 2b: `camelToSnake` — acronym-aware conversion

**Files:**
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsValidator.java`
- Modify: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsValidatorTest.java` (add a table-driven test if it exists; else create)

**Why this task exists:** The current `camelToSnake` implementation lowercases each uppercase letter and inserts an underscore before it, which turns `selectCPU` into `select_c_p_u`. The kernel BTF field is `select_cpu`. Runs of uppercase letters must stay grouped as one word segment. This is a prerequisite for Task 3 — without it, sched-ext method-to-BTF-field lookup fails for `selectCPU`, and any similar acronym-carrying method on other struct_ops kinds hits the same bug.

**Algorithm:** Insert an underscore before an uppercase letter only when the previous letter is lowercase OR the next letter is lowercase (i.e., the current uppercase is at a word boundary). This is the same rule Guava/Apache Commons uses for `LOWER_CAMEL` → `LOWER_UNDERSCORE`.

Cases the new rule must handle:
- `selectCPU` → `select_cpu` (was `select_c_p_u`)
- `congAvoid` → `cong_avoid` (unchanged from current behaviour)
- `HTTPServer` → `http_server` (all-caps prefix followed by mixed case)
- `parseXMLDoc` → `parse_xml_doc` (all-caps middle segment)
- `ssthresh` → `ssthresh` (all lowercase — no change)
- `undoCwnd` → `undo_cwnd` (unchanged)

- [ ] **Step 1: Add a table-driven test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CamelToSnakeTest {

    @Test
    void handlesAcronyms() {
        assertThat(StructOpsValidator.camelToSnake("selectCPU")).isEqualTo("select_cpu");
        assertThat(StructOpsValidator.camelToSnake("congAvoid")).isEqualTo("cong_avoid");
        assertThat(StructOpsValidator.camelToSnake("HTTPServer")).isEqualTo("http_server");
        assertThat(StructOpsValidator.camelToSnake("parseXMLDoc")).isEqualTo("parse_xml_doc");
        assertThat(StructOpsValidator.camelToSnake("ssthresh")).isEqualTo("ssthresh");
        assertThat(StructOpsValidator.camelToSnake("undoCwnd")).isEqualTo("undo_cwnd");
        assertThat(StructOpsValidator.camelToSnake("schedInit")).isEqualTo("sched_init");
        assertThat(StructOpsValidator.camelToSnake("initTask")).isEqualTo("init_task");
    }
}
```

- [ ] **Step 2: Run — expect FAIL** on `selectCPU`, `HTTPServer`, `parseXMLDoc`.

- [ ] **Step 3: Replace the implementation**

```java
public static String camelToSnake(String s) {
    var sb = new StringBuilder(s.length() + 4);
    for (int i = 0; i < s.length(); i++) {
        char c = s.charAt(i);
        if (Character.isUpperCase(c)) {
            boolean atStart = i == 0;
            boolean prevLower = !atStart && Character.isLowerCase(s.charAt(i - 1));
            boolean nextLower = i + 1 < s.length() && Character.isLowerCase(s.charAt(i + 1));
            if (!atStart && (prevLower || nextLower)) {
                sb.append('_');
            }
            sb.append(Character.toLowerCase(c));
        } else {
            sb.append(c);
        }
    }
    return sb.toString();
}
```

The `nextLower` clause is the acronym-boundary rule: for `HTTPServer`, when we're at `S` (index 4), prev is `P` (upper), next is `e` (lower) → insert underscore. For `HTTPS` (imaginary continuation), when we're at `S` (last), prev is `P`, next doesn't exist → no underscore.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsValidator.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/CamelToSnakeTest.java
git commit -m "fix(plugin): camelToSnake groups acronym runs (selectCPU -> select_cpu)"
```

---

### Task 2c: `StructOpsDiscovery` — walk superclass chain for inherited overrides

**Files:**
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscovery.java`
- Modify: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscoveryTest.java` (extend if present, else create)

**Why this task exists:** `StructOpsDiscovery.collectOverriddenMethods` currently calls `bpfClass.getEnclosedElements()`, which returns only the class's **directly declared** methods. In-tree scheduler samples like `MinimalScheduler` inherit `init`, `exit`, `dispatch`, etc. from `SchedulerBase` (an abstract class), not by declaring them directly. Under the current discovery rule, these inherited overrides go undetected and the synthesizer emits no initializer line for them — the resulting `sched_ext_ops` struct is missing crucial callbacks and kernel attach fails.

The fix is to walk the superclass chain from `bpfClass` up to (but not including) `Object` / `BPFProgram`, collecting non-abstract methods at every level. A subclass override shadows a superclass override with the same signature — take the closest (most-derived) match.

- [ ] **Step 1: Failing test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.bpf.compiler.testutil.CompilerFixture;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StructOpsDiscoveryInheritanceTest {

    @Test
    void collectsOverridesInheritedFromAbstractSuperclass() {
        String src = """
            package p;
            import me.bechberger.ebpf.annotations.bpf.*;
            import me.bechberger.ebpf.annotations.bpf.StructOps;
            import me.bechberger.ebpf.bpf.BPFProgram;

            @StructOps("sched_ext_ops")
            interface Sched {
                default int schedInit() { return 0; }
                default int schedExit() { return 0; }
            }

            abstract class Base extends BPFProgram implements Sched {
                @Override public int schedInit() { return 0; }
                // schedExit stays defaulted
            }

            @BPF abstract class Derived extends Base {
                // Inherits Base.schedInit; no direct declaration.
            }
            """;
        var fixture = CompilerFixture.compile("p.Derived", src);
        var cls = fixture.getClass("p.Derived");
        var kinds = StructOpsDiscovery.discover(cls, fixture.env());
        assertThat(kinds).hasSize(1);
        var methodNames = kinds.get(0).overriddenMethods().stream()
                .map(m -> m.getSimpleName().toString())
                .toList();
        assertThat(methodNames).contains("schedInit").doesNotContain("schedExit");
    }
}
```

- [ ] **Step 2: Run — expect FAIL** (`schedInit` not in the list — only direct members walked).

- [ ] **Step 3: Extend `collectOverriddenMethods`**

Replace the single-level walk with a superclass-walking version:

```java
private static List<ExecutableElement> collectOverriddenMethods(
        TypeElement iface, TypeElement bpfClass, ProcessingEnvironment env) {
    var elements = env.getElementUtils();
    // Walk bpfClass and all its non-Object, non-BPFProgram ancestors, gathering
    // concrete methods. Closer-to-bpfClass declarations shadow farther ones.
    List<ExecutableElement> concreteChain = new ArrayList<>();
    TypeElement cursor = bpfClass;
    while (cursor != null) {
        String fqn = cursor.getQualifiedName().toString();
        if (fqn.equals("java.lang.Object")) break;
        for (ExecutableElement m : ElementFilter.methodsIn(cursor.getEnclosedElements())) {
            if (m.getModifiers().contains(Modifier.ABSTRACT)) continue;
            concreteChain.add(m);
        }
        TypeMirror sup = cursor.getSuperclass();
        cursor = (sup instanceof DeclaredType d) ? (TypeElement) d.asElement() : null;
    }
    List<ExecutableElement> out = new ArrayList<>();
    for (ExecutableElement m : ElementFilter.methodsIn(iface.getEnclosedElements())) {
        if (m.getModifiers().contains(Modifier.STATIC)) continue;
        for (ExecutableElement candidate : concreteChain) {
            if (!candidate.getSimpleName().contentEquals(m.getSimpleName())) continue;
            if (elements.overrides(candidate, m, (TypeElement) candidate.getEnclosingElement())) {
                out.add(m);
                break;   // most-derived wins (concreteChain is ordered bpfClass -> super)
            }
        }
    }
    return out;
}
```

Note the third argument to `elements.overrides(candidate, m, container)`: `container` must be the class where `candidate` is declared, not `bpfClass` (which was correct only when `candidate` was directly declared there). Passing `(TypeElement) candidate.getEnclosingElement()` handles both direct and inherited overrides.

- [ ] **Step 4: Extend `StructOpsSynthesizer.findConcreteMethod` similarly**

The synthesizer also needs to look up the concrete method for `@Sleepable` and data-field initializer purposes. `StructOpsSynthesizer.findConcreteMethod` currently walks `bpfClass.getEnclosedElements()` too. Apply the same superclass walk. Extract as a small private helper if the shape ends up duplicated in two places:

```java
private ExecutableElement findConcreteMethod(TypeElement bpfClass,
                                             ExecutableElement ifaceMethod) {
    TypeElement cursor = bpfClass;
    while (cursor != null) {
        String fqn = cursor.getQualifiedName().toString();
        if (fqn.equals("java.lang.Object")) break;
        for (ExecutableElement m : ElementFilter.methodsIn(cursor.getEnclosedElements())) {
            if (m.getModifiers().contains(Modifier.ABSTRACT)) continue;
            if (!m.getSimpleName().contentEquals(ifaceMethod.getSimpleName())) continue;
            if (m.getParameters().size() != ifaceMethod.getParameters().size()) continue;
            return m;
        }
        TypeMirror sup = cursor.getSuperclass();
        cursor = (sup instanceof DeclaredType d) ? (TypeElement) d.asElement() : null;
    }
    return null;
}
```

- [ ] **Step 5: Run — expect PASS**

Also re-run the existing `StructOpsSynthesizerTest` and Sub-plan B tests to confirm no regression on direct-override cases.

- [ ] **Step 6: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscovery.java
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscoveryInheritanceTest.java
git commit -m "feat(plugin): walk superclass chain when collecting @StructOps overrides"
```

---

### Task 2d: `@StructOps.emittedNamePrefix` SPI + synthesizer support

**Naming-convention decision: Option B1 — single `emittedNamePrefix` on the interface, retire the six `simple_*` symbols.**

The synthesizer previously emitted BPF function names as `<snake_case_field>`. To preserve existing framework symbol names (which the kernel doesn't care about — only `.field =` pointers in the struct instance matter for attach), extend `@StructOps` with a new field:

```java
/** Prefix prepended to each emitted BPF function name and to the ".field ="
 *  initializer's function-pointer reference. Default empty. Set to
 *  {@code "sched_"} on the sched-ext interface so emitted symbols match
 *  the existing scheduler C. */
String emittedNamePrefix() default "";
```

Sched-ext's `Scheduler` interface uses `emittedNamePrefix = "sched_"`. Every emitted function name becomes `sched_<field>` and every initializer line becomes `.<field> = (void *)sched_<field>`.

**Six historical `simple_*` symbols** (`simple_running`, `simple_enable`, `simple_disable`, `simple_stopping`, `simple_dequeue`, `simple_tick`) are renamed to `sched_running` etc. Grep confirms no in-tree consumer references them by name; trace_pipe output for those callbacks will show `sched_running` instead of `simple_running` going forward.

**Prerequisite tasks 2b + 2c already extend the synthesizer** for acronym-safe snake_case and superclass-walking discovery; Task 2d adds the `emittedNamePrefix` SPI; Task 3 layers on top.

---

**Files:**
- Modify: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/StructOps.java`
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsSynthesizer.java`
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsDiscovery.java` (thread prefix into `Kind` record)
- Test: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/EmittedNamePrefixTest.java`

**Contract:** if `emittedNamePrefix` is set (non-empty):
- The emitted BPF function name is `<prefix><snake_case_field>` (was: `<snake_case_field>`).
- The initializer line becomes `.<field> = (void *)<prefix><field>`.
- The `@BPFFunction(name = ...)` annotation on the proxy uses the prefixed name so `$name` in the header template resolves consistently.

- [ ] **Step 1: Add the annotation field** to `StructOps.java`:

```java
/** Prefix prepended to each emitted BPF function name and to the corresponding
 *  {@code .field = (void *)<name>} initializer entry. Default empty.
 *
 *  <p>Set to {@code "sched_"} on the sched-ext {@code Scheduler} interface so
 *  emitted symbols match the pre-@StructOps scheduler C exactly. The kernel
 *  doesn't care about emitted C function names — only the field pointers in
 *  the struct instance matter for attach — but preserving symbol names avoids
 *  a spurious diff in trace_pipe output and in {@code .c} files consumers may
 *  have inspected. */
String emittedNamePrefix() default "";
```

- [ ] **Step 2: Thread it through `Kind`**

Add `String emittedNamePrefix` to `StructOpsDiscovery.Kind`. Populate from `ann.emittedNamePrefix()` in `discover(...)`.

- [ ] **Step 3: Apply in `StructOpsSynthesizer.synthesize(...)`**

Replace the two sites that use bare `fieldName` for the emitted symbol:

```java
String emittedName = kind.emittedNamePrefix() + fieldName;
functions.add(new SynthFunction(target, makeProxy(section, header, emittedName)));
initializerLines.add("    ." + fieldName + " = (void *)" + emittedName);
```

`fieldName` still drives the BTF-field-name side; only the pointer target changes.

- [ ] **Step 4: Tests** in `EmittedNamePrefixTest.java`:

```java
@Test
void prefixAppliedToEmittedSymbolAndInitializer() {
    String src = """
        package p;
        import me.bechberger.ebpf.annotations.bpf.*;
        import me.bechberger.ebpf.annotations.bpf.StructOps;
        import me.bechberger.ebpf.bpf.BPFProgram;
        @StructOps(value = "sched_ext_ops", emittedNamePrefix = "sched_")
        interface Sched {
            default int init() { return 0; }
        }
        @BPF abstract class S extends BPFProgram implements Sched {
            @Override public int init() { return 0; }
        }
        """;
    var fixture = CompilerFixture.compile("p.S", src);
    var cls = fixture.getClass("p.S");
    var kinds = StructOpsDiscovery.discover(cls, fixture.env());
    var result = new StructOpsSynthesizer(fixture.env()).synthesize(cls, kinds);
    assertThat(result.functions().get(0).bpfFunction().name())
            .isEqualTo("sched_init");
    assertThat(result.instances().get(0).cSource())
            .contains(".init = (void *)sched_init");
}

@Test
void emptyPrefixLeavesNamesUnchanged() { /* tcp_congestion_ops case */ }
```

- [ ] **Step 5: No standalone commit — batched with Task 3 (see "Batching strategy" below).**

---

### Task 3: Convert `Scheduler` to `@StructOps` — annotation flip + `@Sleepable` on `sched_init`

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java`
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/SchedulerBase.java`

**Java-method rename plan:** Java method names on the interface must be the pure `snake_case_field` in camelCase form, WITHOUT the `sched` prefix, so that `emittedNamePrefix + snake_case = <existing symbol>`. Example: what's currently `schedInit` becomes `init` on the interface (`sched_` + `init` = `sched_init`). Existing methods without the prefix (`selectCPU`, `enqueue`, `dispatch`, etc.) stay as-is.

**Rename table:**

| Currently emitted C     | Was Java method   | New Java method   | New snake_case_field       | New emitted C           |
|-------------------------|-------------------|-------------------|----------------------------|-------------------------|
| `sched_init`            | `schedInit`       | `init`            | `init`                     | `sched_init`            |
| `sched_exit`            | `schedExit`       | `exit`            | `exit`                     | `sched_exit`            |
| `sched_select_cpu`      | `selectCPU`       | `selectCPU`       | `select_cpu` (via Task 2b) | `sched_select_cpu`      |
| `sched_enqueue`         | `enqueue`         | `enqueue`         | `enqueue`                  | `sched_enqueue`         |
| `sched_dispatch`        | `dispatch`        | `dispatch`        | `dispatch`                 | `sched_dispatch`        |
| `sched_update_idle`     | `updateIdle`      | `updateIdle`      | `update_idle`              | `sched_update_idle`     |
| `sched_init_task`       | `initTask`        | `initTask`        | `init_task`                | `sched_init_task`       |
| `sched_runnable`        | `runnable`        | `runnable`        | `runnable`                 | `sched_runnable`        |
| `simple_running` **(!)**| `running`         | `running`         | `running`                  | `sched_running`         |
| `simple_enable` **(!)** | `enable`          | `enable`          | `enable`                   | `sched_enable`          |
| `simple_disable` **(!)**| `disable`         | `disable`         | `disable`                  | `sched_disable`         |
| `simple_stopping` **(!)**| `stopping`       | `stopping`        | `stopping`                 | `sched_stopping`        |
| `simple_dequeue` **(!)**| `dequeue`         | `dequeue`         | `dequeue`                  | `sched_dequeue`         |
| `simple_tick` **(!)**   | `tick`            | `tick`            | `tick`                     | `sched_tick`            |
| (all remaining `sched_*` methods: Java name is the field-name camelCase, symbol pattern is uniform) |||||

The 6 `simple_*` symbols become `sched_*`. Grep confirmed no in-tree consumer references any of them by name; trace_pipe output for those callbacks changes accordingly.

- [ ] **Step 1: Snapshot the pre-migration generated C**

Before touching `Scheduler.java`, on thinkstation, capture the *currently* emitted C for a canonical implementation:

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-samples -am compile -DskipTests 2>&1 | tail -10'
ssh thinkstation 'find /home/i560383/code/experiments/hello-ebpf/bpf-samples/target/generated-sources \
  -name "MinimalScheduler*.c" 2>/dev/null | head'
ssh thinkstation 'cp <the file path from previous command> /tmp/minimal-pre.c'
```

Copy `/tmp/minimal-pre.c` back to the local mac for the parity test in Task 5.

- [ ] **Step 2: Edit `Scheduler.java`**

At the top of the interface, before `@BPFInterface`:

```java
@me.bechberger.ebpf.annotations.bpf.StructOps(
        value = "sched_ext_ops",
        instanceName = "sched_ops")
```

Remove the `after = """ SCX_OPS_DEFINE(...) """` clause of the existing `@BPFInterface` annotation. Keep the `before = """..."""` clause verbatim — it still emits kfunc externs, `__arena`, `__ulong`, `BPF_STRUCT_OPS`, `SCX_OPS_DEFINE`, `BPF_STRUCT_OPS_SLEEPABLE`, `BPF_FOR_EACH_ITER` macros. Those aren't obsolete: `SCX_OPS_DEFINE` is a widely-used macro other user code might expand, and `BPF_STRUCT_OPS_SLEEPABLE` is still what the plugin will need to reference indirectly if a user hand-writes a `struct_ops.s/` section. Leave `@PropertyDefinition` annotations alone.

Find `sched_init` (search Scheduler.java for `sched_init` — should have `@BPFFunction(section = "struct_ops.s/sched_init", …)` or similar in its current declaration). Replace the manual `section = "struct_ops.s/sched_init"` with plain `@Override` on the concrete class side + `@Sleepable` marker on the method. The interface declaration of `schedInit` should NOT carry `@BPFFunction` anymore — that's the synthesizer's job now. Concrete overriders that want the sleepable variant tag `@Sleepable` at the override site.

For discovery: the interface currently declares `schedInit` with a `headerTemplate = "s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init)"`. Remove the header override — the synthesizer produces `s32 BPF_PROG(sched_init, …)` by default. Wrap-macro switching (`BPF_PROG` vs `BPF_STRUCT_OPS_SLEEPABLE`) is not needed at the C level because both expand to the same `SEC("…") BPF_PROG(…)` shape — the section prefix alone (which `@Sleepable` controls) is what the kernel/libbpf reads.

- [ ] **Step 3: Delete or shim `attachScheduler()`**

Per the spec's migration window (line 576-579): keep as a no-op deprecated wrapper for one release.

```java
/**
 * @deprecated  Retained as a no-op for source compatibility.
 *              {@link BPFProgram#load(Class)} now attaches struct_ops
 *              automatically via {@link me.bechberger.ebpf.bpf.structops.StructOpsAttach}.
 *              Delete callers in your codebase; this method will be
 *              removed in the release after next.
 */
@Deprecated(since = "0.2", forRemoval = true)
default void attachScheduler() {
    // No-op: BPFProgram.load(Class) already invoked StructOpsAttach.attachAll(this)
    // and populated structOpsInfo().  Warn once via javac's @Deprecated
    // mechanism — no runtime warning to keep log noise down for schedulers
    // that pipeline through this in tight loops.
}
```

Keep `runSchedulerLoop()` unchanged — it still calls `attachScheduler()`, which is now the no-op, so behaviour is equivalent to just `waitWhileSchedulerIsAttachedProperly()`. Simplify to drop the `attachScheduler()` call:

```java
default void runSchedulerLoop() {
    // struct_ops is already attached by BPFProgram.load().
    waitWhileSchedulerIsAttachedProperly();
}
```

- [ ] **Step 4: Rebuild plugin + bpf jars (per feedback memory)**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin,bpf -am install -DskipTests 2>&1 | tail -10'
```

Expected: BUILD SUCCESS.

- [ ] **Step 5: Regenerate the C for `MinimalScheduler` and inspect**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-samples -am compile -DskipTests 2>&1 | tail -10'
ssh thinkstation 'find /home/i560383/code/experiments/hello-ebpf/bpf-samples/target/generated-sources \
  -name "MinimalScheduler*.c" | xargs cat' > /tmp/minimal-post.c
diff /tmp/minimal-pre.c /tmp/minimal-post.c
```

Expected: the only differences are (a) macro-comment ordering (harmless) and (b) the `SCX_OPS_DEFINE(...)` block moving from the `after` template to a `SEC(".struct_ops.link") struct sched_ext_ops sched_ops = { … };` block emitted post-methods by the synthesizer. All `.field = (void *)fn` lines and property placeholders should be present. If any `.field = (void *)X` is missing that was present pre-migration, the layout JSON is missing that field — fix in Sub-plan A's layout regeneration, not here.

- [ ] **Step 6: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java
git commit -m "refactor(sched): retarget Scheduler at @StructOps pipeline, deprecate attachScheduler"
```

---

### Task 3d: Documentation pass — `@StructOps` + `@Sleepable` code examples, per-method sched-ext Javadoc

**Files:**
- Modify: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/StructOps.java` — expand class Javadoc with runnable code examples for all four supported kinds (sched-ext, TCP CC, Qdisc, HID); document each field with example values.
- Modify: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/Sleepable.java` — expand Javadoc with a concrete `@Override @Sleepable public int init() { … }` example and cross-link to `@StructOps`.
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java` — every sched-ext callback method gets a research-derived Javadoc describing: when the kernel invokes it, what the args mean, return-value semantics, non-sleepable/sleepable contract, and a one-line example use case. Pull from `include/linux/sched/ext.h`, `kernel/sched/ext.c`, and `Documentation/scheduler/sched-ext.rst` in the upstream kernel tree.

**Why this task exists:** The current in-tree Javadoc on scheduler callbacks is sparse and often just restates the method name. For an `@StructOps` public API to be usable without reading kernel source, each callback needs a paragraph explaining its role in the scheduler lifecycle. Same for `@StructOps` itself — a user encountering the annotation for the first time should see a full working example, not an abstract description.

**Approach: subagent research pass.** For each of the ~34 sched-ext callbacks:
1. Look up the kernel header comment on the matching `struct sched_ext_ops` field.
2. Look up the call site in `kernel/sched/ext.c` for the calling context.
3. Cross-reference `Documentation/scheduler/sched-ext.rst` for prose explanation.
4. Write 3-6 lines of Javadoc: what it's for, when it's called, what to return.

The kernel is at v6.14+ (thinkstation's floor); pin research to that revision. Where a callback is optional and un-overriding is the common case, say so explicitly.

- [ ] **Step 1: `@StructOps` Javadoc**

Rewrite the class Javadoc to include a working example for each kind. Draft:

```java
/**
 * Marks an interface as the Java mirror of a kernel {@code bpf_struct_ops}
 * table. …
 *
 * <h2>Example: TCP congestion control</h2>
 * <pre>{@code
 * @StructOps("tcp_congestion_ops")
 * public interface TcpCongestionControl {
 *     default int ssthresh(Ptr<sock> sk) { return 4; }
 *     default void congAvoid(Ptr<sock> sk, int ack, int acked) {}
 *     default String name() { return "myalgo"; }
 * }
 *
 * @BPF
 * public abstract class MyCc extends BPFProgram implements TcpCongestionControl {
 *     @Override public int ssthresh(Ptr<sock> sk) { return 4; }
 *     @Override public void congAvoid(Ptr<sock> sk, int ack, int acked) {
 *         BPFJ.bpf_printk("myalgo ack=%u acked=%u", ack, acked);
 *     }
 *     @Override public String name() { return "myalgo"; }
 * }
 *
 * try (var prog = BPFProgram.load(MyCc.class)) {
 *     // "myalgo" now appears in /proc/sys/net/ipv4/tcp_available_congestion_control
 *     Thread.sleep(Long.MAX_VALUE);
 * }
 * }</pre>
 *
 * <h2>Example: sched-ext</h2>
 * <pre>{@code
 * @StructOps(value = "sched_ext_ops", instanceName = "sched_ops", emittedNamePrefix = "sched_")
 * public interface Scheduler {
 *     @Sleepable default int init() { return 0; }
 *     default int enqueue(Ptr<task_struct> p, long enqFlags) { … }
 *     …
 * }
 * }</pre>
 *
 * <h2>Fields</h2>
 * (Existing per-field Javadoc for value/sectionPrefix/instanceName/emittedNamePrefix,
 * each with a one-line example.)
 */
```

Add similar snippets for `Qdisc_ops` and `hid_bpf_ops`.

- [ ] **Step 2: `@Sleepable` Javadoc**

Extend with:

```java
/**
 * …existing text…
 *
 * <h2>Example</h2>
 * <pre>{@code
 * @BPF
 * public abstract class MyScheduler extends BPFProgram implements Scheduler {
 *     @Override
 *     @Sleepable
 *     public int init() {
 *         // Sleepable context — may call bpf_kfunc_alloc_and_move_arena_area, etc.
 *         return 0;
 *     }
 * }
 * }</pre>
 *
 * <p>Only kernel struct_ops slots that carry the sleepable BTF flag can
 * accept a sleepable program. As of kernel 6.14, sched-ext's {@code init}
 * is the only widely-used sleepable slot; others may follow.
 */
```

- [ ] **Step 3: Per-method Javadoc on `Scheduler.java`**

Dispatch a research subagent (see Subagent Prompt below) to produce Javadoc drafts for all ~34 methods. Review each draft: verify calling context, argument semantics, and return-value rules against the kernel source and scx docs. Edit the file in place.

For each method the Javadoc should cover:
1. **What the callback is for** in one sentence.
2. **When the kernel calls it** — trigger and calling context (sleepable? IRQ-safe? preemptible?).
3. **What the arguments mean** — one line per non-trivial arg.
4. **What to return** and what the return value controls.
5. **Whether it's optional** and what happens if you don't override it.

Example (for `select_cpu`, which currently has a paragraph but is a good template):

```java
/**
 * Pick a target CPU for a waking task before it enqueues.
 *
 * <p>Called during {@code sched_class::select_task_rq}. Returning a valid
 * CPU number places the task on that CPU's local DSQ (SCX_DSQ_LOCAL) if
 * {@code SCX_ENQ_HEAD} is included in the returned flags; returning
 * {@code prev_cpu} keeps the task where it was.
 *
 * @param p          the waking task
 * @param prev_cpu   the CPU the task last ran on
 * @param wake_flags kernel wake-up flags ({@code WF_TTWU}, {@code WF_FORK}, …)
 * @return the chosen CPU number, or {@code prev_cpu} to keep affinity
 *
 * <p>Non-sleepable. Called with preemption disabled. If not overridden,
 * the kernel picks {@code prev_cpu}.
 */
```

- [ ] **Step 4: Subagent Prompt** (research-only, produces Javadoc drafts as its output — controller applies them)

```
Research each sched_ext_ops callback and produce a Javadoc paragraph for each. Kernel is v6.14+; pin research to that. For each Java method listed below, output a Javadoc block covering:

  1) One-sentence purpose.
  2) Trigger: what kernel event causes the call. Include the call site
     (e.g. "called from ttwu_do_wakeup" or "invoked when a task on this
     runqueue is about to sleep").
  3) Sleepable vs non-sleepable context; whether preemption is disabled.
  4) Per-argument semantics for any non-trivial arg. Ignore obvious args
     like `struct task_struct *p`.
  5) Return-value contract. If void, note any side-effect expectations.
  6) Optional-or-required: if it's optional, note the kernel default.

Sources: prefer the header comment on the matching field in
`include/linux/sched/ext.h` first; then the call site in
`kernel/sched/ext.c`; then Documentation/scheduler/sched-ext.rst. Cite
each source with a file:line. Do NOT paraphrase Documentation as if it's
your own — quote it directly if you're using its exact wording.

Java methods on `Scheduler` after Task 3 rename (list all ~34 from the
rename table). For each, produce a Javadoc block. Keep it to 6-10 lines
each; don't pad. If you find no meaningful documentation for a method,
say so explicitly — a "no upstream doc; see kernel/sched/ext.c:1234"
pointer is more useful than fabricated prose.

Return all Javadoc blocks in a single output file so the controller can
paste them into Scheduler.java. Under 4000 words total.
```

- [ ] **Step 5: Apply the subagent's Javadoc drafts to `Scheduler.java`**

Read the subagent's output; for each method, replace the existing Javadoc (if any) with the researched version. Preserve any implementation-specific notes already in-tree that the subagent's kernel-focused research would have missed.

- [ ] **Step 6: No standalone commit — bundled into the Task 3 batch (see Batching strategy).**

---

### Task 4: Update in-tree callers of `attachScheduler()`

**Files:**
- Modify: `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerExtension.java:87`
- Modify: `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerBehaviorTest.java:350`
- Modify: `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerSmokeTest.java:102,114,204,238`
- Modify: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/SampleScheduler.java:296`
- Modify: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LockHolderBoostScheduler.java:354`
- Modify: any other `attachScheduler()` callers surfaced by the grep

- [ ] **Step 1: Grep for all callers**

```
grep -rn "attachScheduler\b" bpf-samples/src bpf/src --include="*.java"
```

Confirm the file/line list matches the modified-files list above; if new callers landed, add them.

- [ ] **Step 2: Remove each call**

Replace each `sched.attachScheduler();` / `program.attachScheduler();` with either (a) deletion (the call is now redundant), or (b) an `assertThat(prog.structOpsInfo()).extracting("kernelName").containsExactly("sched_ext_ops");` where the test previously asserted attach happened. Prefer (b) in tests, (a) in `main` methods and framework glue.

Specific edits:

- `SchedulerExtension.java:87`: replace `((Scheduler) program).attachScheduler();` with a no-op comment: `// struct_ops attached by BPFProgram.load()` (deletion). The extension's contract is already "load and prepare"; the load path now does the attach.

- `SchedulerSmokeTest.java:102, 114, 204, 238`: delete the four `sched.attachScheduler();` calls. Add an assertion at test start-of-scope:
  ```java
  assertThat(sched.structOpsInfo())
      .as("Scheduler was auto-attached by BPFProgram.load")
      .extracting("kernelName").containsExactly("sched_ext_ops");
  ```
  Add it inside the `try` block that follows `BPFProgram.load(...)`, only in one representative test to avoid duplication — the other tests just delete the call.

- `SchedulerBehaviorTest.java:350`: same treatment — delete the call.

- `SampleScheduler.java:296`: delete the call. `main` already goes into `waitWhileSchedulerIsAttachedProperly()` immediately after.

- `LockHolderBoostScheduler.java:354`: delete the call.

- [ ] **Step 3: Rebuild + run scheduler smoke tests on thinkstation**

```
rsync -avz --delete --exclude=.git --exclude=target ./ thinkstation:/home/i560383/code/experiments/hello-ebpf/
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf-samples SchedulerSmokeTest 2>&1 | tail -30'
```

Expected: PASS — same pass-count and dispatch counts as pre-migration.

If a scheduler that used to attach cleanly now fails to attach: check the generated `.c` for missing initializer lines (some `.field = (void *)fn` you had before is not there now). Root cause is almost always a missing entry in `sched_ext_ops.json` (Sub-plan A). Fix the layout, don't patch around it here.

- [ ] **Step 4: Run additional scheduler smokes**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf-samples SchedulerBehaviorTest 2>&1 | tail -30'
```

Then run one representative sample scheduler through `mvn exec:java`:

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf-samples MinimalSchedulerSample 2>&1 | tail -25'
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerExtension.java
git add bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerBehaviorTest.java
git add bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerSmokeTest.java
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/SampleScheduler.java
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/LockHolderBoostScheduler.java
git commit -m "refactor(samples): drop explicit attachScheduler() calls — @StructOps auto-attaches"
```

---

### Task 5: Codegen-parity regression test

**Files:**
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/SchedulerCodegenParityTest.java`
- Create: `bpf/src/test/resources/scheduler-parity/minimal-scheduler-expected.c` — the *post-migration* golden.

The parity test asserts the generated C for a canonical `MinimalScheduler` matches a checked-in golden after a normalization pass (whitespace and comment-line order). If a future plugin change breaks the initializer shape or field ordering, this test catches it before it hits any real scheduler test.

- [ ] **Step 1: After Task 4 passes cleanly, save the working `MinimalScheduler.c` as the golden**

```
ssh thinkstation 'find /home/i560383/code/experiments/hello-ebpf/bpf-samples/target/generated-sources \
  -name "MinimalScheduler*.c" | xargs cat' > /tmp/minimal-scheduler-golden.c
# Copy back to local:
scp thinkstation:/tmp/minimal-scheduler-golden.c \
    bpf/src/test/resources/scheduler-parity/minimal-scheduler-expected.c
```

Inspect the file for obvious junk before committing (temp paths, absolute directories, build timestamps). Strip any of those with `sed` / a manual edit.

- [ ] **Step 2: Write the test**

```java
package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Locks the shape of the C generated for a canonical sched-ext scheduler
 * against a checked-in golden. A change to the plugin's struct-ops
 * initializer format or field ordering has to update the golden as an
 * explicit part of the change.
 */
class SchedulerCodegenParityTest {

    @Test
    void minimalSchedulerMatchesGolden() throws Exception {
        // The @BPF pipeline emits the C into
        // ../bpf-samples/target/generated-sources/annotations/…/MinimalSchedulerImpl.c
        // during bpf-samples compile.  Locate it via classpath resource or a
        // scan; the exact path depends on the annotation-processor Filer output
        // convention — see how existing generated-C tests in this repo do it
        // (grep for readGeneratedC or similar in bpf/src/test).
        Path generated = LocateGeneratedC.find("MinimalSchedulerImpl.c");
        String actual = normalise(Files.readString(generated));

        Path goldenPath = Path.of(
            "src/test/resources/scheduler-parity/minimal-scheduler-expected.c");
        String expected = normalise(Files.readString(goldenPath));

        assertThat(actual).isEqualTo(expected);
    }

    /** Strips blank lines, trailing spaces, and preserves everything else. */
    private static String normalise(String s) {
        return s.lines()
                .map(String::stripTrailing)
                .filter(l -> !l.isBlank())
                .collect(Collectors.joining("\n"));
    }
}
```

`LocateGeneratedC` is a small utility — grep first for an existing helper in this repo (e.g. `bpf-compiler-plugin-test` has one; if not, add a tiny class):

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/LocateGeneratedC.java
package me.bechberger.ebpf.bpf;

import java.nio.file.*;
import java.util.stream.Stream;

final class LocateGeneratedC {
    static Path find(String fileName) {
        Path root = Path.of("../bpf-samples/target/generated-sources");
        if (!Files.exists(root)) {
            throw new IllegalStateException(
                    "bpf-samples not compiled — run `mvn -pl bpf-samples compile` first");
        }
        try (Stream<Path> stream = Files.walk(root)) {
            return stream.filter(p -> p.getFileName().toString().equals(fileName))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("not found: " + fileName));
        } catch (java.io.IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
```

- [ ] **Step 3: Run — expect PASS** (golden was just captured from the same pipeline)

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf -Dtest=SchedulerCodegenParityTest test 2>&1 | tail -20'
```

- [ ] **Step 4: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/SchedulerCodegenParityTest.java
git add bpf/src/test/java/me/bechberger/ebpf/bpf/LocateGeneratedC.java
git add bpf/src/test/resources/scheduler-parity/minimal-scheduler-expected.c
git commit -m "test(sched): codegen-parity golden for MinimalScheduler post-migration"
```

---

### Task 6: Scheduler `structOpsInfo()` coverage in a smoke test

**Files:**
- Modify: `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerSmokeTest.java` (one representative test)

Assert that the real, kernel-attached `MinimalScheduler` populates `prog.structOpsInfo()` with the expected `kernelName="sched_ext_ops"` and `mapName="sched_ops"`.

- [ ] **Step 1: Extend one existing test method to include the assertion**

Find the first test method in `SchedulerSmokeTest.java` that loads a `MinimalScheduler`. After `BPFProgram.load(MinimalScheduler.class)`, add:

```java
var info = sched.structOpsInfo();
assertThat(info).hasSize(1);
assertThat(info.get(0).kernelName()).isEqualTo("sched_ext_ops");
assertThat(info.get(0).mapName()).isEqualTo("sched_ops");
assertThat(info.get(0).mapFd()).isPositive();
assertThat(info.get(0).bpfLinkId()).isNotZero();
```

- [ ] **Step 2: Run on thinkstation vng**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf-samples SchedulerSmokeTest 2>&1 | tail -30'
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add bpf-samples/src/test/java/me/bechberger/ebpf/bpf/SchedulerSmokeTest.java
git commit -m "test(sched): assert structOpsInfo populated for MinimalScheduler"
```

---

## Verification

**End-to-end acceptance:**

1. **Plugin unit tests** (mac OK):
   ```
   mvn -pl bpf-compiler-plugin-test test
   ```
   All new + all existing `structops.*` tests pass. Specifically the new `SleepableMarkerTest` and `PropertyPassthroughTest`.

2. **`bpf` module tests** including parity (thinkstation):
   ```
   ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
     PATH=/home/i560383/.local/bin:$PATH \
     ./scripts/run-tests-vng.sh bpf SchedulerCodegenParityTest 2>&1 | tail -20'
   ```
   PASS.

3. **Scheduler smoke suite** (thinkstation vng): both `SchedulerSmokeTest` and `SchedulerBehaviorTest` pass with the same or improved pass counts vs pre-migration.

4. **Every scheduler sample compiles**:
   ```
   ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
     HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
     mvn -pl bpf-samples compile -DskipTests 2>&1 | tail -10'
   ```
   BUILD SUCCESS.

5. **Generated C inspection** (thinkstation): after full build, open the generated `.c` for `MinimalSchedulerImpl` and confirm:
   - `SEC("struct_ops.s/sched_init")` above the sched_init body (was `struct_ops.s/sched_init` in the manual `@BPFFunction` too — should be identical).
   - `SEC("struct_ops/select_cpu")`, `SEC("struct_ops/enqueue")`, etc. for the non-sleepable methods.
   - One `SEC(".struct_ops.link") struct sched_ext_ops sched_ops = { … };` block near the end of the file, containing every `.field = (void *)fn` line the pre-migration file had.
   - Property placeholders (`__property_extra_flags`, `__property_timeout_ms`, `"__property_sched_name"`) present in the initializer.

## Rollback

If Task 4 uncovers a smoke-test failure that traces to a missing `sched_ext_ops.json` field (Sub-plan A's layout is incomplete), the fix belongs in Sub-plan A, not here. `git revert` the Task 3 + Task 4 commits, land the layout fix in Sub-plan A's follow-up, then re-cherry-pick these two commits. Don't hack around the missing field with a hardcoded override — the `PROPERTY_OVERRIDES` table is only for the runtime-substituted placeholders (`flags`, `timeout_ms`, `name`), not for missing struct fields.

## Out of scope (deferred)

- **Actually removing `attachScheduler()`** (rather than deprecating it). Deferred one release per spec §10.
- **HelloCubicSample / new consumers.** Sub-plan D.
- **Layout regeneration script updates.** If the sched_ext BTF changes upstream (a new field), regenerating `sched_ext_ops.json` from the extract script (Sub-plan A) picks it up automatically; the migration commit doesn't need to encode that.
- **`Sleepable` on other kinds** (e.g. QdiscOps has some sleepable methods). Add case-by-case as those kinds land in Sub-plan D.
