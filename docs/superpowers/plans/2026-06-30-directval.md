# `Ptr.directVal()` + Inline-C Builtin Removal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace three inline-C `@BuiltinBPFFunction` shims in `UserspaceSchedulerBase` with pure-Java equivalents by introducing `Ptr.directVal()` (a CO-RE-suppressing sibling of `val()`), generalising `@BPFJavaInline` to work on any class, and teaching `bpf-gen` to emit `@TrustedPtr` on kfunc parameters that need it.

**Architecture:** `Ptr.directVal()` is a Java-side method whose body is just `return val();` annotated `@BPFJavaInline`. Because the compiler plugin's `stripPtrVal()` only matches the literal method name `"val"`, a `directVal()` call inlines to `(*p)` but is *not* lifted to `BPF_CORE_READ` — so subsequent `MemberSelect` accesses emit direct field reads (`p->field`), preserving the trusted-pointer annotation required by kfuncs like `bpf_cpumask_test_cpu`. A plugin-side structural check forbids stray `directVal()` calls (must be followed by `MemberSelect`, or guarded by `@TrustedPtr` / `@AllowDirectVal`). `bpf-gen` learns to emit `@TrustedPtr` on `Ptr<cpumask>` parameters so the marker survives `BpfDefinitions.java` regeneration.

**Tech Stack:** Java 25, javac compiler plugin (`bpf-compiler-plugin`), JavaPoet (`bpf-gen`), JUnit 5, sched_ext + vng for kernel-load integration tests.

**Build & test discipline:** Builds and tests run only on thinkstation. Use `ssh thinkstation` with `HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn`. For vng-required tests, prefix `PATH=/home/i560383/.local/bin:$PATH` and pass `-Dmaven.test.skip=false -DskipTests=false`. Any plugin change requires a `bpf` module rebuild (jar-with-dependencies bundles stale plugin classes). Use `-Dshow.warnings=true` (or equivalent) when checking for plugin diagnostics.

---

## File Structure

**New files:**
- `annotations/src/main/java/me/bechberger/ebpf/annotations/TrustedPtr.java` — `@Target(PARAMETER)`, source-retention marker
- `annotations/src/main/java/me/bechberger/ebpf/annotations/AllowDirectVal.java` — `@Target({LOCAL_VARIABLE, METHOD})`, source-retention escape hatch
- `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/BPFJavaInlineGeneralisationTest.java` — generalisation unit tests
- `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/DirectValTest.java` — directVal unit tests
- `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/DirectValTaskCpuAllowedTest.java` — vng-only integration test
- `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/DirectValTaskCpuAllowedScheduler.java` — minimal scheduler used by the integration test

**Modified files:**
- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/Translator.java` — lift `@BPFAbstraction` gate, rename `tryInlineAbstractionMethod` → `tryInlineJavaInlineMethod`, gate carrier-field substitution, route `this` through `localCarrierMap`, extend `stripPtrVal()` to match `directVal`, add structural check at `MethodInvocationTree` emission site
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFJavaInline.java` — Javadoc update (no `@BPFAbstraction` implication)
- `bpf-processor/src/main/java/me/bechberger/ebpf/type/Ptr.java` — add `directVal()`
- `bpf-gen/src/main/java/me/bechberger/ebpf/gen/Generator.java` — emit `@TrustedPtr` on `Ptr<cpumask>` parameters (or based on helper-defs metadata)
- `bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/BpfDefinitions.java` — regenerated; `bpf_cpumask_test_cpu` second param gains `@TrustedPtr`
- `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java` — delete `taskCpuIsAllowed`, `arena_or_assign`, `arena_and_assign`; rewrite callers in Java
- `bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java` — `tryDispatchToLocalCpu` migrated to `p.directVal().cpus_ptr`
- `bpf/src/main/java/me/bechberger/ebpf/bpf/sched/DispatchQueue.java` — Javadoc snippet on line 341 updated
- `bpf-samples/.../LotteryScheduler.java` (line 41) — migrated to `p.directVal().cpus_ptr`

**Responsibility split:**
- Annotations module owns marker types (no plugin coupling).
- `bpf-gen` owns generator-side `@TrustedPtr` placement (keeps regeneration safe).
- `Translator.java` owns one new piece of policy: when CO-RE lifting is suppressed, and how `@BPFJavaInline` bodies are inlined when there is no `@BPFAbstraction` carrier map.
- `Ptr.directVal()` is a 4-line surface that delegates entirely to the plugin.

---

## Task 1 — Add `@TrustedPtr` and `@AllowDirectVal` annotations

**Files:**
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/TrustedPtr.java`
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/AllowDirectVal.java`

- [ ] **Step 1: Create `TrustedPtr.java`**

```java
package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Marker for kfunc parameter declarations that require a trusted pointer.
 * When this annotation is present on a parameter, {@code Ptr.directVal()}
 * may be used in the argument expression without raising a plugin diagnostic,
 * even if the result is not immediately followed by a field access.
 *
 * <p>This is purely documentary metadata; the BPF runtime does not see this
 * annotation. The compiler plugin reads it during structural validation of
 * {@code directVal()} call sites.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.SOURCE)
public @interface TrustedPtr {
}
```

- [ ] **Step 2: Create `AllowDirectVal.java`**

```java
package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Escape hatch for {@code Ptr.directVal()}. Annotate a local variable
 * declaration or an enclosing {@code @BPFFunction}-annotated method to
 * silence the plugin's structural check that {@code directVal()} must be
 * followed by a field access.
 */
@Target({ElementType.LOCAL_VARIABLE, ElementType.METHOD})
@Retention(RetentionPolicy.SOURCE)
public @interface AllowDirectVal {
}
```

- [ ] **Step 3: Build annotations module on thinkstation**

Run:
```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl annotations -am install -DskipTests'
```

Expected: BUILD SUCCESS. The two new types compile cleanly with no warnings.

- [ ] **Step 4: Commit**

```bash
git add annotations/src/main/java/me/bechberger/ebpf/annotations/TrustedPtr.java \
        annotations/src/main/java/me/bechberger/ebpf/annotations/AllowDirectVal.java
git commit -m "feat(annotations): add @TrustedPtr and @AllowDirectVal markers"
```

---

## Task 2 — Generalise `@BPFJavaInline` in Translator: failing tests first

**Files:**
- Create: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/BPFJavaInlineGeneralisationTest.java`

- [ ] **Step 1: Locate the existing `@BPFAbstraction + @BPFJavaInline` test for reference**

Run:
```
grep -rn "BPFJavaInline" /Users/i560383_1/code/experiments/hello-ebpf/bpf-compiler-plugin-test/src/test/java/ | head -20
```

Use the discovered pattern (likely in `BPFAbstractionTest.java`) as the template for fixtures: a small `@BPF` class compiled in-memory with the plugin enabled, then the generated C asserted via a string-contains check.

- [ ] **Step 2: Write the four failing tests**

The four cases enumerated in the spec — `javaInlineWorksOnNonAbstractionClass`, `javaInlineFieldSubstitutionStillRequiresAbstraction`, `javaInlineCarrierSubstitutionStillWorksOnAbstraction`, `javaInlineThisSubstitution`.

Use this skeleton (adapt fixture-loading helpers to whatever the existing test class uses):

```java
package me.bechberger.ebpf.bpf.compiler;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFJavaInlineGeneralisationTest {

    @Test
    void javaInlineWorksOnNonAbstractionClass() {
        // Fixture: a plain class (no @BPFAbstraction) with a @BPFJavaInline instance
        // method that calls another method. A @BPF program calls it from a @BPFFunction.
        // Assert: the called body is inlined at the call site (statement-expression),
        // not emitted as a separate C function call.
        String c = compileAndGetGeneratedC(NonAbstractionInlineFixture.class);
        assertTrue(c.contains("({") && c.contains("})"),
                "Expected GNU statement expression from inlined body; got:\n" + c);
        assertFalse(c.contains("nonAbstractionHelper("),
                "Inlined body should not appear as a separate function call");
    }

    @Test
    void javaInlineFieldSubstitutionStillRequiresAbstraction() {
        // Fixture: a plain class with an instance field `int counter`,
        // a @BPFJavaInline method that references `counter`.
        // Assert: the field reference is emitted as `receiver->counter`
        // (regular field access), NOT rewritten as the carrier expression.
        String c = compileAndGetGeneratedC(NonAbstractionFieldFixture.class);
        assertTrue(c.contains("->counter"),
                "Expected regular field access on receiver; got:\n" + c);
    }

    @Test
    void javaInlineCarrierSubstitutionStillWorksOnAbstraction() {
        // Control: re-run the existing @BPFAbstraction case (copy the fixture
        // from BPFAbstractionTest) and assert the carrier-substitution behaviour
        // is unchanged.
        String c = compileAndGetGeneratedC(AbstractionCarrierFixture.class);
        // Pattern matches whatever the existing test asserts.
        assertTrue(c.contains("/* expected carrier substitution */"));
    }

    @Test
    void javaInlineThisSubstitution() {
        // Fixture: plain (non-@BPFAbstraction) class with a @BPFJavaInline
        // method whose body uses `this` explicitly (e.g. `return foo(this);`).
        // Assert: `this` is substituted with the receiver carrier expression.
        String c = compileAndGetGeneratedC(NonAbstractionThisFixture.class);
        assertFalse(c.contains("this"),
                "Java `this` should not appear in emitted C; expected receiver substitution");
    }

    // Fixture classes go below; copy `compileAndGetGeneratedC` from BPFAbstractionTest.
}
```

For each fixture class, build a minimal `@BPF`-annotated `BPFProgram` subclass that uses the helper from a `@BPFFunction`. Look at `BPFAbstractionTest` (or the closest sibling) for the in-memory compile harness — re-use it verbatim rather than reinventing.

- [ ] **Step 3: Run the tests to confirm they fail**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test test -Dtest=BPFJavaInlineGeneralisationTest'
```

Expected: `javaInlineWorksOnNonAbstractionClass`, `…FieldSubstitution…`, and `…ThisSubstitution` all FAIL because the `@BPFAbstraction` gate at `Translator.java:2409` short-circuits and the call falls through to the regular non-inlined path. `…CarrierSubstitutionStillWorksOnAbstraction` should PASS (control).

- [ ] **Step 4: Commit the failing tests**

```bash
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/BPFJavaInlineGeneralisationTest.java
git commit -m "test(plugin): failing tests for @BPFJavaInline generalisation"
```

---

## Task 3 — Generalise `@BPFJavaInline` in Translator: implementation

**Files:**
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/Translator.java`

The relevant Java identifier handler at `Translator.java:594-605` currently short-circuits on `this` BEFORE consulting `localCarrierMap`. We need to reorder so `this` is routed through `localCarrierMap` when present.

- [ ] **Step 1: Rename `tryInlineAbstractionMethod` → `tryInlineJavaInlineMethod`**

In `Translator.java`, rename the method at line 2400. Update the single caller at line 1187. Update the Javadoc comment block at the rename site to drop the "Only on `@BPFAbstraction` classes" language; reflect the broader applicability (`@BPFJavaInline` on any class).

- [ ] **Step 2: Lift the `@BPFAbstraction` gate and conditionally apply field substitution**

Replace the current short-circuit and carrier-field collection (lines 2409-2456) with this structure. Annotate any new local variables in the body but do NOT change variable names that are already in scope at lines 2418-2435 (`methodTree`, `methodPath`, `carrierExpr`).

```java
// Method must carry @BPFJavaInline; @BPFAbstraction is no longer required.
var javaInlineAnn = symbol.getAnnotation(BPFJavaInline.class);
if (javaInlineAnn == null) {
    return null;
}
boolean isAbstraction = enclosingClass.getAnnotation(BPFAbstraction.class) != null;

// ... existing methodTree / methodPath resolution stays unchanged ...

// Determine the carrier expression: the receiver translated to C.
String carrierExpr = null;
if (receiverExpr != null) {
    var translated = translate(receiverExpr);
    if (translated != null) {
        carrierExpr = translated.toPrettyString();
    }
}

// Build the carrier map for the inner translator.
var innerCarrierMap = new java.util.HashMap<String, String>();

// Carrier-field substitution stays gated behind @BPFAbstraction.
if (isAbstraction && carrierExpr != null) {
    var carrierFields = new ArrayList<String>();
    for (var enc : enclosingClass.getEnclosedElements()) {
        if (enc instanceof javax.lang.model.element.VariableElement ve
                && enc.getKind() == ElementKind.FIELD
                && !enc.getModifiers().contains(Modifier.STATIC)) {
            carrierFields.add(ve.getSimpleName().toString());
        }
    }
    for (var fieldName : carrierFields) {
        innerCarrierMap.put(fieldName, carrierExpr);
    }
}

// `this` substitution applies to every @BPFJavaInline call site that has a
// receiver, regardless of @BPFAbstraction. Non-abstraction callees that
// reference `this` (e.g. `return val();` on `Ptr`) resolve correctly here.
if (carrierExpr != null) {
    innerCarrierMap.put("this", carrierExpr);
}
```

Keep the existing parameter-binding loop (lines 2458-2471) unchanged.

- [ ] **Step 3: Route `this` through `localCarrierMap` in the identifier handler**

At `Translator.java:594-605`, the current code is:

```java
if (identifierTree.getName().contentEquals("this") || identifierTree.getName().contentEquals("super")) {
    yield defaultReturn;
}
var localName = identifierTree.getName().toString();
if (localCarrierMap.containsKey(localName)) {
    yield new VerbatimExpression(localCarrierMap.get(localName));
}
```

Reorder so `this` (but NOT `super`) checks `localCarrierMap` first:

```java
var localName = identifierTree.getName().toString();
if ("this".equals(localName) && localCarrierMap.containsKey("this")) {
    yield new VerbatimExpression(localCarrierMap.get("this"));
}
// 'this' and 'super' are not class members; treat them as verbatim C identifiers.
if (identifierTree.getName().contentEquals("this") || identifierTree.getName().contentEquals("super")) {
    yield defaultReturn;
}
if (localCarrierMap.containsKey(localName)) {
    yield new VerbatimExpression(localCarrierMap.get(localName));
}
```

This ensures the existing `defaultReturn` path for `this` still fires outside of an inlined body (where `localCarrierMap.get("this")` is null), preserving current behaviour for non-inlined code.

- [ ] **Step 4: Rebuild plugin AND bpf jar on thinkstation, re-run the failing tests**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin,bpf -am install -DskipTests'

ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test test -Dtest=BPFJavaInlineGeneralisationTest'
```

Expected: all four tests PASS.

- [ ] **Step 5: Update `BPFJavaInline` Javadoc**

In `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFJavaInline.java`, drop any "only on `@BPFAbstraction`" implication. Add a one-paragraph note: "Carrier-field substitution (every instance field rewritten to the receiver expression) applies only on `@BPFAbstraction` classes. On other classes, `this` is the only thing rewritten — instance fields keep their normal `receiver->field` access."

- [ ] **Step 6: Run the full plugin test suite to catch regressions**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test test'
```

Expected: all existing tests still pass (especially the `BPFAbstraction` ones — `javaInlineCarrierSubstitutionStillWorksOnAbstraction` is the control case).

- [ ] **Step 7: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/Translator.java \
        annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/BPFJavaInline.java
git commit -m "feat(plugin): generalise @BPFJavaInline beyond @BPFAbstraction classes

Lift the @BPFAbstraction gate in tryInlineJavaInlineMethod (renamed from
tryInlineAbstractionMethod). Carrier-field substitution stays gated. \`this\`
is always substituted when a receiver is present, routed through
localCarrierMap before the verbatim short-circuit."
```

---

## Task 4 — `Ptr.directVal()`: failing tests first

**Files:**
- Create: `bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/DirectValTest.java`

- [ ] **Step 1: Write the seven directVal cases as failing tests**

```java
package me.bechberger.ebpf.bpf.compiler;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DirectValTest {

    @Test
    void directValBeforeMemberSelectEmitsDirectAccess() {
        // Fixture: a @BPFFunction calls `kfunc(p.directVal().field)` where
        // `field` belongs to a kernel-BTF struct (e.g. task_struct).
        String c = compileAndGetGeneratedC(DirectValFixtures.MemberSelectOk.class);
        assertTrue(c.contains("p->field") || c.contains("(*(p)).field"),
                "Expected direct field access; got:\n" + c);
        assertFalse(c.contains("BPF_CORE_READ(p, field)"),
                "directVal() must suppress BPF_CORE_READ lifting");
    }

    @Test
    void directValWithoutMemberSelectErrors() {
        // Fixture: `long x = p.directVal();` (assigned to a local; no MemberSelect).
        var diagnostics = compileAndCollectDiagnostics(DirectValFixtures.NoMemberSelect.class);
        assertTrue(diagnostics.stream().anyMatch(d ->
                d.kind().name().equals("ERROR") &&
                d.message().contains("directVal()") &&
                d.message().contains("field access")),
                "Expected directVal-must-be-followed-by-field-access error; got: " + diagnostics);
    }

    @Test
    void directValWithTrustedPtrParamSilent() {
        // Fixture: `kfunc(p.directVal())` where the kfunc parameter is
        // annotated @TrustedPtr — even though directVal() is not followed
        // by a MemberSelect, no error should fire.
        var diagnostics = compileAndCollectDiagnostics(DirectValFixtures.TrustedPtrParam.class);
        assertTrue(diagnostics.stream().noneMatch(d -> d.kind().name().equals("ERROR")),
                "Expected no errors; got: " + diagnostics);
    }

    @Test
    void directValWithAllowDirectValOnStatementSilent() {
        // Fixture: `@AllowDirectVal long x = p.directVal();` — annotation on local.
        var diagnostics = compileAndCollectDiagnostics(DirectValFixtures.AllowDirectValLocal.class);
        assertTrue(diagnostics.stream().noneMatch(d -> d.kind().name().equals("ERROR")),
                "@AllowDirectVal on local should silence the check; got: " + diagnostics);
    }

    @Test
    void directValWithAllowDirectValOnMethodSilent() {
        // Fixture: `@AllowDirectVal @BPFFunction void foo() { long x = p.directVal(); }`
        var diagnostics = compileAndCollectDiagnostics(DirectValFixtures.AllowDirectValMethod.class);
        assertTrue(diagnostics.stream().noneMatch(d -> d.kind().name().equals("ERROR")),
                "@AllowDirectVal on method should silence the check; got: " + diagnostics);
    }

    @Test
    void valCallStillEmitsCoreRead() {
        // Control: ensure `p.val().field` still lifts to BPF_CORE_READ.
        String c = compileAndGetGeneratedC(DirectValFixtures.ValControl.class);
        assertTrue(c.contains("BPF_CORE_READ(p, field)"),
                "val() must still lift to CO-RE; got:\n" + c);
    }

    @Test
    void directValOnNonPtrReceiverDoesNotCrash() {
        // Fixture: a class with its own `directVal()` method (NOT Ptr) — the
        // plugin must not crash and must not emit a false error.
        var diagnostics = compileAndCollectDiagnostics(DirectValFixtures.NonPtrDirectVal.class);
        assertTrue(diagnostics.stream().noneMatch(d ->
                d.kind().name().equals("ERROR") && d.message().contains("directVal")),
                "Non-Ptr directVal must not trigger the structural check; got: " + diagnostics);
    }
}
```

Build the fixture classes (`DirectValFixtures.*`) as small in-memory `@BPF` sources. Re-use the existing compile-harness helpers from `BPFAbstractionTest` or `CompilerPluginTest`.

- [ ] **Step 2: Run to confirm failures**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test test -Dtest=DirectValTest'
```

Expected: all seven FAIL — `directVal()` doesn't exist yet (compile error inside fixtures), or compiles but emits no special handling.

- [ ] **Step 3: Commit failing tests**

```bash
git add bpf-compiler-plugin-test/src/test/java/me/bechberger/ebpf/bpf/compiler/DirectValTest.java
git commit -m "test(plugin): failing tests for Ptr.directVal() structural check"
```

---

## Task 5 — Add `Ptr.directVal()`

**Files:**
- Modify: `bpf-processor/src/main/java/me/bechberger/ebpf/type/Ptr.java`

- [ ] **Step 1: Add `directVal()` method to `Ptr`**

Place after the existing `val()` method (search for `public T val()` in `Ptr.java`):

```java
/**
 * Like {@link #val()}, but tells the BPF compiler plugin to emit a <em>direct</em>
 * field access ({@code (*p).field} → {@code p->field}) instead of a CO-RE
 * relocation ({@code BPF_CORE_READ(p, field)}).
 *
 * <p>Use this only when a kfunc requires a trusted pointer on a field load.
 * {@code BPF_CORE_READ} strips the trusted annotation; a direct access preserves it.
 *
 * <p>The plugin enforces that the result of {@code directVal()} is immediately
 * followed by a field access. Other uses are a compile error. To override the
 * check, annotate the call site with {@link me.bechberger.ebpf.annotations.AllowDirectVal}
 * or the kfunc parameter with {@link me.bechberger.ebpf.annotations.TrustedPtr}.
 *
 * <p>Outside a {@code @BPFFunction} body this method is identical to {@link #val()}.
 */
@BPFJavaInline
@NotUsableInJava
public T directVal() {
    return val();
}
```

Add `import` statements at the top of `Ptr.java` if needed (`BPFJavaInline`, `NotUsableInJava`).

- [ ] **Step 2: Compile `bpf-processor` on thinkstation**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-processor -am install -DskipTests'
```

Expected: BUILD SUCCESS.

- [ ] **Step 3: Commit**

```bash
git add bpf-processor/src/main/java/me/bechberger/ebpf/type/Ptr.java
git commit -m "feat(Ptr): add directVal() — sibling of val() that suppresses CO-RE lifting"
```

---

## Task 6 — Extend `stripPtrVal` to match `directVal`

**Files:**
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/Translator.java`

- [ ] **Step 1: Update `stripPtrVal` at line 2293**

Change:

```java
if (!"val".contentEquals(mst.getIdentifier())) return expr;
```

To:

```java
var name = mst.getIdentifier();
if (!"val".contentEquals(name) && !"directVal".contentEquals(name)) return expr;
```

This ensures the receiver of `directVal()` is exposed when the result is later used in a CO-RE context — though since `directVal()` is supposed to suppress CO-RE, the more important effect is that the `(*p)` produced by the inlined body gets pierced cleanly for subsequent `MemberSelect` lowering. The control test `valCallStillEmitsCoreRead` keeps the original `val` path honest.

Update the method's Javadoc to mention both names.

- [ ] **Step 2: Rebuild plugin + bpf, partial test run**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin,bpf -am install -DskipTests'

ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test test -Dtest=DirectValTest#directValBeforeMemberSelectEmitsDirectAccess,DirectValTest#valCallStillEmitsCoreRead'
```

Expected: `directValBeforeMemberSelectEmitsDirectAccess` and `valCallStillEmitsCoreRead` PASS. The other five still fail until Task 7.

- [ ] **Step 3: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/Translator.java
git commit -m "feat(plugin): stripPtrVal also pierces Ptr.directVal()"
```

---

## Task 7 — Structural check for `directVal()` non-MemberSelect uses

**Files:**
- Modify: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/Translator.java`

The check runs at the `MethodInvocationTree` translation site. Locate the existing handler (grep for `MethodInvocationTree` or `JCMethodInvocation` in the expression-translation switch). It must run AFTER we've confirmed the receiver is `Ptr` and the method name is `directVal`, but BEFORE emission.

- [ ] **Step 1: Add a helper `isDirectValCall(MethodInvocationTree mit)`**

Mirror the `stripPtrVal` structure: argless invocation, MemberSelect select, identifier `"directVal"`, receiver typed as `Ptr<...>`.

```java
private boolean isDirectValCall(MethodInvocationTree mit) {
    if (!mit.getArguments().isEmpty()) return false;
    if (!(mit.getMethodSelect() instanceof MemberSelectTree mst)) return false;
    if (!"directVal".contentEquals(mst.getIdentifier())) return false;
    var recvType = typeOf(mst.getExpression());
    return recvType instanceof ClassType ct
            && ct.asElement().getQualifiedName().contentEquals(Ptr.class.getName());
}
```

- [ ] **Step 2: Inspect the parent context for each `directVal()` call**

Build a helper `validateDirectValContext(MethodInvocationTree mit, TreePath path)` that returns void on success and emits an error via `compilerPlugin.messager.printMessage(Diagnostic.Kind.ERROR, ..., element)` on failure. Logic:

```java
private void validateDirectValContext(MethodInvocationTree mit, TreePath path) {
    var parent = path.getParentPath().getLeaf();
    // (a) Direct MemberSelect parent → OK.
    if (parent instanceof MemberSelectTree mst && mst.getExpression() == mit) {
        return;
    }
    // (b) Walk up to find: an enclosing call with a @TrustedPtr param,
    //     an enclosing VariableTree / @BPFFunction with @AllowDirectVal.
    var cursor = path.getParentPath();
    while (cursor != null) {
        var leaf = cursor.getLeaf();
        if (leaf instanceof MethodInvocationTree callerMit) {
            // Find parameter index of `mit` in callerMit's arguments.
            int idx = callerMit.getArguments().indexOf(mit);
            if (idx >= 0) {
                var calleeSym = resolveMethodSymbol(callerMit);
                if (calleeSym != null && idx < calleeSym.getParameters().size()) {
                    var paramSym = calleeSym.getParameters().get(idx);
                    if (paramSym.getAnnotation(TrustedPtr.class) != null) {
                        return;
                    }
                }
            }
            // Once we've passed through the immediately enclosing call, stop:
            // further outer calls don't apply to this argument.
            break;
        }
        if (leaf instanceof VariableTree vt) {
            if (hasAnnotation(vt.getModifiers(), AllowDirectVal.class)) return;
            break;
        }
        if (leaf instanceof MethodTree mt) {
            if (hasAnnotation(mt.getModifiers(), AllowDirectVal.class)
                    && hasAnnotation(mt.getModifiers(), BPFFunction.class)) {
                return;
            }
            break;
        }
        cursor = cursor.getParentPath();
    }
    compilerPlugin.messager.printMessage(
            javax.tools.Diagnostic.Kind.ERROR,
            "directVal() result must be followed by a field access "
            + "(or annotate the kfunc parameter with @TrustedPtr / "
            + "the call site with @AllowDirectVal)",
            // pass a JCTree.JCMethodInvocation for source-position attribution
            (com.sun.tools.javac.tree.JCTree) mit);
}
```

Use whatever helper already exists in this file to resolve `MethodInvocationTree` to its `MethodSymbol` (likely `TreeInfo.symbol(...)` or a wrapper). Don't invent — re-use the surrounding code's idiom.

`hasAnnotation` walks `ModifiersTree.getAnnotations()` and checks the fully-qualified name against the marker.

- [ ] **Step 3: Wire the check at the call site**

In the `MethodInvocationTree` translation branch, after detecting `isDirectValCall(mit)`, call `validateDirectValContext(mit, currentPath)` and proceed with normal emission. The check only emits diagnostics; it doesn't change emitted C.

- [ ] **Step 4: Rebuild plugin + bpf, full test run**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin,bpf -am install -DskipTests'

ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test test -Dtest=DirectValTest'
```

Expected: all seven `DirectValTest` cases PASS.

- [ ] **Step 5: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/Translator.java
git commit -m "feat(plugin): structural check for Ptr.directVal() — must be followed by field access"
```

---

## Task 8 — Teach `bpf-gen` to emit `@TrustedPtr` on `Ptr<cpumask>` parameters

**Files:**
- Modify: `bpf-gen/src/main/java/me/bechberger/ebpf/gen/Generator.java`

- [ ] **Step 1: Locate where parameter `@`-annotations are added**

Open `Generator.java` and search for `toParameterSpec` (in the `Parameter` or similar inner type/class). That's where existing per-parameter annotations (e.g. `@Unsigned`, `@Size`) are emitted. Confirm by reading 30 lines around the hit. The intent: add `@TrustedPtr` to the emitted `ParameterSpec` whenever the parameter type matches `Ptr<cpumask>`.

- [ ] **Step 2: Decide the trigger — type-based vs. metadata-based**

The simplest correct trigger is **type-based**: any kfunc parameter whose Java type is `Ptr<cpumask>` is a trusted-pointer parameter. (The kernel's verifier semantics for `bpf_cpumask_*` kfuncs make this a property of the type, not the helper.) If `helper-defs.json` already carries some "trusted" marker, prefer that; otherwise hardcode the type check.

Add to `toParameterSpec` (or wherever annotations are appended to the builder):

```java
// @TrustedPtr: kfuncs taking Ptr<cpumask> require a trusted-pointer argument.
// Emitting this here keeps the marker stable across BpfDefinitions regenerations.
if (isPtrToCpumask(parameterType)) {
    builder.addAnnotation(
            com.squareup.javapoet.ClassName.get(
                    "me.bechberger.ebpf.annotations", "TrustedPtr"));
}
```

Where `isPtrToCpumask` checks the JavaPoet `TypeName` / `ParameterizedTypeName`:

```java
private static boolean isPtrToCpumask(TypeName t) {
    if (!(t instanceof ParameterizedTypeName pt)) return false;
    if (!pt.rawType.equals(ClassName.get("me.bechberger.ebpf.type", "Ptr"))) return false;
    if (pt.typeArguments.size() != 1) return false;
    var arg = pt.typeArguments.get(0);
    return arg instanceof ClassName cn && cn.simpleName().equals("cpumask");
}
```

Adjust the exact class-name resolution to match this file's existing helpers (it may already have a `ptrOf(...)` factory or a `BTFType` enum).

- [ ] **Step 3: Build `bpf-gen` on thinkstation**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-gen -am install -DskipTests'
```

Expected: BUILD SUCCESS.

- [ ] **Step 4: Add a generator unit test**

If `bpf-gen` already has a test module (look for `bpf-gen/src/test/java`), add a small case that feeds a fake `bpf_cpumask_test_cpu` declaration through the generator and asserts the produced `MethodSpec`'s second `ParameterSpec` carries `@TrustedPtr`. If no test infrastructure exists, skip and rely on Task 9's regen check.

- [ ] **Step 5: Commit**

```bash
git add bpf-gen/src/main/java/me/bechberger/ebpf/gen/Generator.java
# also any new generator test
git commit -m "feat(bpf-gen): emit @TrustedPtr on Ptr<cpumask> kfunc parameters"
```

---

## Task 9 — Regenerate `BpfDefinitions.java`

**Files:**
- Regenerate: `bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/BpfDefinitions.java`

- [ ] **Step 1: Run the regen pipeline on thinkstation**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  bash bpf-runtime/build.sh 2>&1 | tail -40'
```

Inspect the output for the build steps. If `build.sh` uses a different entry point (the spec referenced `bpf-gen/target/bpf-gen.jar`), align the command.

- [ ] **Step 2: Pull the regenerated file to mac for committing**

After regen on thinkstation, sync the file back:

```
scp thinkstation:/home/i560383/code/experiments/hello-ebpf/bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/BpfDefinitions.java \
    /Users/i560383_1/code/experiments/hello-ebpf/bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/BpfDefinitions.java
```

- [ ] **Step 3: Verify the annotation lands on `bpf_cpumask_test_cpu`'s second parameter**

```bash
grep -B1 -A3 "bpf_cpumask_test_cpu" /Users/i560383_1/code/experiments/hello-ebpf/bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/BpfDefinitions.java | head -20
```

Expected: the second parameter (`Ptr<cpumask>`) carries `@TrustedPtr`.

- [ ] **Step 4: Commit regenerated file**

```bash
git add bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/BpfDefinitions.java
git commit -m "chore(bpf-runtime): regenerate BpfDefinitions.java with @TrustedPtr"
```

---

## Task 10 — Migrate `UserspaceSchedulerBase`: delete the three builtins, rewrite callers

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java`

- [ ] **Step 1: Delete `taskCpuIsAllowed`, `arena_or_assign`, `arena_and_assign`**

Search for `@BuiltinBPFFunction\("bpf_cpumask_test_cpu` and `@BuiltinBPFFunction\("\*\(\$arg1\)` in `UserspaceSchedulerBase.java`. Delete each of the three methods (and their preceding Javadoc).

- [ ] **Step 2: Rewrite `taskCpuIsAllowed` call site**

Find the single caller (e.g. around line 734 — `if (!taskCpuIsAllowed(targetCpu, p)) { ... }`). Replace with:

```java
if (!bpf_cpumask_test_cpu(targetCpu, p.directVal().cpus_ptr)) {
    // ... existing body ...
}
```

Make sure `bpf_cpumask_test_cpu` is in scope (import or static-import per the existing usage in this file).

- [ ] **Step 3: Rewrite `setBit` / `clearBit`**

Find the two call sites (around line 960):

```java
if (idle) arena_or_assign(idleMaskBase.add(wordIdx), mask);
else      arena_and_assign(idleMaskBase.add(wordIdx), ~mask);
```

Replace each with the local-variable form to preserve once-evaluation semantics:

```java
Ptr<Long> word = idleMaskBase.add(wordIdx);
if (idle) {
    word.set(word.val() | mask);
} else {
    word.set(word.val() & ~mask);
}
```

Place the local in the smallest enclosing scope. If `setBit` and `clearBit` are separate methods, each gets its own local with the appropriate assignment (no `if`).

- [ ] **Step 4: Rebuild bpf module and inspect generated C**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf -am install -DskipTests'

ssh thinkstation 'grep -n "taskCpuIsAllowed\|arena_or_assign\|arena_and_assign\|bpf_cpumask_test_cpu" \
    /home/i560383/code/experiments/hello-ebpf/bpf/target/generated-sources/annotations/me/bechberger/ebpf/bpf/UserspaceSchedulerBaseImpl.c \
    | head -20'
```

Expected:
- No occurrences of `taskCpuIsAllowed`, `arena_or_assign`, `arena_and_assign`.
- `bpf_cpumask_test_cpu(targetCpu, p->cpus_ptr)` (or equivalent) at the affinity-check site — NOT `BPF_CORE_READ(p, cpus_ptr)`.
- `setBit`/`clearBit` lower to `*(word) = (*(word)) | mask;` and `*(word) = (*(word)) & ~mask;`.

If `BPF_CORE_READ` still appears at the affinity site, the structural check passed but `stripPtrVal`/inlining didn't cover the path — re-check Task 6.

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java
git commit -m "refactor(UserspaceSchedulerBase): replace 3 inline-C builtins with Java equivalents

- taskCpuIsAllowed → bpf_cpumask_test_cpu(cpu, p.directVal().cpus_ptr)
- arena_or_assign / arena_and_assign → word.set(word.val() | mask) etc.

Relies on Ptr.directVal() (suppresses CO-RE lifting, preserves trusted-pointer
annotation) and the generalised @BPFJavaInline."
```

---

## Task 11 — Migrate other `p.val().cpus_ptr` call sites

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java` (line 1040, `tryDispatchToLocalCpu`)
- Modify: `bpf-samples/src/main/java/.../LotteryScheduler.java` (line 41)
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/sched/DispatchQueue.java` (line 341 Javadoc snippet)

- [ ] **Step 1: `Scheduler.tryDispatchToLocalCpu`**

At line ~1040, change:

```java
if (!bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)) {
    return false;
}
```

To:

```java
if (!bpf_cpumask_test_cpu(cpu, p.directVal().cpus_ptr)) {
    return false;
}
```

- [ ] **Step 2: `LotteryScheduler.java:41`**

Same migration: `p.val().cpus_ptr` → `p.directVal().cpus_ptr`.

- [ ] **Step 3: `DispatchQueue.java:341`**

This is a Javadoc snippet, not live code. Find the code block in the Javadoc that shows `p.val().cpus_ptr` and update to `p.directVal().cpus_ptr`. Add a one-line note in the Javadoc: "Use `directVal()` (not `val()`) to preserve the trusted-pointer annotation that `bpf_cpumask_test_cpu` requires."

- [ ] **Step 4: Rebuild and inspect generated C for `tryDispatchToLocalCpu`**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf,bpf-samples -am install -DskipTests'

ssh thinkstation 'grep -n "bpf_cpumask_test_cpu" \
    /home/i560383/code/experiments/hello-ebpf/bpf/target/generated-sources/annotations/me/bechberger/ebpf/bpf/UserspaceSchedulerBaseImpl.c \
    | head -5'
```

Expected: `bpf_cpumask_test_cpu(cpu, p->cpus_ptr)` at `tryDispatchToLocalCpu`'s call site. NOT `BPF_CORE_READ`.

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/sched/DispatchQueue.java \
        bpf-samples/src/main/java/me/bechberger/ebpf/bpf/samples/sched/LotteryScheduler.java
git commit -m "refactor(sched): migrate p.val().cpus_ptr → p.directVal().cpus_ptr

Scheduler.tryDispatchToLocalCpu and LotteryScheduler emitted BPF_CORE_READ on
p.cpus_ptr, which strips the trusted-pointer annotation bpf_cpumask_test_cpu
requires on its second argument. directVal() emits a direct field access that
preserves the annotation. DispatchQueue Javadoc snippet updated to match."
```

---

## Task 12 — Framework-level integration test

**Files:**
- Create: `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/DirectValTaskCpuAllowedTest.java`
- Create: `bpf-samples/src/test/java/me/bechberger/ebpf/bpf/DirectValTaskCpuAllowedScheduler.java`

- [ ] **Step 1: Write the test scheduler**

Model after `ArenaFromStructOpsHandlerScheduler.java` for structure (the JUnit-extension + `@TestScheduler` pattern):

```java
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;

/**
 * Minimal scheduler that exercises {@code p.directVal().cpus_ptr} in a
 * non-sleepable {@code struct_ops} handler ({@code enqueue}). The kernel
 * verifier accepts the load only because {@code directVal()} suppresses
 * CO-RE lifting on {@code cpus_ptr}, preserving the trusted-pointer
 * annotation that {@code bpf_cpumask_test_cpu} requires.
 *
 * <p>If {@code directVal()} regresses to {@code BPF_CORE_READ(p, cpus_ptr)},
 * the verifier rejects the load with a trusted-pointer error and the test
 * fails.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "directval_taskcpu_test")
@Property(name = "timeout_ms", value = "10000")
public abstract class DirectValTaskCpuAllowedScheduler extends SchedulerBase implements Scheduler {

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        // Direct trusted-pointer load: must NOT lower to BPF_CORE_READ.
        if (bpf_cpumask_test_cpu(0, p.directVal().cpus_ptr)) {
            shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
        } else {
            shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
        }
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();
    }
}
```

- [ ] **Step 2: Write the test**

```java
package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Framework-level integration test for {@link me.bechberger.ebpf.type.Ptr#directVal()}.
 *
 * <p>Loads a scheduler whose {@code enqueue} handler calls
 * {@code bpf_cpumask_test_cpu(0, p.directVal().cpus_ptr)}. The kernel
 * verifier accepts the load only when {@code directVal()} suppresses
 * CO-RE lifting on {@code cpus_ptr} — a regression that re-introduces
 * {@code BPF_CORE_READ} is rejected with a trusted-pointer error.
 */
@ExtendWith(SchedulerExtension.class)
public class DirectValTaskCpuAllowedTest {

    @Test
    @Timeout(15)
    @TestScheduler(DirectValTaskCpuAllowedScheduler.class)
    void schedulerAttachesWithTrustedCpumaskLoad(
            DirectValTaskCpuAllowedScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "Scheduler must remain attached after 300 ms — if the verifier "
                + "rejected the load, directVal() regressed to BPF_CORE_READ.");
    }
}
```

- [ ] **Step 3: Run on thinkstation under vng**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  vng -p ./vng.profile -- mvn -pl bpf-samples -Dtest=DirectValTaskCpuAllowedTest \
      -Dmaven.test.skip=false -DskipTests=false test 2>&1 | tail -40'
```

Expected: PASS. If FAIL with "trusted pointer required" or similar verifier error → the structural check passed but emission is still lifting; revisit Task 6/7.

- [ ] **Step 4: Commit**

```bash
git add bpf-samples/src/test/java/me/bechberger/ebpf/bpf/DirectValTaskCpuAllowedTest.java \
        bpf-samples/src/test/java/me/bechberger/ebpf/bpf/DirectValTaskCpuAllowedScheduler.java
git commit -m "test(directval): framework integration test for p.directVal().cpus_ptr"
```

---

## Task 13 — End-to-end verification

- [ ] **Step 1: Re-run the existing arena/sched smoke tests on thinkstation**

The migrations in Tasks 10-11 touch `UserspaceSchedulerBase`, which is exercised by `RustlandFifoSampleSmokeTest` and `ArenaFromStructOpsHandlerTest`. Confirm no regression.

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  vng -p ./vng.profile -- mvn -pl bpf-samples \
      -Dtest=RustlandFifoSampleSmokeTest,ArenaFromStructOpsHandlerTest,DirectValTaskCpuAllowedTest \
      -Dmaven.test.skip=false -DskipTests=false test 2>&1 | tail -30'
```

Expected: all three PASS.

- [ ] **Step 2: Inspect final generated C**

```
ssh thinkstation 'grep -c "BPF_CORE_READ" \
    /home/i560383/code/experiments/hello-ebpf/bpf/target/generated-sources/annotations/me/bechberger/ebpf/bpf/UserspaceSchedulerBaseImpl.c'
ssh thinkstation 'grep -c "taskCpuIsAllowed\|arena_or_assign\|arena_and_assign" \
    /home/i560383/code/experiments/hello-ebpf/bpf/target/generated-sources/annotations/me/bechberger/ebpf/bpf/UserspaceSchedulerBaseImpl.c'
```

Expected: zero occurrences of any of the three deleted builtins. `BPF_CORE_READ` count may still be non-zero (other unrelated field accesses) — that's fine.

- [ ] **Step 3: Full plugin test suite**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin-test test'
```

Expected: all tests PASS.

- [ ] **Step 4: No commit (verification-only task). Note any anomalies for follow-up.**

---

## Out of Scope (do not touch)

- New trusted-pointer mechanisms beyond field-access. The structural check is intentionally minimal.
- Atomic arena writes (`__sync_fetch_and_or` etc.). The non-atomic `|=` is correct because each CPU writes only its own bit; if multi-CPU contention on the same word ever becomes a requirement, that's a separate design.
- Auditing every `@BuiltinBPFFunction` in the codebase. Focused scope: only the three in `UserspaceSchedulerBase` plus `bpf_cpumask_test_cpu` migrations.
- A pre-pass architecture (`DirectValGuardPass`). The structural check is one inspection at the call site — no pass needed.
- Other kfuncs that may also need `@TrustedPtr`. The bpf-gen rule keys on `Ptr<cpumask>`; if a future kfunc needs the marker for a different type, extend the predicate then.
