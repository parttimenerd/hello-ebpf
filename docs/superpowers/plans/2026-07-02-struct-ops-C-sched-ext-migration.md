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

### Task 3: Convert `Scheduler` to `@StructOps` — annotation flip + `@Sleepable` on `sched_init`

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/Scheduler.java`

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
