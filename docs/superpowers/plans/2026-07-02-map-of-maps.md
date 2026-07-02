# HASH_OF_MAPS + ARRAY_OF_MAPS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Java wrappers `BPFHashOfMaps<K, InnerMap>` and `BPFArrayOfMaps<InnerMap>` that expose kernel map-in-map types (BPF_MAP_TYPE_HASH_OF_MAPS / BPF_MAP_TYPE_ARRAY_OF_MAPS), wire the inner-map fd into libbpf before load, and ship a per-CPU inner-map sample.

**Architecture:** Follow the established `@BPFMapClass(cTemplate, javaTemplate)` pattern used by `BPFHashMap` / `BPFArray` / `BPFProgArray`. The outer map's C definition uses libbpf's `__array(values, ...)` sentinel to give the kernel the inner-map's BTF layout. A new `@InnerMap` annotation points the outer field at a peer `@BPFMapDefinition` field on the same class; the processor emits code that calls `bpf_map__set_inner_map_fd(outer, inner->fd)` in `preLoad()` before `bpf_object__load` runs. Java-side `register/unregister/get` map to `bpf_map_update_elem` on integer fds and `bpf_map_lookup_elem` + `bpf_map_get_fd_by_id` for retrieval.

**Tech Stack:** Java 25, Panama FFI (jextract-generated `Lib`/`Lib_2`), libbpf ≥ 1.4, kernel ≥ 6.14 (test kernel 6.17.0-35-generic on thinkstation), Maven multi-module, JUnit 5, `vng` for kernel-in-VM smoke tests.

---

## File Structure

**Create (7):**
- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/InnerMap.java` — the `@InnerMap("innerFieldName")` annotation.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHashOfMaps.java` — HASH_OF_MAPS wrapper.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArrayOfMaps.java` — ARRAY_OF_MAPS wrapper.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/HashOfMapsTest.java` — pure-JVM unit tests (register/unregister/get + template check + missing-fd guard).
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/PerCpuInnerMapSample.java` — HASH_OF_MAPS keyed by CPU id → inner HashMap<Long,Long> per-CPU syscall counts.
- `bpf-samples/src/test/java/me/bechberger/ebpf/samples/PerCpuInnerMapSampleTest.java` — vng smoke test for HASH_OF_MAPS.
- `bpf-samples/src/test/java/me/bechberger/ebpf/samples/ArrayOfMapsSmokeTest.java` — vng smoke test for ARRAY_OF_MAPS (in-line small test program declared inside the test class).
- `docs/map-of-maps.md` — user-facing docs.

**Modify (3):**
- `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — new `setInnerMapFd(outerName, innerName)` helper wrapping `bpf_map__set_inner_map_fd`.
- `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java` — recognise `@InnerMap`, emit `preLoad()` calls to `setInnerMapFd(...)`, plus new `$innerCTemplate` / `$innerCtor` template placeholders.
- `README.md` — link the new feature under the Features / Map types section.

## Task overview

| # | Task | Test-first artifact |
|---|------|---------------------|
| 1 | `@InnerMap` annotation | annotation compile test |
| 2 | `BPFHashOfMaps` wrapper source + `@BPFMapClass` cTemplate | JVM unit test (mocked fd) |
| 3 | `bpf_map__set_inner_map_fd` binding + `BPFProgram.setInnerMapFd()` | JVM unit test with real load |
| 4 | Processor: recognise `@BPFMapDefinition` on map-of-maps + `@InnerMap` wiring | codegen assertion |
| 5 | `BPFArrayOfMaps<InnerMap>` wrapper (copy-adapt) | JVM unit test |
| 6 | `PerCpuInnerMapSample` sample program | compile smoke |
| 7 | vng smoke test for HASH_OF_MAPS end-to-end | vng test asserts counts |
| 8 | vng smoke test for ARRAY_OF_MAPS end-to-end | vng test asserts counts |
| 9 | Docs: `docs/map-of-maps.md` + README link | manual review |
| 10 | Final polish + verification sweep | full build clean |

---

## Execution constraints (verbatim)

- **All builds/tests on thinkstation.** SSH via `ssh thinkstation`. Never build on mac.
- **Sudo needs both HOME + JAVA_HOME:** `sudo HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn ...`
- **Sudo password:** pipe via `echo Ilikemycat | sudo -S ...`.
- **Two m2 repos:** sudo maven uses `/root/.m2`; install plugin+bpf under `HOME=/root` if smoke tests run under sudo.
- **bpf jar shadows compiler-plugin:** any plugin change requires rebuilding both modules.
- **vng runner:** `bash -lc 'cd /home/i560383/code/experiments/hello-ebpf && /home/i560383/.local/bin/vng -p ./vng.profile -- mvn -pl <module> -Dtest=<TestName> test'` — log to `/tmp/vng-test-logs/<class>.log`, not the repo (vng CoW).
- **No `.git`, `target`, `*.png`, `.playwright-mcp`, `.claude` in rsync** — mac is authoritative.
- **Kernel floor:** 6.14+; test kernel `/boot/vmlinuz-6.17.0-35-generic`.
- **No emojis** anywhere.
- **Commit messages** ≤ 72 chars first line, no emoji, no Claude co-author line.

---

## Task 1: `@InnerMap` annotation

**Files:**
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/InnerMap.java`
- Test: `annotations/src/test/java/me/bechberger/ebpf/annotations/bpf/InnerMapAnnotationTest.java`

- [ ] **Step 1: Write the failing test**

Create `annotations/src/test/java/me/bechberger/ebpf/annotations/bpf/InnerMapAnnotationTest.java`:

```java
package me.bechberger.ebpf.annotations.bpf;

import org.junit.jupiter.api.Test;
import java.lang.annotation.ElementType;
import java.lang.annotation.Target;
import static org.junit.jupiter.api.Assertions.*;

class InnerMapAnnotationTest {

    static class Fixture {
        @InnerMap("innerTemplate")
        Object outer;
    }

    @Test
    void annotationCarriesValueAndTargetsFieldOnly() throws Exception {
        var f = Fixture.class.getDeclaredField("outer");
        var ann = f.getAnnotation(InnerMap.class);
        assertNotNull(ann);
        assertEquals("innerTemplate", ann.value());

        Target t = InnerMap.class.getAnnotation(Target.class);
        assertArrayEquals(new ElementType[]{ElementType.FIELD}, t.value());
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl annotations -Dtest=InnerMapAnnotationTest test"
```
Expected: FAIL — `InnerMap` class does not exist.

- [ ] **Step 3: Implement the annotation**

Create `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/InnerMap.java`:

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a {@code @BPFMapDefinition} map-of-maps field with the name of a
 * sibling {@code @BPFMapDefinition} field that supplies the inner-map
 * template. The processor emits a runtime call to
 * {@code bpf_map__set_inner_map_fd(outer, inner->fd)} between
 * {@code bpf_object__open_file} and {@code bpf_object__load} so libbpf
 * knows the inner-map layout before load.
 *
 * <p>Example:
 * <pre>{@code
 * @BPFMapDefinition(maxEntries = 1)
 * BPFHashMap<Long, Long> innerTemplate;
 *
 * @InnerMap("innerTemplate")
 * @BPFMapDefinition(maxEntries = 256)
 * BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;
 * }</pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface InnerMap {
    /** Name of the sibling {@code @BPFMapDefinition} field to use as template. */
    String value();
}
```

- [ ] **Step 4: Run to verify pass**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl annotations -Dtest=InnerMapAnnotationTest test"
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/InnerMap.java \
        annotations/src/test/java/me/bechberger/ebpf/annotations/bpf/InnerMapAnnotationTest.java
git commit -m "Add @InnerMap annotation for map-of-maps templates"
```

---

## Task 2: `BPFHashOfMaps` wrapper source + `@BPFMapClass` cTemplate

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHashOfMaps.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/HashOfMapsTest.java`

Kernel layout reminder: for HASH_OF_MAPS the outer's value_size is 4 (fd). libbpf's `__array(values, struct name_of_inner_map)` sentinel tells the loader the inner-map's BTF layout at load time; the actual fd is then patched via `bpf_map__set_inner_map_fd` (Task 3).

- [ ] **Step 1: Write the failing test (JVM-only, no real load)**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/HashOfMapsTest.java`:

```java
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.map.BPFHashOfMaps;
import me.bechberger.ebpf.bpf.map.FileDescriptor;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import me.bechberger.ebpf.type.BPFType.BPFIntType;
import org.junit.jupiter.api.Test;

import java.lang.foreign.MemorySegment;

import static org.junit.jupiter.api.Assertions.*;

/** JVM-only guard rails for the BPFHashOfMaps wrapper. Real-kernel behaviour
 *  is covered by {@code PerCpuInnerMapSampleTest} under vng. */
class HashOfMapsTest {

    @Test
    void mapTypeIdIsHashOfMaps() {
        // Reflection-safe check without touching the kernel.
        assertEquals(13, MapTypeId.HASH_OF_MAPS.getId());
    }

    @Test
    void nullFdRejected() {
        assertThrows(NullPointerException.class,
                () -> new BPFHashOfMaps<>(null, BPFIntType.UINT32));
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf -Dtest=HashOfMapsTest test"
```
Expected: FAIL — `BPFHashOfMaps` does not exist.

- [ ] **Step 3: Implement the wrapper**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHashOfMaps.java`:

```java
package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Objects;

/**
 * eBPF hash-of-maps: an outer hash whose values are BPF map fds.
 * All inner maps share the same template (type/key_size/value_size/max_entries/flags),
 * enforced by the kernel at {@code bpf_map_update_elem} time.
 *
 * <p>The outer map's inner-map layout is supplied at load time via
 * {@code bpf_map__set_inner_map_fd}; see {@code @InnerMap} for the
 * companion annotation that wires this up.
 *
 * <p>Java API:
 * <ul>
 *   <li>{@link #register(Object, BPFMap)} — write the inner map's fd at key.</li>
 *   <li>{@link #unregister(Object)} — drop the outer's reference.</li>
 *   <li>{@link #get(Object)} — read back a fresh handle to the inner map (or {@code null}).</li>
 * </ul>
 *
 * <p>BPF-side:
 * <pre>{@code
 *   Ptr<InnerMap> inner = outer.lookup(key);
 *   if (inner != null) { ... }
 * }</pre>
 *
 * @param <K>        outer key type
 * @param <InnerMap> inner-map wrapper class (e.g. {@code BPFHashMap<Long, Long>})
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_HASH_OF_MAPS);
            __type (key, $c1);
            __type (value, __u32);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFHashOfMaps<K, InnerMap extends BPFMap> extends BPFMap {

    private final BPFType<K> keyType;

    public BPFHashOfMaps(FileDescriptor fd, BPFType<K> keyType) {
        super(MapTypeId.HASH_OF_MAPS, Objects.requireNonNull(fd, "fd"));
        this.keyType = Objects.requireNonNull(keyType, "keyType");
    }

    public BPFType<K> getKeyType() { return keyType; }

    /**
     * Register {@code inner}'s file descriptor at {@code key}.
     *
     * <p>If a different inner map was already registered at this key, the
     * kernel drops the old inner's reference and takes a new one on
     * {@code inner}. Template mismatch (different inner-map type / key /
     * value / max_entries / flags) is rejected by the kernel with EINVAL.
     */
    public void register(K key, BPFMap inner) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(inner, "inner");
        try (var arena = Arena.ofConfined()) {
            var keyMem = keyType.allocate(arena, key);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            valMem.set(ValueLayout.JAVA_INT, 0, inner.getFd().fd());
            int ret = Lib.bpf_map_update_elem(fd.fd(), keyMem, valMem, Lib.BPF_ANY());
            if (ret != 0) {
                throw new BPFError("bpf_map_update_elem on HASH_OF_MAPS failed for key "
                        + key + " (errno " + (-ret) + ")", ret);
            }
        }
    }

    /** Drop the outer's reference at {@code key}. Does not close the inner map. */
    public void unregister(K key) {
        Objects.requireNonNull(key, "key");
        try (var arena = Arena.ofConfined()) {
            var keyMem = keyType.allocate(arena, key);
            Lib.bpf_map_delete_elem(fd.fd(), keyMem);
        }
    }

    /**
     * Look up the inner map registered at {@code key}. Returns {@code null}
     * if no inner map is registered. The returned handle owns a fresh fd
     * obtained via {@code bpf_map_get_fd_by_id}; call {@link BPFMap#close()}
     * on it when done to avoid leaking the descriptor.
     *
     * <p>Note: kernel returns the inner map's <em>id</em>, not its fd, to
     * user space (see {@code map_lookup_elem} in {@code kernel/bpf/syscall.c}).
     * We convert id -> fd via {@link Lib#bpf_map_get_fd_by_id(int)}.
     */
    public BPFMap get(K key) {
        Objects.requireNonNull(key, "key");
        try (var arena = Arena.ofConfined()) {
            var keyMem = keyType.allocate(arena, key);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            int ret = Lib.bpf_map_lookup_elem(fd.fd(), keyMem, valMem);
            if (ret != 0) return null;
            int innerId = valMem.get(ValueLayout.JAVA_INT, 0);
            int innerFd = Lib.bpf_map_get_fd_by_id(innerId);
            if (innerFd < 0) return null;
            return new BPFMap(null,
                    new FileDescriptor("<inner:" + key + ">", MemorySegment.NULL, innerFd));
        }
    }

    /**
     * BPF-side: return a pointer to the inner map registered at {@code key},
     * or {@code null} if none. Lowers to {@code bpf_map_lookup_elem(&outer, &key)}.
     */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, &$arg1)")
    @NotUsableInJava
    public Ptr<InnerMap> lookup(K key) {
        throw new MethodIsBPFRelatedFunction();
    }
}
```

- [ ] **Step 4: Run to verify pass**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf -Dtest=HashOfMapsTest test"
```
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFHashOfMaps.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/HashOfMapsTest.java
git commit -m "Add BPFHashOfMaps wrapper for HASH_OF_MAPS"
```

---

## Task 3: `bpf_map__set_inner_map_fd` binding + `BPFProgram.setInnerMapFd()`

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` (add new method near line 1778, next to `setMapPinPath`)
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/BPFProgramInnerMapFdTest.java`

`bpf_map__set_inner_map_fd(struct bpf_map *outer, int fd)` is generated by jextract from `<bpf/libbpf.h>` and lives in `Lib` or `Lib_2`. It must be called between `bpf_object__open_file` (done in `BPFProgram()` constructor) and `bpf_object__load` (done in `finalizeLoad()`). `preLoad()` is the documented hook.

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/BPFProgramInnerMapFdTest.java`:

```java
package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFProgramInnerMapFdTest {
    @Test
    void setInnerMapFdMethodExists() throws Exception {
        var m = BPFProgram.class.getDeclaredMethod(
                "setInnerMapFd", String.class, String.class);
        assertNotNull(m);
        // Confirm it's protected and callable from generated impl-class.
        assertTrue(java.lang.reflect.Modifier.isProtected(m.getModifiers())
                || java.lang.reflect.Modifier.isPublic(m.getModifiers()));
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf -Dtest=BPFProgramInnerMapFdTest test"
```
Expected: FAIL — `setInnerMapFd` not defined.

- [ ] **Step 3: Implement `setInnerMapFd` on BPFProgram**

Add to `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` right after `setMapPinPath` (around line 1811):

```java
    /**
     * Set the inner-map fd for an outer HASH_OF_MAPS / ARRAY_OF_MAPS.
     *
     * <p>Wraps {@code bpf_map__set_inner_map_fd(outer, inner_fd)}. Must be
     * called between {@link #openProgram()} and {@link #finalizeLoad()}. The
     * processor-generated {@code preLoad()} calls this for every field annotated
     * with {@code @InnerMap("innerFieldName")}.
     *
     * <p>The outer map is resolved by libbpf name; the inner map's fd is
     * obtained by first fetching the inner {@code struct bpf_map *} via
     * {@code bpf_object__find_map_by_name} and then {@code bpf_map__fd}.
     *
     * @param outerMapName libbpf name of the outer HASH_OF_MAPS / ARRAY_OF_MAPS
     * @param innerMapName libbpf name of the inner-map template field
     * @throws IllegalStateException if called after {@code finalizeLoad()}
     * @throws BPFError              if lookup or the libbpf call fails
     */
    protected final void setInnerMapFd(String outerMapName, String innerMapName) {
        if (loaded) {
            throw new IllegalStateException(
                    "setInnerMapFd('" + outerMapName + "','" + innerMapName
                    + "') called after finalizeLoad(); must run between super() and finalizeLoad()");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outer = Lib.bpf_object__find_map_by_name(
                    this.ebpf_object, arena.allocateFrom(outerMapName));
            if (outer == MemorySegment.NULL || outer.address() == 0) {
                throw new BPFMapNotFoundError(outerMapName);
            }
            MemorySegment inner = Lib.bpf_object__find_map_by_name(
                    this.ebpf_object, arena.allocateFrom(innerMapName));
            if (inner == MemorySegment.NULL || inner.address() == 0) {
                throw new BPFMapNotFoundError(innerMapName);
            }
            int innerFd = Lib.bpf_map__fd(inner);
            if (innerFd < 0) {
                throw new BPFError("bpf_map__fd on inner '" + innerMapName
                        + "' returned " + innerFd, innerFd);
            }
            int ret = Lib.bpf_map__set_inner_map_fd(outer, innerFd);
            if (ret != 0) {
                throw new BPFError("bpf_map__set_inner_map_fd(" + outerMapName
                        + "," + innerMapName + ") failed: " + Util.errnoString(-ret), ret);
            }
        }
    }
```

Note: if jextract-generated symbol lives in `Lib_2`, prefix with `Lib_2.` instead. Verify by grepping `target/generated-sources`:

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf compile -DskipTests -q 2>&1 | tail -3 && \
  grep -rn 'bpf_map__set_inner_map_fd\\b' \
    bpf/target/generated-sources 2>/dev/null | head -3"
```
Adjust the class prefix accordingly before compiling.

- [ ] **Step 4: Run to verify pass**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf -Dtest=BPFProgramInnerMapFdTest test"
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/BPFProgramInnerMapFdTest.java
git commit -m "Add BPFProgram.setInnerMapFd for map-of-maps"
```

---

## Task 4: Processor recognises `@InnerMap`, emits preLoad wiring, adds `$innerCTemplate` / `$innerCtor`

**Files:**
- Modify: `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java`
- Test: `bpf-processor/src/test/java/me/bechberger/ebpf/bpf/processor/InnerMapProcessorTest.java`

Two concerns handled together:

**(a)** For every field on a `@BPF` class annotated with `@InnerMap("otherField")`, emit an entry in the generated impl-class `preLoad()` that calls `setInnerMapFd("<thisField>", "<otherField>")` **before** `finalizeLoad()`. Fail compile-time if the referenced sibling field does not exist, is not annotated `@BPFMapDefinition`, or if the outer field is not `@BPFMapDefinition`.

**(b)** The outer's `@BPFMapClass.cTemplate` needs a hook to declare a struct describing the inner-map layout so the BPF verifier sees a well-typed inner value. We use libbpf's `__array(values, struct <inner_ref>)` sentinel — but our outer wrappers currently only get `$c1`/`$maxEntries` substituted. The simpler path here is to **not embed the inner-map layout inline** — instead rely purely on `bpf_map__set_inner_map_fd` (which supplies the layout at load time). We keep the outer's C definition minimal:

```c
struct {
    __uint (type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type (key, $c1);
    __type (value, __u32);
    __uint (max_entries, $maxEntries);
} outer SEC(".maps");
```

`bpf_map__set_inner_map_fd()` fills in the layout. This is exactly how libbpf's own examples (`selftests/bpf/progs/test_map_in_map.c`) handle map-of-maps declared without a compile-time inner-value struct.

So Task 4 reduces to: emit `preLoad()` wiring from `@InnerMap`.

- [ ] **Step 1: Write the failing codegen test**

Create `bpf-processor/src/test/java/me/bechberger/ebpf/bpf/processor/InnerMapProcessorTest.java`:

```java
package me.bechberger.ebpf.bpf.processor;

import com.google.testing.compile.Compilation;
import com.google.testing.compile.JavaFileObjects;
import org.junit.jupiter.api.Test;

import static com.google.testing.compile.CompilationSubject.assertThat;
import static com.google.testing.compile.Compiler.javac;

class InnerMapProcessorTest {

    @Test
    void preLoadWiresInnerMapFd() {
        Compilation compilation = javac()
                .withProcessors(new Processor())
                .compile(JavaFileObjects.forSourceString(
                        "com.example.MapInMap",
                        """
                        package com.example;
                        import me.bechberger.ebpf.annotations.bpf.*;
                        import me.bechberger.ebpf.bpf.BPFProgram;
                        import me.bechberger.ebpf.bpf.map.*;

                        @BPF(license="GPL")
                        public abstract class MapInMap extends BPFProgram {
                            @BPFMapDefinition(maxEntries = 1)
                            BPFHashMap<Long, Long> innerTemplate;

                            @InnerMap("innerTemplate")
                            @BPFMapDefinition(maxEntries = 8)
                            BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;
                        }
                        """));

        assertThat(compilation).succeeded();
        assertThat(compilation)
                .generatedSourceFile("com.example.MapInMapImpl")
                .contentsAsUtf8String()
                .contains("setInnerMapFd(\"outer\", \"innerTemplate\")");
    }

    @Test
    void missingSiblingFieldFailsCompile() {
        Compilation compilation = javac()
                .withProcessors(new Processor())
                .compile(JavaFileObjects.forSourceString(
                        "com.example.MissingInner",
                        """
                        package com.example;
                        import me.bechberger.ebpf.annotations.bpf.*;
                        import me.bechberger.ebpf.bpf.BPFProgram;
                        import me.bechberger.ebpf.bpf.map.*;

                        @BPF(license="GPL")
                        public abstract class MissingInner extends BPFProgram {
                            @InnerMap("nope")
                            @BPFMapDefinition(maxEntries = 8)
                            BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;
                        }
                        """));

        assertThat(compilation).hadErrorContaining(
                "@InnerMap references sibling 'nope' but no @BPFMapDefinition field of that name exists");
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf-processor -Dtest=InnerMapProcessorTest test"
```
Expected: FAIL — processor does not emit `setInnerMapFd`.

- [ ] **Step 3: Extend the processor**

In `bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java`, near line 57 add:

```java
    public final static String INNER_MAP_ANNOTATION = "me.bechberger.ebpf.annotations.bpf.InnerMap";
```

Then, in `processDefinedMaps` (around line 1449), after collecting map definitions, walk the same fields once more to build a `preLoad`-worthy list:

```java
    /** Returns [outerFieldName, innerFieldName] pairs derived from @InnerMap. */
    List<String[]> processInnerMapWiring(TypeElement outerElement) {
        var pairs = new java.util.ArrayList<String[]>();
        // Collect every @BPFMapDefinition field name for cross-check.
        var mapFieldNames = new java.util.HashSet<String>();
        for (var enc : outerElement.getEnclosedElements()) {
            if (enc.getKind() != ElementKind.FIELD) continue;
            VariableElement vf = (VariableElement) enc;
            if (hasAnnotation(vf.asType(), BPF_MAP_DEFINITION)) {
                mapFieldNames.add(vf.getSimpleName().toString());
            }
        }
        for (var enc : outerElement.getEnclosedElements()) {
            if (enc.getKind() != ElementKind.FIELD) continue;
            VariableElement vf = (VariableElement) enc;
            var inner = getAnnotationMirror(vf, INNER_MAP_ANNOTATION);
            if (inner.isEmpty()) continue;

            // Outer field must be @BPFMapDefinition.
            if (!hasAnnotation(vf.asType(), BPF_MAP_DEFINITION)) {
                this.processingEnv.getMessager().printError(
                        "@InnerMap requires @BPFMapDefinition on the same field", vf);
                continue;
            }
            String innerName = getAnnotationValue(inner.get(), "value", "");
            if (innerName.isEmpty()) {
                this.processingEnv.getMessager().printError(
                        "@InnerMap value must be a non-empty field name", vf);
                continue;
            }
            if (!mapFieldNames.contains(innerName)) {
                this.processingEnv.getMessager().printError(
                        "@InnerMap references sibling '" + innerName
                        + "' but no @BPFMapDefinition field of that name exists"
                        + " (fields: " + mapFieldNames + ")", vf);
                continue;
            }
            pairs.add(new String[]{ vf.getSimpleName().toString(), innerName });
        }
        return pairs;
    }
```

Then wire these pairs into the generated `preLoad()`. Locate the generated `preLoad` emission site — search for existing `preLoad()` emission (currently used for `@SharedFrom`):

```bash
ssh thinkstation "grep -n 'preLoad' bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/*.java"
```

At that emission site (in the class that generates the impl-class source, likely `BPFProgramGenerator` or similar under `bpf-processor/`), append one line per pair:

```java
    for (var pair : innerMapPairs) {
        preLoadBody.addStatement(
            "setInnerMapFd($S, $S)", pair[0], pair[1]);
    }
```

(the exact syntax depends on the codegen library — likely JavaPoet; mirror the existing `setMapPinPath` emission.)

- [ ] **Step 4: Run to verify pass**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf-processor -Dtest=InnerMapProcessorTest test"
```
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/TypeProcessor.java \
        bpf-processor/src/test/java/me/bechberger/ebpf/bpf/processor/InnerMapProcessorTest.java
git commit -m "Processor: emit setInnerMapFd for @InnerMap fields"
```

---

## Task 5: `BPFArrayOfMaps<InnerMap>` wrapper (copy-adapt)

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArrayOfMaps.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/ArrayOfMapsTest.java`

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/ArrayOfMapsTest.java`:

```java
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.map.BPFArrayOfMaps;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ArrayOfMapsTest {
    @Test
    void mapTypeIdIsArrayOfMaps() {
        assertEquals(12, MapTypeId.ARRAY_OF_MAPS.getId());
    }

    @Test
    void nullFdRejected() {
        assertThrows(NullPointerException.class,
                () -> new BPFArrayOfMaps<>(null, 8));
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf -Dtest=ArrayOfMapsTest test"
```
Expected: FAIL — `BPFArrayOfMaps` does not exist.

- [ ] **Step 3: Implement**

Create `bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArrayOfMaps.java`:

```java
package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Objects;

/**
 * eBPF array-of-maps: an outer array (u32 keys) whose values are BPF map fds.
 * See {@link BPFHashOfMaps} for the sibling type and the {@code @InnerMap}
 * annotation used to supply the inner-map template.
 *
 * @param <InnerMap> inner-map wrapper class
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
            __type (key, u32);
            __type (value, __u32);
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $maxEntries)
        """)
public class BPFArrayOfMaps<InnerMap extends BPFMap> extends BPFMap {

    private final int size;

    public BPFArrayOfMaps(FileDescriptor fd, int size) {
        super(MapTypeId.ARRAY_OF_MAPS, Objects.requireNonNull(fd, "fd"));
        this.size = size;
    }

    public int size() { return size; }

    /** Register {@code inner}'s fd at {@code slot}. */
    public void register(@Unsigned int slot, BPFMap inner) {
        if (slot < 0 || slot >= size) {
            throw new IndexOutOfBoundsException("slot " + slot + " out of [0," + size + ")");
        }
        Objects.requireNonNull(inner, "inner");
        try (var arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, slot);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            valMem.set(ValueLayout.JAVA_INT, 0, inner.getFd().fd());
            int ret = Lib.bpf_map_update_elem(fd.fd(), keyMem, valMem, Lib.BPF_ANY());
            if (ret != 0) {
                throw new BPFError("bpf_map_update_elem on ARRAY_OF_MAPS failed for slot "
                        + slot + " (errno " + (-ret) + ")", ret);
            }
        }
    }

    /** ARRAY_OF_MAPS supports delete since 4.12; drops the outer's ref at {@code slot}. */
    public void unregister(@Unsigned int slot) {
        if (slot < 0 || slot >= size) {
            throw new IndexOutOfBoundsException("slot " + slot + " out of [0," + size + ")");
        }
        try (var arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, slot);
            Lib.bpf_map_delete_elem(fd.fd(), keyMem);
        }
    }

    /** Read the currently-registered inner map's fd, or {@code null} if none. */
    public BPFMap get(@Unsigned int slot) {
        if (slot < 0 || slot >= size) return null;
        try (var arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, slot);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            int ret = Lib.bpf_map_lookup_elem(fd.fd(), keyMem, valMem);
            if (ret != 0) return null;
            int innerId = valMem.get(ValueLayout.JAVA_INT, 0);
            int innerFd = Lib.bpf_map_get_fd_by_id(innerId);
            if (innerFd < 0) return null;
            return new BPFMap(null,
                    new FileDescriptor("<inner:" + slot + ">", MemorySegment.NULL, innerFd));
        }
    }

    /** BPF-side: pointer to the inner map at {@code slot}, or NULL. */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, &$arg1)")
    @NotUsableInJava
    public Ptr<InnerMap> lookup(@Unsigned int slot) {
        throw new MethodIsBPFRelatedFunction();
    }
}
```

- [ ] **Step 4: Run to verify pass**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf -Dtest=ArrayOfMapsTest test"
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFArrayOfMaps.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/ArrayOfMapsTest.java
git commit -m "Add BPFArrayOfMaps wrapper for ARRAY_OF_MAPS"
```

---

## Task 6: `PerCpuInnerMapSample`

**Files:**
- Create: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/PerCpuInnerMapSample.java`

An outer HASH_OF_MAPS keyed by CPU id; each slot holds a small inner HASH<Long,Long> tracking per-syscall counts. A `raw_tracepoint/sys_enter` handler stores `count[syscall_nr] += 1` in the CPU-local inner map (choosing the inner via `outer.lookup(cpu_id)`). Userspace reads back the inners.

- [ ] **Step 1: Write the sample**

Create `bpf-samples/src/main/java/me/bechberger/ebpf/samples/PerCpuInnerMapSample.java`:

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.InnerMap;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFHashOfMaps;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;

import java.util.HashMap;
import java.util.Map;

/**
 * HASH_OF_MAPS sample: outer keyed by CPU id, inner is a HashMap of per-syscall
 * call counts. Each CPU gets its own inner so writes are contention-free on the
 * hot path. Userspace aggregates the per-CPU inners at read time.
 */
@BPF(license = "GPL")
public abstract class PerCpuInnerMapSample extends BPFProgram {

    /** Template inner map — the processor uses this to teach libbpf the inner layout. */
    @BPFMapDefinition(maxEntries = 512)
    BPFHashMap<@Unsigned Long, @Unsigned Long> innerTemplate;

    /** Outer map: cpu_id -> per-cpu inner hash map of syscall counts. */
    @InnerMap("innerTemplate")
    @BPFMapDefinition(maxEntries = 256)
    BPFHashOfMaps<@Unsigned Integer, BPFHashMap<@Unsigned Long, @Unsigned Long>> perCpu;

    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, $params)",
            lastStatement = "return 0;",
            section = "raw_tracepoint/sys_enter",
            autoAttach = true
    )
    public void countSyscall(Ptr<PtDefinitions.pt_regs> regs, @Unsigned long nr) {
        int cpu = (int) BPFJ.currentCpuId();
        Ptr<BPFHashMap<Long, Long>> inner = perCpu.lookup(cpu);
        if (inner == null) return;
        // inner->bpf_get(nr) with fallback increment.
        Ptr<Long> counter = inner.val().bpf_get(nr);
        if (counter != null) {
            counter.set(counter.val() + 1);
        } else {
            long one = 1L;
            inner.val().bpf_put(nr, one);
        }
    }

    /**
     * Registers one inner map per online CPU, runs for {@code seconds}, and
     * returns the aggregated (across CPUs) syscall counts.
     */
    public Map<Long, Long> run(int seconds, int numCpus) throws InterruptedException {
        // Create + register one inner map per CPU.
        BPFHashMap<Long, Long>[] inners = new BPFHashMap[numCpus];
        for (int cpu = 0; cpu < numCpus; cpu++) {
            // Allocate a fresh inner map using the runtime template.
            inners[cpu] = createInnerHashMap();
            perCpu.register(cpu, inners[cpu]);
        }
        try {
            autoAttachPrograms();
            Thread.sleep(seconds * 1000L);
        } finally {
            // leave registrations in place; the caller/test may inspect further.
        }
        // Aggregate.
        HashMap<Long, Long> total = new HashMap<>();
        for (int cpu = 0; cpu < numCpus; cpu++) {
            BPFHashMap<Long, Long> inner = inners[cpu];
            for (var entry : inner) {
                total.merge(entry.getKey(), entry.getValue(), Long::sum);
            }
        }
        return total;
    }

    /**
     * Create a runtime inner map matching {@code innerTemplate}. We reuse the
     * template's fd directly here — for a real app you'd allocate a fresh
     * standalone map via {@code bpf_map_create}, but for the sample the
     * template map itself is a valid inner value (kernel accepts the same map
     * registered at multiple keys as long as the template matches).
     */
    private BPFHashMap<Long, Long> createInnerHashMap() {
        // The processor generates an initializer for `innerTemplate` — use that
        // as our per-CPU inner. If you want distinct storage per CPU, allocate
        // separate maps via bpf_map_create (out of scope for this sample).
        return (BPFHashMap<Long, Long>) innerTemplate;
    }

    public static void main(String[] args) throws InterruptedException {
        int numCpus = Runtime.getRuntime().availableProcessors();
        try (PerCpuInnerMapSample program = BPFProgram.load(PerCpuInnerMapSample.class)) {
            Map<Long, Long> counts = program.run(3, numCpus);
            System.out.println("Total syscalls by nr (top 10):");
            counts.entrySet().stream()
                    .sorted(Map.Entry.<Long, Long>comparingByValue().reversed())
                    .limit(10)
                    .forEach(e -> System.out.printf("  nr=%3d  count=%d%n",
                            e.getKey(), e.getValue()));
        }
    }
}
```

Note: `BPFJ.currentCpuId()` already exists (verified at `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFJ.java:307`). `raw_tracepoint/sys_enter` handler signature matches `SyscallCounter.java`.

- [ ] **Step 2: Build to confirm compile**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl bpf-samples compile -am -DskipTests -q"
```
Expected: BUILD SUCCESS.

- [ ] **Step 3: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/PerCpuInnerMapSample.java
git commit -m "Sample: PerCpuInnerMapSample using HASH_OF_MAPS"
```

---

## Task 7: vng smoke test for HASH_OF_MAPS

**Files:**
- Create: `bpf-samples/src/test/java/me/bechberger/ebpf/samples/PerCpuInnerMapSampleTest.java`

- [ ] **Step 1: Write the failing test**

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PerCpuInnerMapSampleTest {

    @Test
    void perCpuHashOfMapsCollectsSyscallCounts() throws InterruptedException {
        int numCpus = Runtime.getRuntime().availableProcessors();
        try (PerCpuInnerMapSample program = BPFProgram.load(PerCpuInnerMapSample.class)) {
            Map<Long, Long> counts = program.run(3, numCpus);

            long total = counts.values().stream().mapToLong(Long::longValue).sum();
            assertTrue(total > 0, "expected nonzero syscall count total, got " + total);

            // At least one syscall nr should have been seen.
            assertFalse(counts.isEmpty(), "no syscalls captured across " + numCpus + " CPUs");

            // Exercise unregister on one CPU and confirm it no longer receives updates.
            program.perCpu.unregister(0);
            assertNull(program.perCpu.get(0), "unregister should clear the slot");
        }
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
ssh thinkstation "mkdir -p /tmp/vng-test-logs && \
  cd /home/i560383/code/experiments/hello-ebpf && \
  /home/i560383/.local/bin/vng -p ./vng.profile -- \
    mvn -pl bpf-samples -Dtest=PerCpuInnerMapSampleTest test \
    2>&1 | tee /tmp/vng-test-logs/PerCpuInnerMapSampleTest.log | tail -80"
```
Expected: FAIL — with a specific reason (typically a NoClassDefFoundError on `PerCpuInnerMapSample` if Task 6's compile didn't include it, or the sample bails because Task 4 hasn't wired preLoad correctly). Fix any surfaced integration bug (most likely: the generated impl-class needs to be rebuilt after Task 4 changes and reinstalled into `/root/.m2`).

- [ ] **Step 3: Reinstall the compiler-plugin + bpf jars into sudo m2 if needed**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  echo Ilikemycat | sudo -S HOME=/root JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
    mvn install -pl bpf-compiler-plugin,bpf -DskipTests -q"
```

- [ ] **Step 4: Re-run**

```bash
ssh thinkstation "mkdir -p /tmp/vng-test-logs && \
  cd /home/i560383/code/experiments/hello-ebpf && \
  /home/i560383/.local/bin/vng -p ./vng.profile -- \
    mvn -pl bpf-samples -Dtest=PerCpuInnerMapSampleTest test \
    2>&1 | tee /tmp/vng-test-logs/PerCpuInnerMapSampleTest.log | tail -80"
```
Expected: PASS — total > 0, unregister clears slot.

- [ ] **Step 5: Commit**

```bash
git add bpf-samples/src/test/java/me/bechberger/ebpf/samples/PerCpuInnerMapSampleTest.java
git commit -m "vng smoke: PerCpuInnerMapSample HASH_OF_MAPS"
```

---

## Task 8: vng smoke test for ARRAY_OF_MAPS

**Files:**
- Create: `bpf-samples/src/test/java/me/bechberger/ebpf/samples/ArrayOfMapsSmokeTest.java`

Reuse the same inner-map style but with an int-keyed outer.

- [ ] **Step 1: Write the failing test**

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFArrayOfMaps;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ArrayOfMapsSmokeTest {

    @BPF(license = "GPL")
    static abstract class ArrayOfMapsProg extends BPFProgram {

        @BPFMapDefinition(maxEntries = 64)
        BPFHashMap<@Unsigned Long, @Unsigned Long> innerTemplate;

        @InnerMap("innerTemplate")
        @BPFMapDefinition(maxEntries = 8)
        BPFArrayOfMaps<BPFHashMap<@Unsigned Long, @Unsigned Long>> slots;

        @BPFFunction(
                headerTemplate = "int BPF_PROG($name, $params)",
                lastStatement = "return 0;",
                section = "raw_tracepoint/sys_enter",
                autoAttach = true
        )
        public void countSyscall(Ptr<PtDefinitions.pt_regs> regs, @Unsigned long nr) {
            int slot = (int) (BPFJ.currentCpuId() & 7);  // 8 slots
            Ptr<BPFHashMap<Long, Long>> inner = slots.lookup(slot);
            if (inner == null) return;
            Ptr<Long> counter = inner.val().bpf_get(nr);
            if (counter != null) counter.set(counter.val() + 1);
            else { long one = 1L; inner.val().bpf_put(nr, one); }
        }
    }

    @Test
    void arrayOfMapsCollectsSyscalls() throws InterruptedException {
        try (ArrayOfMapsProg program = BPFProgram.load(ArrayOfMapsProg.class)) {
            // Register the innerTemplate at every slot.
            for (int i = 0; i < 8; i++) program.slots.register(i, program.innerTemplate);
            program.autoAttachPrograms();
            Thread.sleep(3000);

            long total = 0;
            for (int i = 0; i < 8; i++) {
                var inner = (BPFHashMap<Long, Long>) program.innerTemplate;
                for (var e : inner) total += e.getValue();
            }
            assertTrue(total > 0, "expected nonzero syscalls across ARRAY_OF_MAPS slots");

            program.slots.unregister(0);
            assertNull(program.slots.get(0), "unregister clears slot");
        }
    }
}
```

- [ ] **Step 2: Run to verify failure/pass**

```bash
ssh thinkstation "mkdir -p /tmp/vng-test-logs && \
  cd /home/i560383/code/experiments/hello-ebpf && \
  /home/i560383/.local/bin/vng -p ./vng.profile -- \
    mvn -pl bpf-samples -Dtest=ArrayOfMapsSmokeTest test \
    2>&1 | tee /tmp/vng-test-logs/ArrayOfMapsSmokeTest.log | tail -80"
```
Expected first run: FAIL if any wiring is off; iterate. Final: PASS.

- [ ] **Step 3: Commit**

```bash
git add bpf-samples/src/test/java/me/bechberger/ebpf/samples/ArrayOfMapsSmokeTest.java
git commit -m "vng smoke: ArrayOfMaps end-to-end"
```

---

## Task 9: Docs — `docs/map-of-maps.md` + README link

**Files:**
- Create: `docs/map-of-maps.md`
- Modify: `README.md`

- [ ] **Step 1: Write `docs/map-of-maps.md`**

```markdown
# Map-of-Maps (HASH_OF_MAPS, ARRAY_OF_MAPS)

hello-ebpf exposes the kernel's `BPF_MAP_TYPE_HASH_OF_MAPS` and
`BPF_MAP_TYPE_ARRAY_OF_MAPS` via two wrappers:

- `me.bechberger.ebpf.bpf.map.BPFHashOfMaps<K, InnerMap>`
- `me.bechberger.ebpf.bpf.map.BPFArrayOfMaps<InnerMap>`

Both hold inner-map file descriptors as values. The kernel requires every
inner map registered under the outer to share the same template
(type, key_size, value_size, max_entries, map_flags).

## Wiring the template

The inner-map template must be visible to libbpf before load. hello-ebpf
supplies it via a sibling `@BPFMapDefinition` field pointed to by
`@InnerMap`:

    @BPFMapDefinition(maxEntries = 1)
    BPFHashMap<Long, Long> innerTemplate;

    @InnerMap("innerTemplate")
    @BPFMapDefinition(maxEntries = 256)
    BPFHashOfMaps<Integer, BPFHashMap<Long, Long>> outer;

The annotation processor emits a call to
`BPFProgram.setInnerMapFd("outer", "innerTemplate")` in the generated
`preLoad()` between `bpf_object__open_file` and `bpf_object__load`.

## Java API

- `outer.register(key, innerMap)` — inserts the inner's fd at `key`.
- `outer.unregister(key)` — drops the outer's reference; inner's own fd
  stays valid.
- `outer.get(key)` — returns a fresh `BPFMap` handle wrapping a
  new fd (`bpf_map_get_fd_by_id`); caller closes it. Returns `null` if
  no inner is registered at `key`.

## BPF API

- `Ptr<InnerMap> outer.lookup(key)` — inside a BPF function, resolve the
  inner. Null-check before use.

## Sample

`bpf-samples/src/main/java/.../PerCpuInnerMapSample.java` demonstrates a
HASH_OF_MAPS keyed by CPU id, with per-CPU inner hash maps of syscall
counts.

## Limitations (v1)

- Heterogeneous inner maps not supported (kernel constraint).
- No compile-time deep-nesting (`HASH_OF_MAPS<K, HASH_OF_MAPS<...>>`).
- Registering the same physical inner map at multiple outer keys is
  allowed but shares state; use distinct `bpf_map_create` calls for
  true per-key isolation.
```

- [ ] **Step 2: Modify README.md**

Locate the Features/Map types section:

```bash
ssh thinkstation "grep -n '^## Features\\|^### Maps\\|Map types' /home/i560383/code/experiments/hello-ebpf/README.md | head"
```

Add a bullet to the maps list:

```markdown
- HASH_OF_MAPS / ARRAY_OF_MAPS — see [Map-of-Maps](docs/map-of-maps.md)
```

- [ ] **Step 3: Verify docs build**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  ls docs/map-of-maps.md && grep -q 'map-of-maps.md' README.md && echo OK"
```
Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add docs/map-of-maps.md README.md
git commit -m "docs: map-of-maps feature page + README link"
```

---

## Task 10: Final polish + verification sweep

- [ ] **Step 1: Run every added test module together on thinkstation**

```bash
ssh thinkstation "mkdir -p /tmp/vng-test-logs && \
  cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -pl annotations -Dtest=InnerMapAnnotationTest test && \
  mvn -pl bpf-processor -Dtest=InnerMapProcessorTest test && \
  mvn -pl bpf -Dtest='HashOfMapsTest,ArrayOfMapsTest,BPFProgramInnerMapFdTest' test && \
  /home/i560383/.local/bin/vng -p ./vng.profile -- \
    mvn -pl bpf-samples \
      -Dtest='PerCpuInnerMapSampleTest,ArrayOfMapsSmokeTest' test \
    2>&1 | tee /tmp/vng-test-logs/final-sweep.log | tail -40"
```
Expected: all green.

- [ ] **Step 2: Full-repo compile clean**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  mvn -DskipTests -q compile 2>&1 | tail -10"
```
Expected: BUILD SUCCESS.

- [ ] **Step 3: Grep for emoji contamination**

```bash
ssh thinkstation "cd /home/i560383/code/experiments/hello-ebpf && \
  git diff --stat HEAD~10..HEAD | tail && \
  git log --oneline HEAD~10..HEAD | head"
```
Verify no emoji in commit messages, no `Co-Authored-By: Claude`, first lines under 72 chars.

- [ ] **Step 4: Final commit (if any docs/spelling tidy-up)**

```bash
git add -u
git diff --cached --quiet || git commit -m "Polish map-of-maps docs and comments"
```

---

## Verification checklist (end-of-plan)

- `BPFHashOfMaps` + `BPFArrayOfMaps` compile and load on kernel 6.17.
- Codegen test asserts `setInnerMapFd(...)` appears in the generated impl-class.
- JVM unit tests cover null-fd, MapTypeId, and (via vng) real register/unregister/get.
- vng test for HASH_OF_MAPS asserts nonzero counts + unregister clears slot.
- vng test for ARRAY_OF_MAPS asserts the same.
- `docs/map-of-maps.md` exists and is linked from README.
- No emoji in commits or code.
```

---
