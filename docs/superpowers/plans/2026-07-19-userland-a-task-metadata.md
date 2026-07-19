# Sub-project A — Extensible per-task metadata — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a Java scheduler author attach custom per-task fields to the BPF→Java message via a `@TaskExtension` record + a one-method BPF fill hook, carried in a fixed-size tail after the stable 88-byte `QueuedTaskCtx` prefix.

**Architecture:** A fixed `EXT_CAP`-byte tail is appended to the ring-buffer record. The stable 88-byte prefix stays byte-for-byte rustland-compatible. `QueuedTask` gains a `MemorySegment extSegment` slice plus `extLong(offset)` / `extInt(offset)` primitive accessors and a cached `ext(Class<E>)` record view. On the BPF side an overridable no-op `fillExtension(Ptr<task_struct>, Ptr<...>)` runs in `enqueue` before ringbuf submit. Schedulers that declare no extension keep `EXT_CAP = 0` and produce an exactly-88-byte record (full back-compat).

**Tech Stack:** Java 25 (Panama Foreign Memory API: `MemorySegment`/`ValueLayout`), hello-ebpf annotations + bpf-processor compiler plugin, JUnit 5, sched_ext BPF. Builds/tests run on thinkstation only.

**Build/test workflow (CRITICAL):** All builds and tests run on thinkstation, never the local mac.
- Sync local edits: `./scripts/sync.sh`
- Run a Maven/command on thinkstation: `./scripts/ts.sh <cmd>` (e.g. `./scripts/ts.sh ./mvnw -pl bpf -am test`)
- Pure-Java tests (no kernel) run fine under plain `./scripts/ts.sh ./mvnw ...`. Kernel-attach smoke tests run via `./scripts/ts.sh ./scripts/run-tests-vng.sh <TestClass>`.
- After ANY compiler-plugin (`bpf-processor`) change you MUST also rebuild the `bpf` module — the `bpf` jar-with-dependencies bundles a copy of the plugin classes and a stale copy silently wins (see repo memory `bpf_jar_shadows_compiler_plugin`).

---

## Design decisions locked for this plan

- **`EXT_CAP = 64`** bytes (eight `long`s of headroom). Single named constant `QueuedTaskCtx.EXT_CAP` (BPF side) and `QueuedTask.EXT_CAP` (Java side); they MUST be equal and are asserted equal by a test.
- **One `@TaskExtension` record per scheduler** in v1. The framework carries the raw tail bytes; the record view is purely a typed reader over those bytes.
- **Record size = 88 (prefix) + EXT_CAP.** With `EXT_CAP=64` → 152 bytes total. The 4 MiB ring absorbs ~27k records — noted in the design, re-asserted by a comment in the marshalling test.
- **Extension field layout = declaration order, natural alignment,** matching how the compiler plugin already lays out `@Type` records. Offsets into the tail are relative to the start of the tail (byte 0 of the tail == byte 88 of the record).
- **No compiler-plugin auto-generation of the extension `@Type` in v1.** The author declares BOTH the Java `@TaskExtension` record (for the typed read view) AND a plain BPF `@Type` struct (for the fill hook to write into), and the framework reserves the tail region generically as `@Size(EXT_CAP) byte[]`. This keeps the plugin untouched and is the smallest correct step. (The design doc's "compiler plugin generates a matching `@Type`" is deferred — noted as a follow-up in the final task.)

---

## File Structure

- **New** `annotations/src/main/java/me/bechberger/ebpf/annotations/TaskExtension.java` — marker annotation, `SOURCE` retention, `@Target(TYPE)`. ~15 lines.
- **Modify** `bpf/src/main/java/me/bechberger/ebpf/bpf/QueuedTask.java` — add `EXT_CAP`, `extSegment`, `extLong/extInt/extByte`, `ext(Class<E>)` cached view, copy the tail in the copy ctor, `fillFromSegment` overload that also slices the tail. ~60 added lines.
- **Modify** `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java` — add `@Size(EXT_CAP) byte[] ext` tail field to `QueuedTaskCtx`, add `EXT_CAP` constant, add overridable no-op `fillExtension(Ptr<task_struct>, Ptr<QueuedTaskCtx>)` and call it in the enqueue path after `fillQueuedCtx` and before submit.
- **Modify** `bpf/src/test/java/me/bechberger/ebpf/bpf/QueuedTaskDispatchedTaskMarshallingTest.java` — assert prefix offsets unchanged, assert total record size == 88 + EXT_CAP, assert tail round-trips.
- **New** `bpf/src/test/java/me/bechberger/ebpf/bpf/TaskExtensionTest.java` — pure-Java: write known bytes into a tail segment, read back via `ext(Record.class)` and primitive accessors, assert equality; assert a no-extension task still reports EXT_CAP tail zeroed.
- **New** `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/CgroupAwareSample.java` — demo: declare `CgroupExt(long cgroupId, long ppid)`, fill it in `fillExtension`, route by cgroup in `policy`. ~70 lines.

---

## Task 1: `@TaskExtension` marker annotation

**Files:**
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/TaskExtension.java`

- [ ] **Step 1: Write the annotation**

Create `annotations/src/main/java/me/bechberger/ebpf/annotations/TaskExtension.java`:

```java
package me.bechberger.ebpf.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a Java record as the per-task extension view for a {@code UserspaceScheduler}.
 *
 * <p>The record's components (in declaration order, natural alignment) describe how to
 * interpret the fixed {@code EXT_CAP}-byte extension tail appended to each
 * {@code QueuedTask}. The author fills the tail on the BPF side by overriding
 * {@code UserspaceSchedulerBase.fillExtension} and reads it back type-safely via
 * {@code QueuedTask.ext(MyExt.class)}.
 *
 * <p>v1 supports one extension record per scheduler. Retention is {@code SOURCE}:
 * the annotation is a documentation/marker aid only; the framework carries raw tail
 * bytes and the record view is a plain reader over them.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.SOURCE)
@Documented
public @interface TaskExtension {
}
```

- [ ] **Step 2: Compile the annotations module on thinkstation**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl annotations -am compile -q`
Expected: BUILD SUCCESS (annotation compiles; no processor changes needed).

- [ ] **Step 3: Commit**

```bash
git add annotations/src/main/java/me/bechberger/ebpf/annotations/TaskExtension.java
git commit -m "feat(annotations): add @TaskExtension marker for per-task metadata"
```

---

## Task 2: `QueuedTask` extension tail — failing test first

**Files:**
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/TaskExtensionTest.java`

- [ ] **Step 1: Write the failing test**

Create `bpf/src/test/java/me/bechberger/ebpf/bpf/TaskExtensionTest.java`:

```java
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.TaskExtension;
import org.junit.jupiter.api.Test;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import static org.junit.jupiter.api.Assertions.*;

class TaskExtensionTest {

    @TaskExtension
    record CgroupExt(long cgroupId, long ppid) {}

    /** Build a full 88 + EXT_CAP record segment with a known prefix pid and a known tail. */
    private MemorySegment recordWithTail(Arena arena, int pid, long cgroupId, long ppid) {
        MemorySegment seg = arena.allocate(QueuedTask.QT_SIZEOF + QueuedTask.EXT_CAP);
        seg.set(ValueLayout.JAVA_INT, 0, pid);                 // prefix pid at offset 0
        long tail = QueuedTask.QT_SIZEOF;                       // tail starts at 88
        seg.set(ValueLayout.JAVA_LONG, tail + 0, cgroupId);
        seg.set(ValueLayout.JAVA_LONG, tail + 8, ppid);
        return seg;
    }

    @Test
    void tailPrimitiveAccessorsRoundTrip() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = recordWithTail(arena, 4242, 0xABCDL, 7L);
            QueuedTask t = new QueuedTask();
            QueuedTask.fillFromSegment(seg, t);

            assertEquals(4242, t.pid);
            assertEquals(0xABCDL, t.extLong(0));
            assertEquals(7L, t.extLong(8));
        }
    }

    @Test
    void extRecordViewRoundTrips() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = recordWithTail(arena, 1, 999L, 123L);
            QueuedTask t = new QueuedTask();
            QueuedTask.fillFromSegment(seg, t);

            CgroupExt ext = t.ext(CgroupExt.class);
            assertEquals(999L, ext.cgroupId());
            assertEquals(123L, ext.ppid());
        }
    }

    @Test
    void copyPreservesTail() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment seg = recordWithTail(arena, 5, 55L, 66L);
            QueuedTask t = new QueuedTask();
            QueuedTask.fillFromSegment(seg, t);

            QueuedTask c = t.copy();
            assertEquals(55L, c.extLong(0));
            assertEquals(66L, c.extLong(8));
        }
    }

    @Test
    void extCapConstantsAgree() {
        assertEquals(64, QueuedTask.EXT_CAP);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=TaskExtensionTest -q`
Expected: COMPILE FAILURE — `QueuedTask.EXT_CAP`, `QueuedTask.QT_SIZEOF`, `extLong`, and `ext(Class)` do not exist yet.

---

## Task 3: `QueuedTask` extension tail — implement

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/QueuedTask.java`

- [ ] **Step 1: Make `QT_SIZEOF` public and add `EXT_CAP` + tail state**

In `QueuedTask.java`, replace the wire-offset block (lines 29-41, the `QT_PID`…`QT_COMM` constants) so the size and cap are public constants and add the tail slice field. Change the existing `private static final long QT_COMM = 72;` region to:

```java
    // Wire offsets — match BPF's queued_task_ctx and QueuedTaskDispatchedTaskMarshallingTest.
    private static final long QT_PID           =  0;
    private static final long QT_PREV_CPU      =  4;
    private static final long QT_NR_CPUS_ALLOW =  8;
    private static final long QT_FLAGS         = 16;
    private static final long QT_START_TS      = 24;
    private static final long QT_STOP_TS       = 32;
    private static final long QT_EXEC_RUNTIME  = 40;
    private static final long QT_WEIGHT        = 48;
    private static final long QT_VTIME         = 56;
    private static final long QT_ENQ_CNT       = 64;
    private static final long QT_COMM          = 72;

    /** Size of the stable rustland-compatible prefix. Never changes. */
    public static final long QT_SIZEOF = 88;

    /**
     * Fixed size of the per-task extension tail appended after the 88-byte prefix.
     * MUST equal {@code UserspaceSchedulerBase.QueuedTaskCtx.EXT_CAP}. Asserted by
     * {@code QueuedTaskDispatchedTaskMarshallingTest} and {@code TaskExtensionTest}.
     */
    public static final int EXT_CAP = 64;

    /** Zero-copy view over the EXT_CAP tail of the current record; never null after fill. */
    private final byte[] extBytes = new byte[EXT_CAP];
```

- [ ] **Step 2: Copy the tail in the copy constructor**

In the copy constructor (the `QueuedTask(QueuedTask src)` body, currently ending at the `System.arraycopy(src.comm, ...)` line), add a tail copy right after the comm copy:

```java
        System.arraycopy(src.comm, 0, this.comm, 0, 16);
        System.arraycopy(src.extBytes, 0, this.extBytes, 0, EXT_CAP);
```

- [ ] **Step 3: Fill the tail in `fillFromSegment`**

In `fillFromSegment`, after the existing `MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, QT_COMM, out.comm, 0, 16);` line, copy the tail only when the segment is large enough (back-compat: an 88-byte segment leaves the tail zeroed):

```java
        MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, QT_COMM, out.comm, 0, 16);
        if (seg.byteSize() >= QT_SIZEOF + EXT_CAP) {
            MemorySegment.copy(seg, ValueLayout.JAVA_BYTE, QT_SIZEOF, out.extBytes, 0, EXT_CAP);
        } else {
            java.util.Arrays.fill(out.extBytes, (byte) 0);
        }
```

- [ ] **Step 4: Add primitive tail accessors**

After the `commEquals` method (before the closing brace of the class), add:

```java
    /** Read a signed 64-bit value from the extension tail at {@code offset} (0-based within the tail). */
    public long extLong(int offset) {
        return (extBytes[offset] & 0xFFL)
             | (extBytes[offset + 1] & 0xFFL) << 8
             | (extBytes[offset + 2] & 0xFFL) << 16
             | (extBytes[offset + 3] & 0xFFL) << 24
             | (extBytes[offset + 4] & 0xFFL) << 32
             | (extBytes[offset + 5] & 0xFFL) << 40
             | (extBytes[offset + 6] & 0xFFL) << 48
             | (extBytes[offset + 7] & 0xFFL) << 56;
    }

    /** Read a signed 32-bit value from the extension tail at {@code offset}. */
    public int extInt(int offset) {
        return (extBytes[offset] & 0xFF)
             | (extBytes[offset + 1] & 0xFF) << 8
             | (extBytes[offset + 2] & 0xFF) << 16
             | (extBytes[offset + 3] & 0xFF) << 24;
    }

    /** Read a single byte from the extension tail at {@code offset}. */
    public byte extByte(int offset) {
        return extBytes[offset];
    }
```

- [ ] **Step 5: Add the cached record view `ext(Class<E>)`**

Add a field near `extBytes` for the cache:

```java
    private Object cachedExt;
    private Class<?> cachedExtType;
```

Then add the reflective record builder after the primitive accessors:

```java
    /**
     * Build a typed view of the extension tail as a record instance. The record's
     * components must be {@code long}/{@code int} in declaration order; they are read
     * from the tail with natural alignment (long on 8-byte boundaries, int on 4-byte).
     *
     * <p>Cached per flyweight until the next {@code fillFromSegment} refill, so repeated
     * reads in one {@code policy}/{@code schedule} call allocate at most once.
     */
    @SuppressWarnings("unchecked")
    public <E extends Record> E ext(Class<E> type) {
        if (cachedExtType == type && cachedExt != null) {
            return (E) cachedExt;
        }
        E view = buildExtView(type);
        cachedExt = view;
        cachedExtType = type;
        return view;
    }

    private <E extends Record> E buildExtView(Class<E> type) {
        var comps = type.getRecordComponents();
        Object[] args = new Object[comps.length];
        Class<?>[] paramTypes = new Class<?>[comps.length];
        int off = 0;
        for (int i = 0; i < comps.length; i++) {
            Class<?> ct = comps[i].getType();
            paramTypes[i] = ct;
            if (ct == long.class) {
                off = align(off, 8);
                args[i] = extLong(off);
                off += 8;
            } else if (ct == int.class) {
                off = align(off, 4);
                args[i] = extInt(off);
                off += 4;
            } else {
                throw new IllegalArgumentException(
                    "@TaskExtension record components must be long or int, got " + ct + " in " + type);
            }
        }
        try {
            return type.getDeclaredConstructor(paramTypes).newInstance(args);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot build extension view for " + type, e);
        }
    }

    private static int align(int off, int to) {
        int rem = off % to;
        return rem == 0 ? off : off + (to - rem);
    }
```

Reset the cache on refill: at the top of `fillFromSegment`, after the method opening brace, add `out.cachedExt = null;`. Place it as the first statement:

```java
    public static void fillFromSegment(MemorySegment seg, QueuedTask out) {
        out.cachedExt = null;
        out.pid           = seg.get(ValueLayout.JAVA_INT,  QT_PID);
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=TaskExtensionTest -q`
Expected: PASS — all four tests green.

- [ ] **Step 7: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/QueuedTask.java \
        bpf/src/test/java/me/bechberger/ebpf/bpf/TaskExtensionTest.java
git commit -m "feat(userspace): carry fixed EXT_CAP tail on QueuedTask with typed ext() view"
```

---

## Task 4: Guard the wire contract — extend marshalling test

**Files:**
- Modify: `bpf/src/test/java/me/bechberger/ebpf/bpf/QueuedTaskDispatchedTaskMarshallingTest.java`

- [ ] **Step 1: Read the current test to find the round-trip test method**

Run: `./scripts/ts.sh --no-tty 'grep -n "QT_SIZEOF\|byteSize\|allocate\|@Test" bpf/src/test/java/me/bechberger/ebpf/bpf/QueuedTaskDispatchedTaskMarshallingTest.java'`
Expected: prints the test methods and any existing size references. (This confirms whether the test already references `QT_SIZEOF=88` locally or via the constant.)

- [ ] **Step 2: Add a wire-contract assertion test**

Add this test method inside `QueuedTaskDispatchedTaskMarshallingTest` (anywhere among the other `@Test` methods):

```java
    @Test
    void extensionTailKeepsPrefixStableAndBoundsTotalSize() {
        // The stable rustland-compatible prefix is exactly 88 bytes and must not move.
        assertEquals(88L, QueuedTask.QT_SIZEOF, "88-byte prefix is the wire contract");
        // The extension tail is a fixed 64 bytes → total record is 152 bytes.
        assertEquals(64, QueuedTask.EXT_CAP, "EXT_CAP is the agreed tail size");
        // 4 MiB ring / 152 B ≈ 27k records — still absorbs a fork storm (see design doc).
        assertEquals(152L, QueuedTask.QT_SIZEOF + QueuedTask.EXT_CAP);

        // An 88-byte (extension-less) segment must still fill cleanly with a zeroed tail.
        try (var arena = java.lang.foreign.Arena.ofConfined()) {
            var seg = arena.allocate(QueuedTask.QT_SIZEOF);
            seg.set(java.lang.foreign.ValueLayout.JAVA_INT, 0, 77);
            var t = new QueuedTask();
            QueuedTask.fillFromSegment(seg, t);
            assertEquals(77, t.pid);
            assertEquals(0L, t.extLong(0), "extension-less record has a zeroed tail");
        }
    }
```

If the test file does not already `import static org.junit.jupiter.api.Assertions.assertEquals;`, confirm it does (the existing round-trip tests will already use it).

- [ ] **Step 3: Run the full marshalling test class**

Run: `./scripts/ts.sh ./mvnw -pl bpf -am test -Dtest=QueuedTaskDispatchedTaskMarshallingTest -q`
Expected: PASS — existing prefix round-trip tests plus the new size/back-compat assertions all green.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/QueuedTaskDispatchedTaskMarshallingTest.java
git commit -m "test(userspace): assert 88-byte prefix stable and 88+EXT_CAP total record size"
```

---

## Task 5: BPF-side tail + `fillExtension` hook

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java`

- [ ] **Step 1: Add the tail field to `QueuedTaskCtx` and an `EXT_CAP` constant**

In `UserspaceSchedulerBase.java`, locate the `@Type ... class QueuedTaskCtx` declaration (fields `pid`…`@Size(16) byte[] comm`). Add an `EXT_CAP` constant just above the class and a fixed tail as the last field:

```java
    /** Fixed extension-tail size (bytes) appended after the 88-byte prefix. MUST equal QueuedTask.EXT_CAP. */
    public static final int EXT_CAP = 64;

    @Type
    static class QueuedTaskCtx {
        int pid;
        int prevCpu;
        @Unsigned long nrCpusAllowed;
        @Unsigned long flags;
        @Unsigned long startTs;
        @Unsigned long stopTs;
        @Unsigned long execRuntime;
        @Unsigned long weight;
        @Unsigned long vtime;
        @Unsigned long enqCnt;
        @Size(16) byte[] comm;
        @Size(EXT_CAP) byte[] ext;   // per-task extension tail; zeroed unless fillExtension writes it
    }
```

(Keep the existing field order and annotations exactly; only append the `ext` field and add the constant.)

- [ ] **Step 2: Add the overridable no-op fill hook**

Near `fillQueuedCtx` (the `@BPFFunction void fillQueuedCtx(Ptr<QueuedTaskCtx> evt, Ptr<task_struct> p, long enq_flags)` method), add a no-op default hook:

```java
    /**
     * Fill the per-task extension tail. Default is a no-op (tail stays zeroed).
     * Override in a scheduler subclass to write custom BPF-computed fields into
     * {@code evt.val().ext}. Runs in {@code enqueue} context: non-sleepable, hot —
     * keep it to a few bounded field reads.
     */
    @BPFFunction
    public void fillExtension(Ptr<QueuedTaskCtx> evt, Ptr<task_struct> p) {
        // default: no extension
    }
```

- [ ] **Step 3: Call the hook in the enqueue path before submit**

In `enqueue(Ptr<task_struct> p, long enq_flags)`, after `fillQueuedCtx(evt, p, enq_flags);` and before the `submit`/`submitNoWakeup` calls, insert the hook call:

```java
        fillQueuedCtx(evt, p, enq_flags);
        fillExtension(evt, p);
        if (nrUserPending.get() > 0) queued.submitNoWakeup(evt);
        else                         queued.submit(evt);
```

- [ ] **Step 4: Rebuild the bpf module (plugin-bundled jar) on thinkstation**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf-processor -am install -q -DskipTests && ./scripts/ts.sh ./mvnw -pl bpf -am install -q -DskipTests`
Expected: BUILD SUCCESS. (bpf-processor first, then bpf — the bpf jar bundles the plugin, so the plugin must be installed first. See repo memory `bpf_jar_shadows_compiler_plugin`.)

- [ ] **Step 5: Verify the generated BPF C struct picks up the tail**

Run: `./scripts/ts.sh --no-tty 'find bpf/target -name "*.c" -newer bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java 2>/dev/null | head; grep -rn "queued_task_ctx" bpf/target/generated-sources 2>/dev/null | head'`
Expected: the generated struct for `queued_task_ctx` now includes a 64-byte `ext` array member (`char ext[64]` or `__u8 ext[64]`). If generated sources aren't under `bpf/target`, this step is informational only — the authoritative check is the kernel smoke test in the sample task.

- [ ] **Step 6: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java
git commit -m "feat(userspace): reserve EXT_CAP tail in QueuedTaskCtx and add fillExtension hook"
```

---

## Task 6: `CgroupAwareSample` — end-to-end demo

**Files:**
- Create: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/CgroupAwareSample.java`

- [ ] **Step 1: Find an existing sample to mirror the boilerplate**

Run: `./scripts/ts.sh --no-tty 'ls bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/ && sed -n "1,60p" bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java'`
Expected: prints the sample package contents and the minimal scheduler's class/`main`/`policy` skeleton to copy the attach + `runUntilExit` idiom from.

- [ ] **Step 2: Write the sample**

Create `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/CgroupAwareSample.java`. Use `MinimalScheduler` as the structural template (same package, same `@BPF(license="GPL")` + `extends UserspaceScheduler` shape, same `main`). The extension-specific pieces are:

```java
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.TaskExtension;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.UserspaceSchedulerBase.QueuedTaskCtx;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.runtime.task_struct;

@BPF(license = "GPL")
public abstract class CgroupAwareSample extends UserspaceScheduler {

    /** Typed read view over the extension tail. long cgroupId at tail+0, long ppid at tail+8. */
    @TaskExtension
    public record CgroupExt(long cgroupId, long ppid) {}

    private static final int ANY_CPU = -1;

    // BPF fill hook: runs in enqueue context, writes the tail. Bind the non-identifier
    // CO-RE root to a local first (see repo memory on preserve_access_index).
    @Override
    @BPFFunction
    public void fillExtension(Ptr<QueuedTaskCtx> evt, Ptr<task_struct> p) {
        long cgId = BPFHelpers.BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id);
        evt.val().ext_setLong(0, cgId);        // see note below on tail writes
        long ppid = p.val().real_parent.val().tgid;
        evt.val().ext_setLong(8, ppid);
    }

    @Override
    protected int policy(QueuedTask t) {
        CgroupExt ext = t.ext(CgroupExt.class);
        // Trivial demo policy: everything to ANY_CPU; the point is that cgroupId is observed.
        return ANY_CPU;
    }

    public static void main(String[] args) throws Exception {
        try (var sched = BPF.load(CgroupAwareSample.class)) {
            sched.attachScheduler();
            sched.runUntilExit(new Opts());
        }
    }
}
```

**Note on tail writes from BPF:** the `evt.val().ext` field is a `@Size(64) byte[]`. Writing typed values into it from the BPF fill hook requires either (a) declaring a parallel `@Type CgroupExtCtx { @Unsigned long cgroupId; @Unsigned long ppid; }` and casting the tail pointer to it, or (b) a small `@BuiltinBPFFunction` helper `ext_setLong(offset, value)`. Before finalizing this sample, verify which idiom the codebase supports for writing a struct view over a byte-array field:

Run: `./scripts/ts.sh --no-tty 'grep -rn "bpf_probe_read\|memcpy\|__builtin_memcpy\|Ptr.*cast\|reinterpret" bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java | head'`

- [ ] **Step 3: Resolve the tail-write idiom (decision point)**

If the codebase supports casting a `Ptr` to a struct type over the byte array, replace the `ext_setLong` calls with:

```java
    @Type
    static class CgroupExtCtx { @Unsigned long cgroupId; @Unsigned long ppid; }

    @Override
    @BPFFunction
    public void fillExtension(Ptr<QueuedTaskCtx> evt, Ptr<task_struct> p) {
        Ptr<CgroupExtCtx> e = evt.val().ext;   // tail bytes reinterpreted as the ext struct
        long cgId = BPFHelpers.BPF_CORE_READ(p, cgroups, dfl_cgrp, kn, id);
        e.val().cgroupId = cgId;
        e.val().ppid = p.val().real_parent.val().tgid;
    }
```

Pick whichever idiom compiles. Confirm with a build:

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf-samples -am compile -q`
Expected: BUILD SUCCESS. If the `Ptr` reinterpret does not compile, fall back to a `@BuiltinBPFFunction` byte-writer helper on `UserspaceSchedulerBase` and use idiom (a). Add whichever helper is needed to `UserspaceSchedulerBase` in this same task and re-run the bpf-processor+bpf install from Task 5 Step 4.

- [ ] **Step 4: Kernel smoke test on thinkstation (root via vng)**

Run: `./scripts/ts.sh ./scripts/run-tests-vng.sh CgroupAwareSample 2>&1 | tail -40`
(If `CgroupAwareSample` has no test class yet, run it directly under vng as root instead — mirror how other `*Sample` mains are smoke-run on thinkstation. If the sample is main-only, this step is a manual attach check: attach, run a `sleep`-in-a-cgroup workload, assert the log shows a non-zero `cgroupId`.)
Expected: scheduler attaches, drains tasks, and the observed `cgroupId` for a cgroup-confined process is non-zero. No verifier rejection, no reference leak.

- [ ] **Step 5: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/CgroupAwareSample.java \
        bpf/src/main/java/me/bechberger/ebpf/bpf/UserspaceSchedulerBase.java
git commit -m "feat(samples): CgroupAwareSample demonstrates @TaskExtension end-to-end"
```

---

## Task 7: Full regression + follow-up note

**Files:**
- (none — verification + doc note)

- [ ] **Step 1: Run the full bpf module test suite (pure-Java + marshalling)**

Run: `./scripts/sync.sh && ./scripts/ts.sh ./mvnw -pl bpf -am test -q`
Expected: BUILD SUCCESS — no regressions in the marshalling/round-trip suite. (Kernel-attach tests that need root are covered by the vng runner in Task 6.)

- [ ] **Step 2: Record the deferred compiler-plugin auto-generation as a follow-up**

Append a short "Follow-ups" note to the design doc so the deferred piece isn't lost. Edit `docs/superpowers/specs/2026-07-19-userland-a-task-metadata-design.md`, adding at the end:

```markdown
## Follow-ups (post-v1)

- **Compiler-plugin auto-generation:** v1 requires the author to declare both the
  `@TaskExtension` Java record and (for the BPF fill hook) either a parallel `@Type`
  struct or byte-writer helpers. A follow-up should make the bpf-processor generate the
  BPF `@Type` and the Java offset table directly from the `@TaskExtension` record, so the
  record is the single source of truth.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-07-19-userland-a-task-metadata-design.md
git commit -m "docs(userspace): note deferred @TaskExtension plugin auto-generation follow-up"
```

---

## Self-review notes

- **Spec coverage:** wire layout (Task 3/4), author-facing `@TaskExtension` + `ext()` (Tasks 1/3), BPF fill hook (Task 5), copy() carries tail (Task 3 Step 2), marshalling guard (Task 4), back-compat 88-byte record (Task 4 Step 2), kernel end-to-end demo (Task 6). The one spec item intentionally deferred is compiler-plugin auto-generation of the `@Type` — captured in Task 7 Step 2.
- **Type consistency:** `EXT_CAP = 64` used identically in `QueuedTask` (Java `int`), `UserspaceSchedulerBase.QueuedTaskCtx` (BPF `@Size`), and both test assertions. `QT_SIZEOF = 88` is the single prefix constant. `ext(Class<E extends Record>)`, `extLong(int)`, `extInt(int)`, `extByte(int)` names are consistent across QueuedTask and the tests.
- **Open risk surfaced in Task 6:** the BPF tail-write idiom (Ptr reinterpret vs. parallel `@Type` vs. byte-writer helper) is resolved by an explicit build-check decision point rather than assumed, because the codebase's support for reinterpreting a `@Size` byte array as a struct pointer is not yet confirmed.
