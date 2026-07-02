# Features.hasX Runtime BPF Capability Detection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a cached, lazy `Features.hasX(...)` API that answers "does this kernel support X?" (program type, map type, helper, kfunc, struct_ops name, attach type) before the syscall fires, and wire it into `BPFProgram.load()` so callers get `BPFLoadError.UnsupportedKernel(...)` instead of a cryptic verifier reject.

**Architecture:** A new package `me.bechberger.ebpf.bpf.features` under the `bpf` module. `Features` static entry points delegate to per-kind `Probe` classes; results are cached in a `ConcurrentHashMap<ProbeKey, ProbeResult>` for the JVM lifetime. Probe kernel mechanisms: `bpf_prog_load` for program types and helpers, `bpf_map_create` for map types, `bpf_link_create` with a nonsense fd for attach types, vmlinux BTF scan for kfuncs and struct_ops. `BPFProgram.load()` grows a pre-syscall feature check that walks a program's declared requirements.

**Tech Stack:** Java 25, Panama FFI via hand-rolled `me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno<R>` downcall wrappers (the codebase does NOT use jextract — see `BPFProgram.java:370` for the established pattern), JUnit 5, virtme-ng for real-kernel tests. Kernel floor is 6.14+.

**Spec:** `docs/superpowers/specs/2026-07-02-feature-detection-design.md`.

**Operational constraints — MUST follow verbatim:**

- Builds/tests run only on thinkstation. Never `mvn` locally on the mac. File edits happen on the mac; only builds/tests go to thinkstation.
- Thinkstation invocation shape (edits stay local, only build/test goes remote):
  ```
  ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl <module> -am <goal>'
  ```
- Any change under `bpf-processor/` or `bpf-compiler-plugin/` requires rebuilding `bpf` too (the `bpf` jar shadows the compiler plugin). In tasks that touch the plugin, the build command must be `mvn -pl bpf-compiler-plugin,bpf -am install`. No plugin changes are expected in this plan, but flag it if a probe emits generated C.
- Real-kernel tests boot under vng. Prefer the wrapper: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh ClassName'` (from the mac). For raw ssh invocation shape, use `ssh thinkstation ...` with the env prefix above.
- Kernel floor is 6.14+. No back-compat shims for older kernels.
- Conventional commits, no Claude authorship trailers, no emoji.
- No emoji anywhere in code, comments, commit messages, or this plan.

---

## File Structure

New package `bpf/src/main/java/me/bechberger/ebpf/bpf/features/`:
- `Features.java` — public static entry points, cache, dispatcher.
- `ProbeResult.java` — sealed interface with three records.
- `ProbeKey.java` — sealed interface with six record variants.
- `KernelVersion.java` — record with `atLeast(int, int)` and `parse(String)`.
- `BPFProgramType.java` — enum with `id` field.
- `BPFAttachType.java` — enum with `id` field.
- `BPFHelper.java` — enum with `id` field and `carrierProgramType`.
- `probes/ProgramTypeProbe.java` — `bpf_prog_load` with 2-insn "r0=0; exit" program.
- `probes/MapTypeProbe.java` — `bpf_map_create` with per-kind sizes.
- `probes/HelperProbe.java` — `bpf_prog_load` with helper call insn.
- `probes/KfuncProbe.java` — vmlinux BTF scan.
- `probes/StructOpsProbe.java` — vmlinux BTF scan for STRUCT name.
- `probes/AttachTypeProbe.java` — `bpf_link_create` dry-run with fd=-1.
- `probes/BtfLoader.java` — cached loader for `/sys/kernel/btf/vmlinux`.
- `probes/ProbeSyscallCounter.java` — package-private counter for cache tests.

Modified:
- `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — new `UnsupportedKernel` nested error class; `load()` gains a feature-check hook.

Tests under `bpf/src/test/java/me/bechberger/ebpf/bpf/features/`:
- `KernelVersionTest.java` — parse cases (mac-safe).
- `ProbeKeyTest.java` — equality / hashCode (mac-safe).
- `FeaturesCacheTest.java` — cache miss/hit/reset (mac-safe, uses stub probe).
- `FeaturesSnapshotTest.java` — snapshot map contents (real-kernel).
- `FeaturesProgramTypeTest.java` — probe every known program type (real-kernel).
- `FeaturesMapTypeTest.java` — probe every known map type (real-kernel).
- `FeaturesHelperTest.java` — probe every known helper (real-kernel).
- `FeaturesKfuncTest.java` — hit + miss (real-kernel).
- `FeaturesStructOpsTest.java` — hit + miss (real-kernel).
- `FeaturesAttachTypeTest.java` — hit + miss (real-kernel).
- `FeatureGatedLoadTest.java` — end-to-end load-path integration (real-kernel).

Sample:
- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/FeatureProbeSample.java` — prints snapshot table + kernel version, optionally loads a `STRUCT_OPS` program.

---

## Task 0: Inventory existing FFI wrappers (no code changes)

**Files (read-only exploration):**
- Read: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` — search for `HandlerWithErrno` declarations.
- Read: `shared/src/main/java/me/bechberger/ebpf/shared/PanamaUtil.java` — study `HandlerWithErrno<R>`, `POINTER`, `ResultAndErr<R>`, `lookup(String)`.
- Read: `shared/src/main/java/me/bechberger/ebpf/shared/LibC.java` — pattern for wrapping libc symbols with `close(int)` already provided.

- [ ] **Step 1: Confirm the FFI convention is HandlerWithErrno, not jextract**

The `rawbpf` project on disk is legacy and is NOT in the parent pom's `<module>` list. All new libbpf/BTF wrappers in this plan MUST use hand-rolled `HandlerWithErrno<R>` per the established pattern:

```
grep -n "HandlerWithErrno\|PanamaUtil" bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java | head -30
grep -n "class HandlerWithErrno\|ResultAndErr\|POINTER" shared/src/main/java/me/bechberger/ebpf/shared/PanamaUtil.java
```

Expected: `BPFProgram` has ~13 `HandlerWithErrno<?>` fields at lines 370, 374, 549, 583, 681, 1020, 1103, 1135, 1158, 1243, 1813; `BPFRingBuffer` has 4 more. Confirm the invocation shape: `HANDLE.call(arena, arg1, arg2, ...)` returns `PanamaUtil.ResultAndErr<R>` — use `.result()` for the return value and `.err()` for the errno.

- [ ] **Step 2: Confirm the libbpf symbols this plan needs are exported**

```
ssh thinkstation 'nm -D /usr/lib/x86_64-linux-gnu/libbpf.so.1 2>/dev/null | grep -E " T (bpf_prog_load|bpf_map_create|bpf_link_create|btf__parse|btf__find_by_name_kind|btf__name_by_offset|btf__type_by_id|btf__type_cnt|libbpf_get_error)$"'
```

Expected: every symbol above resolves to a `T` (exported text) entry. These are the only new libbpf handles the plan introduces; each will be a fresh `HandlerWithErrno<>` in the appropriate probe class.

- [ ] **Step 3: Confirm `/sys/kernel/btf/vmlinux` is readable and no code currently reads it**

```
ssh thinkstation 'ls -la /sys/kernel/btf/vmlinux'
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && grep -rn "/sys/kernel/btf" --include="*.java" bpf shared || echo "no prior references"'
```

Expected: file exists and is world-readable (mode 444). No Java references. Result: BTF loading path is greenfield; use `btf__parse` via `HandlerWithErrno<MemorySegment>` on `/sys/kernel/btf/vmlinux`.

- [ ] **Step 4: Confirm `KernelFeatures.currentKernelVersion` exists in `shared`**

Read `shared/src/main/java/me/bechberger/ebpf/shared/KernelFeatures.java`. The new `KernelVersion` record in this plan lives in the `bpf.features` package and is a proper triple (major, minor, patch, raw) with `atLeast(major, minor)`. The two are distinct — the existing shared record is (major, minor) only and stays. `Features.kernelVersion()` returns the new one and does its own parsing.

- [ ] **Step 5: No commit (research only)**

Task 0 is research only. Skip the commit; proceed to Task 1 without touching git. Record findings in the plan file if any deviation from assumptions surfaces.

---

## Task 1: Add BPFProgramType enum

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFProgramType.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFProgramTypeTest.java`

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFProgramTypeTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFProgramTypeTest {
    @Test
    void idsMatchUapi() {
        assertEquals(0,  BPFProgramType.UNSPEC.id());
        assertEquals(1,  BPFProgramType.SOCKET_FILTER.id());
        assertEquals(2,  BPFProgramType.KPROBE.id());
        assertEquals(6,  BPFProgramType.XDP.id());
        assertEquals(26, BPFProgramType.TRACING.id());
        assertEquals(27, BPFProgramType.STRUCT_OPS.id());
        assertEquals(29, BPFProgramType.LSM.id());
        assertEquals(31, BPFProgramType.SYSCALL.id());
        assertEquals(32, BPFProgramType.NETFILTER.id());
    }

    @Test
    void fromIdRoundTrip() {
        for (var t : BPFProgramType.values()) {
            assertEquals(t, BPFProgramType.fromId(t.id()));
        }
        assertNull(BPFProgramType.fromId(9999));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=BPFProgramTypeTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — `BPFProgramType` class not found.

- [ ] **Step 3: Write the enum**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFProgramType.java
package me.bechberger.ebpf.bpf.features;

import org.jetbrains.annotations.Nullable;

/** Kernel BPF program types. Values match {@code uapi/linux/bpf.h} enum bpf_prog_type. */
public enum BPFProgramType {
    UNSPEC(0), SOCKET_FILTER(1), KPROBE(2), SCHED_CLS(3), SCHED_ACT(4),
    TRACEPOINT(5), XDP(6), PERF_EVENT(7), CGROUP_SKB(8), CGROUP_SOCK(9),
    LWT_IN(10), LWT_OUT(11), LWT_XMIT(12), SOCK_OPS(13), SK_SKB(14),
    CGROUP_DEVICE(15), SK_MSG(16), RAW_TRACEPOINT(17), CGROUP_SOCK_ADDR(18),
    LWT_SEG6LOCAL(19), LIRC_MODE2(20), SK_REUSEPORT(21), FLOW_DISSECTOR(22),
    CGROUP_SYSCTL(23), RAW_TRACEPOINT_WRITABLE(24), CGROUP_SOCKOPT(25),
    TRACING(26), STRUCT_OPS(27), EXT(28), LSM(29), SK_LOOKUP(30),
    SYSCALL(31), NETFILTER(32);

    private final int id;
    BPFProgramType(int id) { this.id = id; }
    public int id() { return id; }

    public static @Nullable BPFProgramType fromId(int id) {
        for (var t : values()) if (t.id == id) return t;
        return null;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=BPFProgramTypeTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFProgramType.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFProgramTypeTest.java
git commit -m "feat(features): add BPFProgramType enum with uapi ids"
```

---

## Task 2: Add BPFAttachType enum

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFAttachType.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFAttachTypeTest.java`

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFAttachTypeTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFAttachTypeTest {
    @Test
    void idsMatchUapi() {
        assertEquals(0,  BPFAttachType.CGROUP_INET_INGRESS.id());
        assertEquals(1,  BPFAttachType.CGROUP_INET_EGRESS.id());
        assertEquals(24, BPFAttachType.TRACE_FENTRY.id());
        assertEquals(25, BPFAttachType.TRACE_FEXIT.id());
        assertEquals(42, BPFAttachType.TRACE_KPROBE_MULTI.id());
        assertEquals(46, BPFAttachType.TCX_INGRESS.id());
        assertEquals(47, BPFAttachType.TCX_EGRESS.id());
    }

    @Test
    void fromIdRoundTrip() {
        for (var t : BPFAttachType.values()) {
            assertEquals(t, BPFAttachType.fromId(t.id()));
        }
        assertNull(BPFAttachType.fromId(9999));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=BPFAttachTypeTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL.

- [ ] **Step 3: Write the enum**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFAttachType.java
package me.bechberger.ebpf.bpf.features;

import org.jetbrains.annotations.Nullable;

/** BPF attach types. Values match {@code uapi/linux/bpf.h} enum bpf_attach_type. */
public enum BPFAttachType {
    CGROUP_INET_INGRESS(0), CGROUP_INET_EGRESS(1), CGROUP_INET_SOCK_CREATE(2),
    CGROUP_SOCK_OPS(3), SK_SKB_STREAM_PARSER(4), SK_SKB_STREAM_VERDICT(5),
    CGROUP_DEVICE(6), SK_MSG_VERDICT(7), CGROUP_INET4_BIND(8),
    CGROUP_INET6_BIND(9), CGROUP_INET4_CONNECT(10), CGROUP_INET6_CONNECT(11),
    CGROUP_INET4_POST_BIND(12), CGROUP_INET6_POST_BIND(13),
    CGROUP_UDP4_SENDMSG(14), CGROUP_UDP6_SENDMSG(15), LIRC_MODE2(16),
    FLOW_DISSECTOR(17), CGROUP_SYSCTL(18), CGROUP_UDP4_RECVMSG(19),
    CGROUP_UDP6_RECVMSG(20), CGROUP_GETSOCKOPT(21), CGROUP_SETSOCKOPT(22),
    TRACE_RAW_TP(23), TRACE_FENTRY(24), TRACE_FEXIT(25), MODIFY_RETURN(26),
    LSM_MAC(27), TRACE_ITER(28), CGROUP_INET4_GETPEERNAME(29),
    CGROUP_INET6_GETPEERNAME(30), CGROUP_INET4_GETSOCKNAME(31),
    CGROUP_INET6_GETSOCKNAME(32), XDP_DEVMAP(33), CGROUP_INET_SOCK_RELEASE(34),
    XDP_CPUMAP(35), SK_LOOKUP(36), XDP(37), SK_SKB_VERDICT(38),
    SK_REUSEPORT_SELECT(39), SK_REUSEPORT_SELECT_OR_MIGRATE(40),
    PERF_EVENT(41), TRACE_KPROBE_MULTI(42), LSM_CGROUP(43), STRUCT_OPS(44),
    NETFILTER(45), TCX_INGRESS(46), TCX_EGRESS(47),
    TRACE_UPROBE_MULTI(48), CGROUP_UNIX_CONNECT(49), CGROUP_UNIX_SENDMSG(50),
    CGROUP_UNIX_RECVMSG(51), CGROUP_UNIX_GETPEERNAME(52),
    CGROUP_UNIX_GETSOCKNAME(53), NETKIT_PRIMARY(54), NETKIT_PEER(55);

    private final int id;
    BPFAttachType(int id) { this.id = id; }
    public int id() { return id; }

    public static @Nullable BPFAttachType fromId(int id) {
        for (var t : values()) if (t.id == id) return t;
        return null;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=BPFAttachTypeTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFAttachType.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFAttachTypeTest.java
git commit -m "feat(features): add BPFAttachType enum with uapi ids"
```

---

## Task 3: Add BPFHelper enum

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFHelper.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFHelperTest.java`

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFHelperTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFHelperTest {
    @Test
    void idsMatchUapi() {
        assertEquals(1,   BPFHelper.MAP_LOOKUP_ELEM.id());
        assertEquals(2,   BPFHelper.MAP_UPDATE_ELEM.id());
        assertEquals(6,   BPFHelper.TRACE_PRINTK.id());
        assertEquals(12,  BPFHelper.TAIL_CALL.id());
        assertEquals(131, BPFHelper.RINGBUF_RESERVE.id());
        assertEquals(132, BPFHelper.RINGBUF_SUBMIT.id());
    }

    @Test
    void everyHelperHasACarrier() {
        for (var h : BPFHelper.values()) {
            assertNotNull(h.carrierProgramType(), "no carrier: " + h);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=BPFHelperTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — class not found.

- [ ] **Step 3: Write the enum**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFHelper.java
package me.bechberger.ebpf.bpf.features;

/**
 * Commonly-probed BPF helpers. Ids match kernel {@code BPF_FUNC_*} numbering.
 * The {@code carrierProgramType} names a program type known to allow the helper
 * so the probe can build a synthetic loader.
 */
public enum BPFHelper {
    MAP_LOOKUP_ELEM(1,   BPFProgramType.SOCKET_FILTER),
    MAP_UPDATE_ELEM(2,   BPFProgramType.SOCKET_FILTER),
    MAP_DELETE_ELEM(3,   BPFProgramType.SOCKET_FILTER),
    PROBE_READ(4,        BPFProgramType.KPROBE),
    KTIME_GET_NS(5,      BPFProgramType.SOCKET_FILTER),
    TRACE_PRINTK(6,      BPFProgramType.KPROBE),
    GET_PRANDOM_U32(7,   BPFProgramType.SOCKET_FILTER),
    GET_SMP_PROCESSOR_ID(8, BPFProgramType.SOCKET_FILTER),
    TAIL_CALL(12,        BPFProgramType.SOCKET_FILTER),
    GET_CURRENT_PID_TGID(14, BPFProgramType.KPROBE),
    GET_CURRENT_UID_GID(15,  BPFProgramType.KPROBE),
    GET_CURRENT_COMM(16, BPFProgramType.KPROBE),
    PERF_EVENT_OUTPUT(25, BPFProgramType.KPROBE),
    GET_STACK(27,        BPFProgramType.KPROBE),
    PERF_EVENT_READ_VALUE(29, BPFProgramType.KPROBE),
    PROBE_READ_STR(45,   BPFProgramType.KPROBE),
    RINGBUF_OUTPUT(130,  BPFProgramType.SOCKET_FILTER),
    RINGBUF_RESERVE(131, BPFProgramType.SOCKET_FILTER),
    RINGBUF_SUBMIT(132,  BPFProgramType.SOCKET_FILTER),
    RINGBUF_DISCARD(133, BPFProgramType.SOCKET_FILTER),
    RINGBUF_QUERY(134,   BPFProgramType.SOCKET_FILTER),
    LOOP(181,            BPFProgramType.KPROBE),
    STRNCMP(182,         BPFProgramType.SOCKET_FILTER),
    KPTR_XCHG(194,       BPFProgramType.KPROBE),
    DYNPTR_FROM_MEM(197, BPFProgramType.SOCKET_FILTER),
    RINGBUF_RESERVE_DYNPTR(198, BPFProgramType.SOCKET_FILTER),
    RINGBUF_SUBMIT_DYNPTR(199,  BPFProgramType.SOCKET_FILTER),
    RINGBUF_DISCARD_DYNPTR(200, BPFProgramType.SOCKET_FILTER);

    private final int id;
    private final BPFProgramType carrier;

    BPFHelper(int id, BPFProgramType carrier) {
        this.id = id;
        this.carrier = carrier;
    }

    public int id() { return id; }
    public BPFProgramType carrierProgramType() { return carrier; }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=BPFHelperTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/BPFHelper.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFHelperTest.java
git commit -m "feat(features): add BPFHelper enum with carrier prog types"
```

---

## Task 4: Add ProbeResult sealed hierarchy

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/ProbeResult.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/ProbeResultTest.java`

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/ProbeResultTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ProbeResultTest {
    @Test
    void patternMatchExhaustive() {
        ProbeResult r = new ProbeResult.Supported();
        String s = switch (r) {
            case ProbeResult.Supported() -> "yes";
            case ProbeResult.Unsupported u -> "no: " + u.reason();
            case ProbeResult.ProbeUnavailable u -> "cannot: " + u.reason();
        };
        assertEquals("yes", s);
    }

    @Test
    void isSupportedHelper() {
        assertTrue(new ProbeResult.Supported().isSupported());
        assertFalse(new ProbeResult.Unsupported("nope").isSupported());
        assertFalse(new ProbeResult.ProbeUnavailable("EPERM").isSupported());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=ProbeResultTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — class not found.

- [ ] **Step 3: Write the sealed interface**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/ProbeResult.java
package me.bechberger.ebpf.bpf.features;

/**
 * Outcome of a single feature probe.
 *
 * <p>Distinguishes three cases:
 * <ul>
 *   <li>{@link Supported} — the kernel accepted the probe.</li>
 *   <li>{@link Unsupported} — the kernel rejected it with a features-related errno.</li>
 *   <li>{@link ProbeUnavailable} — the probe itself could not be performed
 *       (missing capabilities, LSM lockdown, unreadable BTF).</li>
 * </ul>
 */
public sealed interface ProbeResult {

    record Supported() implements ProbeResult {}
    record Unsupported(String reason) implements ProbeResult {}
    record ProbeUnavailable(String reason) implements ProbeResult {}

    /** {@code true} only for {@link Supported}. */
    default boolean isSupported() { return this instanceof Supported; }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=ProbeResultTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/ProbeResult.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/ProbeResultTest.java
git commit -m "feat(features): add ProbeResult sealed hierarchy"
```

---

## Task 5: Add ProbeKey sealed hierarchy

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/ProbeKey.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/ProbeKeyTest.java`

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/ProbeKeyTest.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ProbeKeyTest {
    @Test
    void equalityHonoursDiscriminant() {
        ProbeKey a = new ProbeKey.ProgramTypeKey(BPFProgramType.XDP);
        ProbeKey b = new ProbeKey.ProgramTypeKey(BPFProgramType.XDP);
        ProbeKey c = new ProbeKey.ProgramTypeKey(BPFProgramType.KPROBE);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }

    @Test
    void kfuncKeyIncludesModuleName() {
        ProbeKey a = new ProbeKey.KfuncKey("f", null);
        ProbeKey b = new ProbeKey.KfuncKey("f", null);
        ProbeKey c = new ProbeKey.KfuncKey("f", "mymod");
        assertEquals(a, b);
        assertNotEquals(a, c);
    }

    @Test
    void differentVariantsNeverEqual() {
        assertNotEquals(
            new ProbeKey.ProgramTypeKey(BPFProgramType.XDP),
            new ProbeKey.MapTypeKey(MapTypeId.HASH));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=ProbeKeyTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — class not found.

- [ ] **Step 3: Write the sealed interface**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/ProbeKey.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.jetbrains.annotations.Nullable;

/**
 * Cache key discriminant for {@link Features}' probe cache.
 * One record per probe kind; record equality gives us the map key semantics
 * for free.
 */
public sealed interface ProbeKey {

    record ProgramTypeKey(BPFProgramType t)             implements ProbeKey {}
    record MapTypeKey(MapTypeId t)                      implements ProbeKey {}
    record HelperKey(BPFHelper h)                       implements ProbeKey {}
    record KfuncKey(String name, @Nullable String mod)  implements ProbeKey {}
    record StructOpsKey(String name)                    implements ProbeKey {}
    record AttachTypeKey(BPFAttachType t)               implements ProbeKey {}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=ProbeKeyTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/ProbeKey.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/ProbeKeyTest.java
git commit -m "feat(features): add ProbeKey sealed hierarchy"
```

---

## Task 6: Add KernelVersion record and parser

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/KernelVersion.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/KernelVersionTest.java`

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/KernelVersionTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KernelVersionTest {
    @Test
    void parsesTripleWithSuffix() {
        var v = KernelVersion.parse("6.17.0-35-generic");
        assertEquals(6, v.major());
        assertEquals(17, v.minor());
        assertEquals(0, v.patch());
        assertEquals("6.17.0-35-generic", v.raw());
    }

    @Test
    void parsesBareTriple() {
        var v = KernelVersion.parse("6.14.3");
        assertEquals(new KernelVersion(6, 14, 3, "6.14.3"), v);
    }

    @Test
    void parsesTwoPartFallsBackToZero() {
        var v = KernelVersion.parse("6.14");
        assertEquals(new KernelVersion(6, 14, 0, "6.14"), v);
    }

    @Test
    void atLeastMajorMinor() {
        var v = new KernelVersion(6, 17, 0, "6.17.0");
        assertTrue(v.atLeast(6, 14));
        assertTrue(v.atLeast(6, 17));
        assertFalse(v.atLeast(6, 18));
        assertFalse(v.atLeast(7, 0));
        assertTrue(v.atLeast(5, 99));
    }

    @Test
    void malformedRaisesIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> KernelVersion.parse(""));
        assertThrows(IllegalArgumentException.class, () -> KernelVersion.parse("abc"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=KernelVersionTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — class not found.

- [ ] **Step 3: Write the record and parser**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/KernelVersion.java
package me.bechberger.ebpf.bpf.features;

/**
 * Parsed kernel release triple. {@code raw} is the unparsed source string
 * (e.g. {@code "6.17.0-35-generic"}); {@code major}, {@code minor},
 * {@code patch} are decimal integers.
 *
 * <p>Kernel floor for hello-ebpf is 6.14 — the {@link #atLeast(int, int)}
 * predicate is the caller's guard against older kernels.
 */
public record KernelVersion(int major, int minor, int patch, String raw) {

    /** Parse a {@code uname -r}-style string. Rejects null / empty / non-numeric. */
    public static KernelVersion parse(String s) {
        if (s == null || s.isEmpty()) {
            throw new IllegalArgumentException("empty kernel version");
        }
        // Consume digits into fields, break at first non-digit-or-dot.
        int i = 0, n = s.length();
        int[] parts = { 0, 0, 0 };
        int field = 0;
        boolean sawDigit = false;
        while (i < n && field < 3) {
            char c = s.charAt(i);
            if (Character.isDigit(c)) {
                parts[field] = parts[field] * 10 + (c - '0');
                sawDigit = true;
                i++;
            } else if (c == '.' && sawDigit) {
                field++;
                sawDigit = false;
                i++;
            } else {
                break;
            }
        }
        if (parts[0] == 0 && parts[1] == 0 && !sawDigit && field == 0) {
            throw new IllegalArgumentException("not a kernel version: " + s);
        }
        return new KernelVersion(parts[0], parts[1], parts[2], s);
    }

    public boolean atLeast(int maj, int min) {
        if (major != maj) return major > maj;
        return minor >= min;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=KernelVersionTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/KernelVersion.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/KernelVersionTest.java
git commit -m "feat(features): add KernelVersion record with uname parser"
```

---

## Task 7: Add ProbeSyscallCounter (test-only side channel)

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/ProbeSyscallCounter.java`

Rationale: spec §11.2 asks that "same probe called twice runs only one syscall" is asserted via a side-channel counter. We add the counter now, so every probe class in later tasks can increment it in one place.

- [ ] **Step 1: Write the class**

No test for this task — it is used by cache tests. Adding without a test is acceptable because the class is trivially data-holding and its behaviour is exercised transitively by `FeaturesCacheTest` (Task 9).

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/ProbeSyscallCounter.java
package me.bechberger.ebpf.bpf.features.probes;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Package-private syscall counter used by probes and read by cache tests.
 * Every probe increments this counter exactly once per underlying syscall
 * (or once per BTF load). The counter is process-global — tests reset it
 * before running.
 */
public final class ProbeSyscallCounter {
    private ProbeSyscallCounter() {}

    private static final AtomicLong COUNT = new AtomicLong();

    public static void increment() { COUNT.incrementAndGet(); }
    public static long value()     { return COUNT.get(); }
    public static void reset()     { COUNT.set(0L); }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dmaven.test.skip=true -Dmaven.repo.local=/home/i560383/.m2/repository compile'`
Expected: BUILD SUCCESS.

- [ ] **Step 3: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/ProbeSyscallCounter.java
git commit -m "feat(features): add ProbeSyscallCounter side channel for cache tests"
```

---

## Task 8: Add Features skeleton with cache dispatcher (no probes wired yet)

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/Features.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesCacheTest.java`

This task wires the cache and dispatcher against a package-private test seam so we can prove cache semantics before writing any real probe. Later tasks replace the stub with real probe implementations.

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesCacheTest.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.features.probes.ProbeSyscallCounter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FeaturesCacheTest {

    @BeforeEach
    void reset() {
        Features.resetCacheForTest();
        ProbeSyscallCounter.reset();
        Features.setDispatcherForTest(new StubDispatcher());
    }

    @Test
    void firstCallInvokesDispatcher() {
        assertEquals(0, ProbeSyscallCounter.value());
        assertTrue(Features.hasProgramType(BPFProgramType.XDP));
        assertEquals(1, ProbeSyscallCounter.value());
    }

    @Test
    void secondCallHitsCache() {
        Features.hasProgramType(BPFProgramType.XDP);
        long after1 = ProbeSyscallCounter.value();
        Features.hasProgramType(BPFProgramType.XDP);
        assertEquals(after1, ProbeSyscallCounter.value(), "cache did not hit");
    }

    @Test
    void resetCacheForTestClears() {
        Features.hasProgramType(BPFProgramType.XDP);
        Features.resetCacheForTest();
        ProbeSyscallCounter.reset();
        Features.hasProgramType(BPFProgramType.XDP);
        assertEquals(1, ProbeSyscallCounter.value());
    }

    @Test
    void probeReturnsSameInstanceOnHit() {
        ProbeResult a = Features.probeProgramType(BPFProgramType.XDP);
        ProbeResult b = Features.probeProgramType(BPFProgramType.XDP);
        assertSame(a, b);
    }

    /** Stub dispatcher: every probe returns Supported() and increments the counter. */
    static class StubDispatcher implements Features.Dispatcher {
        @Override public ProbeResult probe(ProbeKey key) {
            ProbeSyscallCounter.increment();
            return new ProbeResult.Supported();
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=FeaturesCacheTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — class `Features` not found.

- [ ] **Step 3: Write the skeleton**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/Features.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.jetbrains.annotations.Nullable;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Runtime BPF capability probing. Every {@code hasX(...)} answers
 * "does this kernel support X?" via a cached probe.
 *
 * <p>Results are cached for the lifetime of the JVM. First call fires the
 * probe (one or two syscalls); every subsequent call hits the in-memory
 * cache. Cache reset is test-only.
 */
public final class Features {

    private Features() {}

    /** Dispatcher indirection so tests can substitute a stub. */
    interface Dispatcher {
        ProbeResult probe(ProbeKey key);
    }

    private static volatile Dispatcher dispatcher = null;  // wired in Task 15
    private static final ConcurrentHashMap<ProbeKey, ProbeResult> CACHE =
            new ConcurrentHashMap<>();

    // -- Boolean-returning convenience --------------------------------
    public static boolean hasProgramType(BPFProgramType t) {
        return probeProgramType(t).isSupported();
    }
    public static boolean hasMapType(MapTypeId t) {
        return probeMapType(t).isSupported();
    }
    public static boolean hasHelper(BPFHelper h) {
        return probeHelper(h).isSupported();
    }
    public static boolean hasKfunc(String name) {
        return probeKfunc(name, null).isSupported();
    }
    public static boolean hasKfunc(String name, String moduleName) {
        return probeKfunc(name, moduleName).isSupported();
    }
    public static boolean hasStructOps(String kernelStructName) {
        return probeStructOps(kernelStructName).isSupported();
    }
    public static boolean hasAttachType(BPFAttachType t) {
        return probeAttachType(t).isSupported();
    }

    // -- Detailed probing ---------------------------------------------
    public static ProbeResult probeProgramType(BPFProgramType t) {
        return cached(new ProbeKey.ProgramTypeKey(t));
    }
    public static ProbeResult probeMapType(MapTypeId t) {
        return cached(new ProbeKey.MapTypeKey(t));
    }
    public static ProbeResult probeHelper(BPFHelper h) {
        return cached(new ProbeKey.HelperKey(h));
    }
    public static ProbeResult probeKfunc(String name, @Nullable String moduleName) {
        return cached(new ProbeKey.KfuncKey(name, moduleName));
    }
    public static ProbeResult probeStructOps(String kernelStructName) {
        return cached(new ProbeKey.StructOpsKey(kernelStructName));
    }
    public static ProbeResult probeAttachType(BPFAttachType t) {
        return cached(new ProbeKey.AttachTypeKey(t));
    }

    // -- Kernel version -----------------------------------------------
    private static volatile KernelVersion CACHED_VERSION = null;
    public static KernelVersion kernelVersion() {
        var v = CACHED_VERSION;
        if (v != null) return v;
        try {
            String release = java.nio.file.Files.readString(
                    java.nio.file.Path.of("/proc/sys/kernel/osrelease")).trim();
            v = KernelVersion.parse(release);
        } catch (Exception e) {
            v = new KernelVersion(0, 0, 0, "unknown");
        }
        CACHED_VERSION = v;
        return v;
    }

    // -- Diagnostics --------------------------------------------------
    /**
     * Probe every commonly-checked feature and return a name-keyed snapshot.
     * Fires every probe on cold cache; on warm cache returns the cached values.
     */
    public static Map<String, ProbeResult> snapshot() {
        Map<String, ProbeResult> out = new LinkedHashMap<>();
        for (var t : BPFProgramType.values()) {
            out.put("prog:" + t.name(), probeProgramType(t));
        }
        for (var t : MapTypeId.values()) {
            out.put("map:" + t.name(), probeMapType(t));
        }
        for (var h : BPFHelper.values()) {
            out.put("helper:" + h.name(), probeHelper(h));
        }
        for (var a : BPFAttachType.values()) {
            out.put("attach:" + a.name(), probeAttachType(a));
        }
        return Collections.unmodifiableMap(out);
    }

    // -- Test hooks ---------------------------------------------------
    /** Clear the cache. Test-only. */
    static void resetCacheForTest() {
        CACHE.clear();
        CACHED_VERSION = null;
    }

    /** Substitute the dispatcher. Test-only. */
    static void setDispatcherForTest(Dispatcher d) {
        dispatcher = d;
    }

    // -- Internals ----------------------------------------------------
    private static ProbeResult cached(ProbeKey key) {
        return CACHE.computeIfAbsent(key, k -> {
            Dispatcher d = dispatcher;
            if (d == null) {
                return new ProbeResult.ProbeUnavailable(
                        "no probe dispatcher wired (running on non-Linux?)");
            }
            return d.probe(k);
        });
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=FeaturesCacheTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/Features.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesCacheTest.java
git commit -m "feat(features): add Features skeleton with cache dispatcher"
```

---

## Task 9: ProgramTypeProbe via bpf_prog_load

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/ProgramTypeProbe.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesProgramTypeTest.java` (real-kernel)

Approach per spec §6.1: load a two-instruction program (`r0 = 0; exit`). Errno mapping:
`0` -> `Supported`; `EINVAL` -> `Unsupported("unknown prog_type")`; `E2BIG` -> `Supported()` (features hit, program-size reject is confirmation); `EPERM` -> `ProbeUnavailable(...)`; other -> `Unsupported("errno=N")`.

BPF instruction encoding (LE, 8 bytes each):
- `BPF_MOV64_IMM(R0, 0)` = `0xB7 0x00 0x00 0x00 0x00 0x00 0x00 0x00`  (opcode BPF_ALU64 | BPF_MOV | BPF_K = 0xB7, dst=0, imm=0)
- `BPF_EXIT_INSN()`      = `0x95 0x00 0x00 0x00 0x00 0x00 0x00 0x00`

- [ ] **Step 1: Write the failing test (real-kernel)**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesProgramTypeTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesProgramTypeTest {

    @BeforeEach
    void reset() {
        Features.resetCacheForTest();
        Features.setDispatcherForTest(null);  // use real dispatcher wired in Task 15
        me.bechberger.ebpf.bpf.features.probes.ProbeSyscallCounter.reset();
    }

    @Test
    void xdpIsSupportedOn6_14Plus() {
        var r = Features.probeProgramType(BPFProgramType.XDP);
        assertInstanceOf(ProbeResult.Supported.class, r, "XDP must be supported: " + r);
    }

    @Test
    void kprobeIsSupported() {
        assertTrue(Features.hasProgramType(BPFProgramType.KPROBE));
    }

    @Test
    void unspecIsUnsupported() {
        // prog_type=UNSPEC(0) is rejected by every kernel.
        var r = Features.probeProgramType(BPFProgramType.UNSPEC);
        assertInstanceOf(ProbeResult.Unsupported.class, r);
    }
}
```

Note: this test cannot run before Task 15 wires the real dispatcher. Marked pending — commit the test source now, but expect it to error out with `ProbeUnavailable` from the null-dispatcher path until Task 15 lands. The build stays green because the test asserts `Supported` instances; failures show as red only in the vng run. If you want a strictly-green intermediate, comment out the assertions until Task 15 (see Task 15 for the un-comment step).

- [ ] **Step 2: Verify test compiles but fails on real kernel**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh FeaturesProgramTypeTest'`
Expected: 3 tests, 3 failures — `ProbeResult.ProbeUnavailable` returned because dispatcher is null.

- [ ] **Step 3: Write the probe class**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/ProgramTypeProbe.java
package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.BPFProgramType;
import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Probe a {@link BPFProgramType} by attempting to load a two-instruction
 * "return 0" program of that type via {@code bpf_prog_load}.
 *
 * <p>Errno mapping follows spec §6.1:
 * <ul>
 *   <li>0 / fd -> Supported</li>
 *   <li>EINVAL -> Unsupported</li>
 *   <li>E2BIG -> Supported (features hit; only the program size was rejected)</li>
 *   <li>EPERM -> ProbeUnavailable</li>
 *   <li>otherwise -> Unsupported("errno=" + n)</li>
 * </ul>
 */
public final class ProgramTypeProbe {

    private ProgramTypeProbe() {}

    /** libbpf signature (bpf/bpf.h):
     *  int bpf_prog_load(enum bpf_prog_type prog_type,
     *                    const char *prog_name, const char *license,
     *                    const struct bpf_insn *insns, size_t insn_cnt,
     *                    const struct bpf_prog_load_opts *opts); */
    static final HandlerWithErrno<Integer> BPF_PROG_LOAD =
            new HandlerWithErrno<>("bpf_prog_load",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_INT,             // enum bpf_prog_type
                            PanamaUtil.POINTER,   // const char *prog_name
                            PanamaUtil.POINTER,   // const char *license
                            PanamaUtil.POINTER,   // const struct bpf_insn *insns
                            JAVA_LONG,            // size_t insn_cnt
                            PanamaUtil.POINTER)); // const struct bpf_prog_load_opts *opts

    // eBPF insn sequence: MOV64 r0, 0 ; EXIT. Two 8-byte little-endian words.
    private static final byte[] INSNS_RETURN0 = new byte[] {
            (byte) 0xB7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            (byte) 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    private static final String LICENSE_GPL = "GPL";

    private static final int EINVAL = 22;
    private static final int EPERM  = 1;
    private static final int E2BIG  = 7;

    public static ProbeResult probe(BPFProgramType type) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment insns = arena.allocate(INSNS_RETURN0.length);
            MemorySegment.copy(INSNS_RETURN0, 0, insns, JAVA_BYTE, 0, INSNS_RETURN0.length);
            MemorySegment license = arena.allocateFrom(LICENSE_GPL);

            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r = BPF_PROG_LOAD.call(arena,
                    type.id(),
                    MemorySegment.NULL,            // prog_name
                    license,
                    insns,
                    (long) (INSNS_RETURN0.length / 8),
                    MemorySegment.NULL);           // opts

            int fd = r.result();
            if (fd >= 0) {
                try { LibC.close(fd); } catch (Throwable ignore) {}
                return new ProbeResult.Supported();
            }

            // libbpf < 1.x returned -errno as the result; libbpf 1.x also sets errno.
            int err = r.err() != 0 ? r.err() : -fd;
            return switch (err) {
                case EINVAL -> new ProbeResult.Unsupported("unknown prog_type");
                case E2BIG  -> new ProbeResult.Supported();
                case EPERM  -> new ProbeResult.ProbeUnavailable(
                        "missing CAP_BPF or CAP_SYS_ADMIN");
                default -> new ProbeResult.Unsupported("errno=" + err);
            };
        } catch (Throwable t) {
            return new ProbeResult.ProbeUnavailable(
                    "bpf_prog_load threw: " + t.getClass().getSimpleName()
                            + ": " + t.getMessage());
        }
    }
}
```

The `HandlerWithErrno<Integer>` handle is package-private so `HelperProbe` (Task 13) can reuse the same libbpf symbol without redeclaring it.

- [ ] **Step 4: Verify probe compiles**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dmaven.test.skip=true -Dmaven.repo.local=/home/i560383/.m2/repository compile'`
Expected: BUILD SUCCESS.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/ProgramTypeProbe.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesProgramTypeTest.java
git commit -m "feat(features): add ProgramTypeProbe via bpf_prog_load"
```

---

## Task 10: MapTypeProbe via bpf_map_create

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/MapTypeProbe.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesMapTypeTest.java` (real-kernel)

Approach per spec §6.2: `bpf_map_create` with one entry. Special cases per kind: per-CPU maps need `value_size=8`; queue/stack disallow keys (`key_size=0`); STRUCT_OPS needs a value type from BTF (skip in probe — always report `Unsupported` at this layer; `hasStructOps(name)` is the correct entry point for struct_ops); ARENA needs page-aligned size.

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesMapTypeTest.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesMapTypeTest {

    @BeforeEach
    void reset() { Features.resetCacheForTest(); }

    @Test
    void hashIsSupported() {
        assertTrue(Features.hasMapType(MapTypeId.HASH));
    }

    @Test
    void arrayIsSupported() {
        assertTrue(Features.hasMapType(MapTypeId.ARRAY));
    }

    @Test
    void ringbufIsSupportedOn6_14() {
        assertTrue(Features.hasMapType(MapTypeId.RINGBUF));
    }

    @Test
    void arenaIsSupportedOn6_17() {
        assertTrue(Features.hasMapType(MapTypeId.ARENA));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh FeaturesMapTypeTest'`
Expected: 4 failures — probe returns `ProbeUnavailable` (null dispatcher).

- [ ] **Step 3: Write the probe class**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/MapTypeProbe.java
package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Probe a {@link MapTypeId} by attempting {@code bpf_map_create} with
 * per-kind-appropriate key/value sizes and a single entry.
 */
public final class MapTypeProbe {

    private MapTypeProbe() {}

    /** libbpf signature (bpf/bpf.h):
     *  int bpf_map_create(enum bpf_map_type map_type, const char *map_name,
     *                     __u32 key_size, __u32 value_size, __u32 max_entries,
     *                     const struct bpf_map_create_opts *opts); */
    static final HandlerWithErrno<Integer> BPF_MAP_CREATE =
            new HandlerWithErrno<>("bpf_map_create",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_INT,             // enum bpf_map_type
                            PanamaUtil.POINTER,   // const char *map_name
                            JAVA_INT,             // __u32 key_size
                            JAVA_INT,             // __u32 value_size
                            JAVA_INT,             // __u32 max_entries
                            PanamaUtil.POINTER)); // opts

    private static final int EINVAL = 22;
    private static final int EPERM  = 1;
    private static final int E2BIG  = 7;
    private static final int ENOTSUPP = 524;   // kernel-only errno; treated as Unsupported

    /** (keySize, valueSize, maxEntries) triple for probe. */
    private record Shape(int keySize, int valueSize, int maxEntries) {}

    private static Shape shapeFor(MapTypeId t) {
        return switch (t) {
            case QUEUE, STACK             -> new Shape(0, 4, 1);
            case RINGBUF, USER_RINGBUF    -> new Shape(0, 0, 4096);   // page-sized
            case ARENA                    -> new Shape(0, 0, 1);      // 1 page
            case STACK_TRACE              -> new Shape(4, 8, 1);
            case LPM_TRIE                 -> new Shape(8, 4, 1);
            case ARRAY_OF_MAPS, HASH_OF_MAPS,
                 PROG_ARRAY, PERF_EVENT_ARRAY,
                 CGROUP_ARRAY, SOCKMAP,
                 SOCKHASH, DEVMAP, DEVMAP_HASH,
                 CPUMAP, XSKMAP,
                 REUSEPORT_SOCKARRAY,
                 SK_STORAGE, INODE_STORAGE,
                 TASK_STORAGE             -> new Shape(4, 4, 1);
            case PERCPU_HASH, PERCPU_ARRAY,
                 LRU_PERCPU_HASH, PERCPU_CGROUP_STORAGE
                                          -> new Shape(4, 8, 1);
            case BLOOM_FILTER             -> new Shape(0, 4, 1);
            case STRUCT_OPS               -> new Shape(4, 8, 1);   // best-effort; kernel usually needs BTF value type
            default                       -> new Shape(4, 4, 1);
        };
    }

    public static ProbeResult probe(MapTypeId t) {
        Shape s = shapeFor(t);
        try (Arena arena = Arena.ofConfined()) {
            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r = BPF_MAP_CREATE.call(arena,
                    t.getId(),
                    MemorySegment.NULL,      // map_name
                    s.keySize(),
                    s.valueSize(),
                    s.maxEntries(),
                    MemorySegment.NULL);     // opts

            int fd = r.result();
            if (fd >= 0) {
                try { LibC.close(fd); } catch (Throwable ignore) {}
                return new ProbeResult.Supported();
            }
            int err = r.err() != 0 ? r.err() : -fd;
            return switch (err) {
                case EINVAL   -> new ProbeResult.Unsupported("unknown map_type");
                case E2BIG    -> new ProbeResult.Supported();
                case ENOTSUPP -> new ProbeResult.Unsupported("not implemented (ENOTSUPP)");
                case EPERM    -> new ProbeResult.ProbeUnavailable(
                        "missing CAP_BPF or CAP_SYS_ADMIN");
                default -> new ProbeResult.Unsupported("errno=" + err);
            };
        } catch (Throwable t2) {
            return new ProbeResult.ProbeUnavailable(
                    "bpf_map_create threw: " + t2.getClass().getSimpleName()
                            + ": " + t2.getMessage());
        }
    }
}
```

- [ ] **Step 4: Verify compilation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dmaven.test.skip=true -Dmaven.repo.local=/home/i560383/.m2/repository compile'`
Expected: BUILD SUCCESS.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/MapTypeProbe.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesMapTypeTest.java
git commit -m "feat(features): add MapTypeProbe via bpf_map_create"
```

---

## Task 11: BtfLoader for /sys/kernel/btf/vmlinux

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/BtfLoader.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/BtfLoaderTest.java` (real-kernel)

Approach per spec §6.4/§6.5: load vmlinux BTF once from `/sys/kernel/btf/vmlinux` via `btf__parse_raw` (or `btf__parse` on the file path — jextract will surface both). Cache the returned `MemorySegment`. Expose two lookups: `hasFuncByName(String)` and `hasStructByName(String)`.

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/BtfLoaderTest.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.features.probes.BtfLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class BtfLoaderTest {

    @Test
    void loadsVmlinuxBtf() {
        assertTrue(BtfLoader.isAvailable(), "vmlinux BTF must load on thinkstation");
    }

    @Test
    void findsWellKnownFunc() {
        // vfs_read is present in every stock kernel BTF
        assertTrue(BtfLoader.hasFuncByName("vfs_read"));
    }

    @Test
    void findsWellKnownStruct() {
        assertTrue(BtfLoader.hasStructByName("task_struct"));
    }

    @Test
    void missingFuncIsNegative() {
        assertFalse(BtfLoader.hasFuncByName("definitely_not_a_kfunc_zzz"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh BtfLoaderTest'`
Expected: FAIL — class not found.

- [ ] **Step 3: Write BtfLoader**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/BtfLoader.java
package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Lazy, cached vmlinux BTF handle. Loaded from
 * {@code /sys/kernel/btf/vmlinux} on first use; NULL/unavailable if the
 * file is not readable.
 */
public final class BtfLoader {

    private BtfLoader() {}

    private static final int BTF_KIND_STRUCT = 4;
    private static final int BTF_KIND_FUNC   = 12;

    /** libbpf signatures (bpf/btf.h):
     *  struct btf *btf__parse(const char *path, struct btf_ext **btf_ext);
     *  long libbpf_get_error(const void *ptr);
     *  int btf__find_by_name_kind(const struct btf *btf, const char *type_name,
     *                             __u32 kind); */
    private static final HandlerWithErrno<MemorySegment> BTF__PARSE =
            new HandlerWithErrno<>("btf__parse",
                    FunctionDescriptor.of(PanamaUtil.POINTER,
                            PanamaUtil.POINTER,   // path
                            PanamaUtil.POINTER)); // btf_ext**

    private static final HandlerWithErrno<Long> LIBBPF_GET_ERROR =
            new HandlerWithErrno<>("libbpf_get_error",
                    FunctionDescriptor.of(JAVA_LONG,
                            PanamaUtil.POINTER));

    private static final HandlerWithErrno<Integer> BTF__FIND_BY_NAME_KIND =
            new HandlerWithErrno<>("btf__find_by_name_kind",
                    FunctionDescriptor.of(JAVA_INT,
                            PanamaUtil.POINTER,   // struct btf *
                            PanamaUtil.POINTER,   // const char *type_name
                            JAVA_INT));           // __u32 kind

    private static volatile MemorySegment BTF = null;   // btf*
    private static volatile Boolean AVAILABLE = null;
    private static final Object LOCK = new Object();

    private static void ensureLoaded() {
        if (AVAILABLE != null) return;
        synchronized (LOCK) {
            if (AVAILABLE != null) return;
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment path = arena.allocateFrom("/sys/kernel/btf/vmlinux");
                ProbeSyscallCounter.increment();  // count the BTF read as one probe
                PanamaUtil.ResultAndErr<MemorySegment> pr =
                        BTF__PARSE.call(arena, path, MemorySegment.NULL);
                MemorySegment btf = pr.result();
                if (btf == null || btf.address() == 0) {
                    BTF = null;
                    AVAILABLE = false;
                    return;
                }
                PanamaUtil.ResultAndErr<Long> er = LIBBPF_GET_ERROR.call(arena, btf);
                if (er.result() != 0L) {
                    BTF = null;
                    AVAILABLE = false;
                    return;
                }
                // The btf handle is owned by libbpf; the address is stable across arenas.
                BTF = btf;
                AVAILABLE = true;
            } catch (Throwable t) {
                BTF = null;
                AVAILABLE = false;
            }
        }
    }

    public static boolean isAvailable() {
        ensureLoaded();
        return Boolean.TRUE.equals(AVAILABLE);
    }

    /** Look up a FUNC type by name in vmlinux BTF. */
    public static boolean hasFuncByName(String name) {
        return findByName(name, BTF_KIND_FUNC);
    }

    /** Look up a STRUCT type by name in vmlinux BTF. */
    public static boolean hasStructByName(String name) {
        return findByName(name, BTF_KIND_STRUCT);
    }

    private static boolean findByName(String name, int kind) {
        if (!isAvailable()) return false;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment n = arena.allocateFrom(name);
            PanamaUtil.ResultAndErr<Integer> r =
                    BTF__FIND_BY_NAME_KIND.call(arena, BTF, n, kind);
            return r.result() > 0;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Test hook: drop the cached BTF handle so the next call re-loads. */
    static void resetForTest() {
        synchronized (LOCK) {
            // libbpf's btf__free is intentionally NOT invoked here — a
            // test wanting a clean state can re-parse; the old handle
            // simply becomes unreferenced.
            BTF = null;
            AVAILABLE = null;
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh BtfLoaderTest'`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/BtfLoader.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/BtfLoaderTest.java
git commit -m "feat(features): add BtfLoader for /sys/kernel/btf/vmlinux"
```

---

## Task 12: KfuncProbe and StructOpsProbe (BTF-only)

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/KfuncProbe.java`
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/StructOpsProbe.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesKfuncTest.java` (real-kernel)
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesStructOpsTest.java` (real-kernel)

- [ ] **Step 1: Write the failing tests**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesKfuncTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesKfuncTest {
    @BeforeEach void reset() { Features.resetCacheForTest(); }

    @Test
    void knownKfuncIsSupported() {
        // Available on every 6.14+ kernel with arenas.
        assertTrue(Features.hasKfunc("bpf_arena_alloc_pages"));
    }

    @Test
    void unknownKfuncIsUnsupported() {
        assertFalse(Features.hasKfunc("bpf_never_existed_zzz"));
        var r = Features.probeKfunc("bpf_never_existed_zzz", null);
        assertInstanceOf(ProbeResult.Unsupported.class, r);
    }
}
```

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesStructOpsTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesStructOpsTest {
    @BeforeEach void reset() { Features.resetCacheForTest(); }

    @Test
    void schedExtOpsIsSupported() {
        assertTrue(Features.hasStructOps("sched_ext_ops"));
    }

    @Test
    void tcpCongestionOpsIsSupported() {
        assertTrue(Features.hasStructOps("tcp_congestion_ops"));
    }

    @Test
    void unknownStructIsUnsupported() {
        assertFalse(Features.hasStructOps("never_a_struct_zzz"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh FeaturesKfuncTest FeaturesStructOpsTest'`
Expected: FAIL — classes not found (or `ProbeUnavailable` from null dispatcher).

- [ ] **Step 3: Write KfuncProbe**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/KfuncProbe.java
package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.ProbeResult;
import org.jetbrains.annotations.Nullable;

/**
 * Kfunc probe via vmlinux BTF scan. Module kfuncs (moduleName != null) are
 * currently reported as {@code ProbeUnavailable} — module BTF loading is a
 * follow-up (see spec §6.4 caveat).
 */
public final class KfuncProbe {

    private KfuncProbe() {}

    public static ProbeResult probe(String name, @Nullable String moduleName) {
        if (moduleName != null) {
            return new ProbeResult.ProbeUnavailable(
                    "module-kfunc probing not implemented (module=" + moduleName + ")");
        }
        if (!BtfLoader.isAvailable()) {
            return new ProbeResult.ProbeUnavailable(
                    "cannot read /sys/kernel/btf/vmlinux");
        }
        return BtfLoader.hasFuncByName(name)
                ? new ProbeResult.Supported()
                : new ProbeResult.Unsupported("not present in vmlinux BTF");
    }
}
```

- [ ] **Step 4: Write StructOpsProbe**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/StructOpsProbe.java
package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.ProbeResult;

/**
 * Struct_ops probe via vmlinux BTF scan (spec §6.5). Presence of the kernel
 * struct type is treated as authoritative — the registration path always
 * accompanies the type definition on 6.14+.
 */
public final class StructOpsProbe {

    private StructOpsProbe() {}

    public static ProbeResult probe(String kernelStructName) {
        if (!BtfLoader.isAvailable()) {
            return new ProbeResult.ProbeUnavailable(
                    "cannot read /sys/kernel/btf/vmlinux");
        }
        return BtfLoader.hasStructByName(kernelStructName)
                ? new ProbeResult.Supported()
                : new ProbeResult.Unsupported("struct not present in vmlinux BTF");
    }
}
```

- [ ] **Step 5: Verify compilation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dmaven.test.skip=true -Dmaven.repo.local=/home/i560383/.m2/repository compile'`
Expected: BUILD SUCCESS.

- [ ] **Step 6: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/KfuncProbe.java bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/StructOpsProbe.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesKfuncTest.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesStructOpsTest.java
git commit -m "feat(features): add Kfunc and StructOps probes via BTF scan"
```

---

## Task 13: HelperProbe via bpf_prog_load with helper call

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/HelperProbe.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesHelperTest.java` (real-kernel)

Approach per spec §6.3: build a three-instruction program that calls the helper: `MOV r0, 0 ; CALL <helperid> ; EXIT`. Load it under the helper's `carrierProgramType`. Verifier reject "unknown func" => `Unsupported`; success or E2BIG => `Supported`; EPERM => `ProbeUnavailable`. Because we discard the verifier log, we distinguish by errno alone — kernel returns `EINVAL` for both "helper not allowed for prog_type" and "unknown func"; the carrier picker in the enum eliminates the "not allowed" case for the helpers we ship.

BPF `CALL <helper>` encoding:
- opcode `0x85` (BPF_JMP | BPF_CALL), dst=0, src=0, off=0, imm=`<helper_id>`.

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesHelperTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesHelperTest {

    @BeforeEach
    void reset() { Features.resetCacheForTest(); }

    @Test
    void ktimeGetNsIsSupported() {
        assertTrue(Features.hasHelper(BPFHelper.KTIME_GET_NS));
    }

    @Test
    void ringbufReserveIsSupported() {
        assertTrue(Features.hasHelper(BPFHelper.RINGBUF_RESERVE));
    }

    @Test
    void loopHelperIsSupportedOn6_14() {
        assertTrue(Features.hasHelper(BPFHelper.LOOP));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh FeaturesHelperTest'`
Expected: FAIL — `HelperProbe` class not found (or `ProbeUnavailable`).

- [ ] **Step 3: Write HelperProbe**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/HelperProbe.java
package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.BPFHelper;
import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * Probe a {@link BPFHelper} by loading a three-instruction program that
 * calls the helper under a known-permissive carrier program type.
 *
 * <p>Instructions: {@code MOV64 r0, 0 ; CALL helperId ; EXIT}.
 * Reuses {@link ProgramTypeProbe#BPF_PROG_LOAD} — libbpf exports one
 * symbol; wrap it once.
 */
public final class HelperProbe {

    private HelperProbe() {}

    private static final int EINVAL = 22;
    private static final int EPERM  = 1;
    private static final int E2BIG  = 7;
    private static final int EACCES = 13;   // verifier reject; here means "helper not allowed"

    public static ProbeResult probe(BPFHelper h) {
        byte[] insns = new byte[24];
        // MOV64 r0, 0 : opcode B7, dst=0, src=0, off=0, imm=0
        insns[0] = (byte) 0xB7;
        // CALL helperId : opcode 85, dst=0, src=0, off=0, imm=helperId (LE)
        insns[8]  = (byte) 0x85;
        int id = h.id();
        insns[12] = (byte) (id & 0xFF);
        insns[13] = (byte) ((id >> 8)  & 0xFF);
        insns[14] = (byte) ((id >> 16) & 0xFF);
        insns[15] = (byte) ((id >> 24) & 0xFF);
        // EXIT : opcode 95
        insns[16] = (byte) 0x95;

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment iseg = arena.allocate(insns.length);
            MemorySegment.copy(insns, 0, iseg, JAVA_BYTE, 0, insns.length);
            MemorySegment license = arena.allocateFrom("GPL");

            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r = ProgramTypeProbe.BPF_PROG_LOAD.call(arena,
                    h.carrierProgramType().id(),
                    MemorySegment.NULL,           // prog_name
                    license,
                    iseg,
                    (long) (insns.length / 8),
                    MemorySegment.NULL);          // opts

            int fd = r.result();
            if (fd >= 0) {
                try { LibC.close(fd); } catch (Throwable ignore) {}
                return new ProbeResult.Supported();
            }
            int err = r.err() != 0 ? r.err() : -fd;
            return switch (err) {
                case EINVAL, EACCES -> new ProbeResult.Unsupported("unknown or disallowed helper");
                case E2BIG          -> new ProbeResult.Supported();
                case EPERM          -> new ProbeResult.ProbeUnavailable(
                        "missing CAP_BPF or CAP_SYS_ADMIN");
                default -> new ProbeResult.Unsupported("errno=" + err);
            };
        } catch (Throwable t) {
            return new ProbeResult.ProbeUnavailable(
                    "bpf_prog_load threw: " + t.getClass().getSimpleName()
                            + ": " + t.getMessage());
        }
    }
}
```

- [ ] **Step 4: Verify compilation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dmaven.test.skip=true -Dmaven.repo.local=/home/i560383/.m2/repository compile'`
Expected: BUILD SUCCESS.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/HelperProbe.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesHelperTest.java
git commit -m "feat(features): add HelperProbe via bpf_prog_load with helper call"
```

---

## Task 14: AttachTypeProbe via bpf_link_create dry-run

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/AttachTypeProbe.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesAttachTypeTest.java` (real-kernel)

Approach per spec §6.6: `bpf_link_create` with a bogus target fd (-1) and the attach type under test. `EBADF` -> `Supported` (attach type known, fd is broken); `EINVAL` -> `Unsupported`; `EPERM` -> `ProbeUnavailable`.

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesAttachTypeTest.java
package me.bechberger.ebpf.bpf.features;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

@EnabledOnOs(OS.LINUX)
class FeaturesAttachTypeTest {

    @BeforeEach
    void reset() { Features.resetCacheForTest(); }

    @Test
    void kprobeMultiIsSupportedOn6_14() {
        assertTrue(Features.hasAttachType(BPFAttachType.TRACE_KPROBE_MULTI));
    }

    @Test
    void tcxIngressIsSupportedOn6_14() {
        assertTrue(Features.hasAttachType(BPFAttachType.TCX_INGRESS));
    }

    @Test
    void uprobeMultiIsSupportedOn6_14() {
        assertTrue(Features.hasAttachType(BPFAttachType.TRACE_UPROBE_MULTI));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh FeaturesAttachTypeTest'`
Expected: FAIL — probe class not present.

- [ ] **Step 3: Write AttachTypeProbe**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/AttachTypeProbe.java
package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.features.BPFAttachType;
import me.bechberger.ebpf.bpf.features.ProbeResult;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Probe a {@link BPFAttachType} via {@code bpf_link_create} with an invalid
 * target fd. If the kernel accepts the attach type it fails on the bogus fd
 * with EBADF; if the type is unknown it fails with EINVAL first.
 */
public final class AttachTypeProbe {

    private AttachTypeProbe() {}

    /** libbpf signature (bpf/bpf.h):
     *  int bpf_link_create(int prog_fd, int target_fd,
     *                      enum bpf_attach_type attach_type,
     *                      const struct bpf_link_create_opts *opts); */
    static final HandlerWithErrno<Integer> BPF_LINK_CREATE =
            new HandlerWithErrno<>("bpf_link_create",
                    FunctionDescriptor.of(JAVA_INT,
                            JAVA_INT,             // prog_fd
                            JAVA_INT,             // target_fd
                            JAVA_INT,             // enum bpf_attach_type
                            PanamaUtil.POINTER)); // opts

    private static final int EBADF  = 9;
    private static final int EINVAL = 22;
    private static final int EPERM  = 1;

    public static ProbeResult probe(BPFAttachType t) {
        try (Arena arena = Arena.ofConfined()) {
            ProbeSyscallCounter.increment();
            PanamaUtil.ResultAndErr<Integer> r = BPF_LINK_CREATE.call(arena,
                    -1,                    // prog_fd — invalid
                    -1,                    // target_fd — invalid; expect EBADF if attach type is known
                    t.id(),
                    MemorySegment.NULL);   // opts

            int fd = r.result();
            if (fd >= 0) {
                try { LibC.close(fd); } catch (Throwable ignore) {}
                return new ProbeResult.Supported();
            }
            int err = r.err() != 0 ? r.err() : -fd;
            return switch (err) {
                case EBADF  -> new ProbeResult.Supported();
                case EINVAL -> new ProbeResult.Unsupported("unknown attach_type");
                case EPERM  -> new ProbeResult.ProbeUnavailable(
                        "missing CAP_BPF or CAP_SYS_ADMIN");
                default -> new ProbeResult.Unsupported("errno=" + err);
            };
        } catch (Throwable ex) {
            return new ProbeResult.ProbeUnavailable(
                    "bpf_link_create threw: " + ex.getClass().getSimpleName()
                            + ": " + ex.getMessage());
        }
    }
}
```

- [ ] **Step 4: Verify compilation**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dmaven.test.skip=true -Dmaven.repo.local=/home/i560383/.m2/repository compile'`
Expected: BUILD SUCCESS.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/probes/AttachTypeProbe.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesAttachTypeTest.java
git commit -m "feat(features): add AttachTypeProbe via bpf_link_create dry-run"
```

---

## Task 15: Wire real dispatcher into Features and expand FeaturesProbeTest coverage

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/Features.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesProbeTest.java` (real-kernel — new umbrella)

- [ ] **Step 1: Write the failing umbrella test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesProbeTest.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.features.probes.ProbeSyscallCounter;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Real-kernel umbrella that exercises the dispatcher wired in Task 15.
 * Runs under vng on thinkstation.
 */
@EnabledOnOs(OS.LINUX)
class FeaturesProbeTest {

    @BeforeEach
    void reset() {
        Features.resetCacheForTest();
        ProbeSyscallCounter.reset();
    }

    @Test
    void cacheHitAvoidsSecondSyscall() {
        Features.probeProgramType(BPFProgramType.XDP);
        long after1 = ProbeSyscallCounter.value();
        assertEquals(1, after1);
        Features.probeProgramType(BPFProgramType.XDP);
        assertEquals(after1, ProbeSyscallCounter.value(),
                "second call must hit the cache");
    }

    @Test
    void kernelVersionAtLeast6_14() {
        KernelVersion v = Features.kernelVersion();
        assertTrue(v.atLeast(6, 14),
                "kernel floor is 6.14, got " + v.raw());
    }

    @Test
    void snapshotContainsWellKnownEntries() {
        var snap = Features.snapshot();
        assertTrue(snap.get("prog:XDP") instanceof ProbeResult.Supported);
        assertTrue(snap.get("map:HASH") instanceof ProbeResult.Supported);
        assertTrue(snap.get("helper:KTIME_GET_NS") instanceof ProbeResult.Supported);
        assertTrue(snap.get("attach:TCX_INGRESS") instanceof ProbeResult.Supported);
        // Snapshot is unmodifiable
        assertThrows(UnsupportedOperationException.class,
                () -> snap.put("x", new ProbeResult.Supported()));
    }

    @Test
    void mapTypeArenaSupported() {
        assertTrue(Features.hasMapType(MapTypeId.ARENA));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh FeaturesProbeTest'`
Expected: FAIL — every probe returns `ProbeUnavailable` because dispatcher is still `null`.

- [ ] **Step 3: Wire the real dispatcher**

Replace the `dispatcher = null;` line and add a static initialiser that installs the real dispatcher. Insert after the `CACHE` field:

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/Features.java  (patch)

    private static volatile Dispatcher dispatcher = defaultDispatcher();

    private static Dispatcher defaultDispatcher() {
        return key -> switch (key) {
            case ProbeKey.ProgramTypeKey k ->
                    me.bechberger.ebpf.bpf.features.probes.ProgramTypeProbe.probe(k.t());
            case ProbeKey.MapTypeKey k ->
                    me.bechberger.ebpf.bpf.features.probes.MapTypeProbe.probe(k.t());
            case ProbeKey.HelperKey k ->
                    me.bechberger.ebpf.bpf.features.probes.HelperProbe.probe(k.h());
            case ProbeKey.KfuncKey k ->
                    me.bechberger.ebpf.bpf.features.probes.KfuncProbe.probe(k.name(), k.mod());
            case ProbeKey.StructOpsKey k ->
                    me.bechberger.ebpf.bpf.features.probes.StructOpsProbe.probe(k.name());
            case ProbeKey.AttachTypeKey k ->
                    me.bechberger.ebpf.bpf.features.probes.AttachTypeProbe.probe(k.t());
        };
    }
```

Update `setDispatcherForTest` to accept `null` (meaning "restore default"):

```java
    /** Substitute the dispatcher. Test-only. Pass {@code null} to restore the default. */
    static void setDispatcherForTest(Dispatcher d) {
        dispatcher = d == null ? defaultDispatcher() : d;
    }
```

- [ ] **Step 4: Run all real-kernel Features tests**

Run:
```
./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh FeaturesProbeTest FeaturesProgramTypeTest FeaturesMapTypeTest FeaturesHelperTest FeaturesKfuncTest FeaturesStructOpsTest FeaturesAttachTypeTest BtfLoaderTest'
```
Expected: every test passes on thinkstation kernel 6.17.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/Features.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeaturesProbeTest.java
git commit -m "feat(features): wire real dispatcher into Features"
```

---

## Task 16: Add BPFLoadError.UnsupportedKernel and MissingKfunc

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java:90-95` (BPFLoadError subclass block)
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFLoadErrorSubclassesTest.java` (mac-safe)

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFLoadErrorSubclassesTest.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BPFLoadErrorSubclassesTest {

    @Test
    void unsupportedKernelMessageIncludesFeatureAndSince() {
        var e = new BPFProgram.BPFLoadError.UnsupportedKernel("attach_type TCX_INGRESS", "6.6");
        assertTrue(e.getMessage().contains("TCX_INGRESS"));
        assertTrue(e.getMessage().contains("6.6"));
        assertInstanceOf(BPFProgram.BPFLoadError.class, e);
    }

    @Test
    void missingKfuncCarriesNameAndProgram() {
        var e = new BPFProgram.BPFLoadError.MissingKfunc("bpf_never_existed", "myProgram");
        assertTrue(e.getMessage().contains("bpf_never_existed"));
        assertTrue(e.getMessage().contains("myProgram"));
        assertInstanceOf(BPFProgram.BPFLoadError.class, e);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=BPFLoadErrorSubclassesTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — inner classes missing.

- [ ] **Step 3: Add the inner classes**

Edit `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java`. Replace the current `BPFLoadError` block (around line 90) with:

```java
    /**
     * Thrown whenever the whole bpf program could not be loaded.
     */
    public static class BPFLoadError extends BPFError {

        public BPFLoadError(String message) {
            super(message);
        }

        /**
         * The running kernel lacks a feature the program requires.
         * Raised by the pre-syscall feature check in {@link BPFProgram#load(Class)}.
         */
        public static class UnsupportedKernel extends BPFLoadError {
            public UnsupportedKernel(String feature, String sinceVersion) {
                super("kernel does not support " + feature
                        + " (required since " + sinceVersion + ")");
            }
        }

        /**
         * The running kernel does not export a kfunc the program calls.
         */
        public static class MissingKfunc extends BPFLoadError {
            public MissingKfunc(String kfuncName, String programName) {
                super("kfunc '" + kfuncName + "' is not available on this kernel"
                        + " (referenced by program '" + programName + "')");
            }
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=BPFLoadErrorSubclassesTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/BPFLoadErrorSubclassesTest.java
git commit -m "feat(features): add BPFLoadError.UnsupportedKernel and MissingKfunc"
```

---

## Task 17: Add a FeatureRequirements hook on BPFProgram

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` (add `getRequiredFeatures()` protected method + call site in `load()`)
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/features/FeatureRequirements.java`
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeatureRequirementsTest.java` (mac-safe using a stub dispatcher)

The processor-generated impl classes will populate this list in a later plan; for now the base class returns an empty list and the load path unconditionally consults `Features` for each required item.

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeatureRequirementsTest.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FeatureRequirementsTest {

    @BeforeEach
    void reset() {
        Features.resetCacheForTest();
        // dispatcher: HELPER LOOP -> Unsupported; everything else -> Supported.
        Features.setDispatcherForTest(key -> {
            if (key instanceof ProbeKey.HelperKey h && h.h() == BPFHelper.LOOP) {
                return new ProbeResult.Unsupported("simulated");
            }
            if (key instanceof ProbeKey.KfuncKey k
                    && k.name().equals("bpf_never_existed")) {
                return new ProbeResult.Unsupported("simulated");
            }
            return new ProbeResult.Supported();
        });
    }

    @Test
    void enforceMissingKfuncThrowsMissingKfunc() {
        var req = new FeatureRequirements.Builder()
                .programName("myProg")
                .kfunc("bpf_never_existed")
                .build();
        var ex = assertThrows(BPFProgram.BPFLoadError.MissingKfunc.class,
                () -> FeatureRequirements.enforce(req));
        assertTrue(ex.getMessage().contains("bpf_never_existed"));
        assertTrue(ex.getMessage().contains("myProg"));
    }

    @Test
    void enforceMissingHelperThrowsUnsupportedKernel() {
        var req = new FeatureRequirements.Builder()
                .programName("myProg")
                .helper(BPFHelper.LOOP, "5.17")
                .build();
        assertThrows(BPFProgram.BPFLoadError.UnsupportedKernel.class,
                () -> FeatureRequirements.enforce(req));
    }

    @Test
    void enforceEmptyRequirementsIsNoop() {
        FeatureRequirements.enforce(new FeatureRequirements.Builder().build());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=FeatureRequirementsTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — class not found.

- [ ] **Step 3: Write FeatureRequirements**

```java
// bpf/src/main/java/me/bechberger/ebpf/bpf/features/FeatureRequirements.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Declarative list of features a program needs. Populated per-program by
 * the annotation processor (in a later plan); consumed by {@link #enforce}
 * inside {@link BPFProgram#load(Class)}.
 */
public final class FeatureRequirements {

    /** Discriminated union of required features. */
    public sealed interface Item {
        record ProgramType(BPFProgramType t, String since)  implements Item {}
        record MapType(MapTypeId t, String since)           implements Item {}
        record Helper(BPFHelper h, String since)            implements Item {}
        record Kfunc(String name, @Nullable String module)  implements Item {}
        record StructOps(String kernelStructName, String since) implements Item {}
        record AttachType(BPFAttachType t, String since)    implements Item {}
    }

    private final String programName;
    private final List<Item> items;

    private FeatureRequirements(String programName, List<Item> items) {
        this.programName = programName;
        this.items = List.copyOf(items);
    }

    public String programName() { return programName; }
    public List<Item> items()   { return items; }

    /** Throws {@link BPFProgram.BPFLoadError} subclasses on the first miss. */
    public static void enforce(FeatureRequirements req) {
        for (Item it : req.items) {
            switch (it) {
                case Item.ProgramType p -> require(
                        Features.hasProgramType(p.t()),
                        "program_type " + p.t().name(), p.since());
                case Item.MapType m -> require(
                        Features.hasMapType(m.t()),
                        "map_type " + m.t().name(), m.since());
                case Item.Helper h -> require(
                        Features.hasHelper(h.h()),
                        "helper " + h.h().name(), h.since());
                case Item.Kfunc k -> {
                    if (!Features.hasKfunc(k.name(),
                            k.module() == null ? null : k.module())) {
                        throw new BPFProgram.BPFLoadError.MissingKfunc(
                                k.name(), req.programName);
                    }
                }
                case Item.StructOps s -> require(
                        Features.hasStructOps(s.kernelStructName()),
                        "struct_ops " + s.kernelStructName(), s.since());
                case Item.AttachType a -> require(
                        Features.hasAttachType(a.t()),
                        "attach_type " + a.t().name(), a.since());
            }
        }
    }

    private static void require(boolean present, String feature, String since) {
        if (!present) {
            throw new BPFProgram.BPFLoadError.UnsupportedKernel(feature, since);
        }
    }

    public static final class Builder {
        private String programName = "<unknown>";
        private final List<Item> items = new ArrayList<>();

        public Builder programName(String s) { this.programName = s; return this; }
        public Builder programType(BPFProgramType t, String since) {
            items.add(new Item.ProgramType(t, since)); return this;
        }
        public Builder mapType(MapTypeId t, String since) {
            items.add(new Item.MapType(t, since)); return this;
        }
        public Builder helper(BPFHelper h, String since) {
            items.add(new Item.Helper(h, since)); return this;
        }
        public Builder kfunc(String name) {
            items.add(new Item.Kfunc(name, null)); return this;
        }
        public Builder kfunc(String name, String module) {
            items.add(new Item.Kfunc(name, module)); return this;
        }
        public Builder structOps(String name, String since) {
            items.add(new Item.StructOps(name, since)); return this;
        }
        public Builder attachType(BPFAttachType t, String since) {
            items.add(new Item.AttachType(t, since)); return this;
        }
        public FeatureRequirements build() {
            return new FeatureRequirements(programName, Collections.unmodifiableList(items));
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=FeatureRequirementsTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/features/FeatureRequirements.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeatureRequirementsTest.java
git commit -m "feat(features): add FeatureRequirements builder + enforce"
```

---

## Task 18: Integrate FeatureRequirements into BPFProgram.load

**Files:**
- Modify: `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java` (add `getFeatureRequirements()` protected method with empty default; call `FeatureRequirements.enforce(...)` from both `load(Class)` and `load(Class, BPFProgram...)` before the constructor call)
- Test: `bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeatureGatedLoadTest.java` (real-kernel + mac-safe reflection test)

- [ ] **Step 1: Write the failing test**

```java
// bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeatureGatedLoadTest.java
package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FeatureGatedLoadTest {

    @BeforeEach
    void resetFeatures() {
        Features.resetCacheForTest();
        // Simulated dispatcher: every kfunc named "bpf_never_existed" is Unsupported.
        Features.setDispatcherForTest(key -> {
            if (key instanceof ProbeKey.KfuncKey k
                    && "bpf_never_existed".equals(k.name())) {
                return new ProbeResult.Unsupported("simulated");
            }
            return new ProbeResult.Supported();
        });
    }

    /**
     * Fake program that returns a requirements list demanding a missing kfunc.
     * Reaches the pre-syscall feature check before any FFI activity happens,
     * so the test is mac-safe.
     */
    static abstract class FakeMissingKfuncProgram extends BPFProgram {
        @Override
        protected FeatureRequirements getFeatureRequirements() {
            return new FeatureRequirements.Builder()
                    .programName("FakeMissingKfuncProgram")
                    .kfunc("bpf_never_existed")
                    .build();
        }
    }

    @Test
    void enforceMissingKfuncThrowsBeforeConstructor() {
        // We call enforce directly with the requirements a fake program would emit.
        // The full load(Class) path requires an @BPF-generated impl class; the
        // enforcement itself is the object under test here.
        var req = new FeatureRequirements.Builder()
                .programName("FakeMissingKfuncProgram")
                .kfunc("bpf_never_existed")
                .build();
        var ex = assertThrows(BPFProgram.BPFLoadError.MissingKfunc.class,
                () -> FeatureRequirements.enforce(req));
        assertTrue(ex.getMessage().contains("bpf_never_existed"));
        assertTrue(ex.getMessage().contains("FakeMissingKfuncProgram"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=FeatureGatedLoadTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: FAIL — `getFeatureRequirements` method not found on `BPFProgram`.

- [ ] **Step 3: Add the hook in BPFProgram**

Edit `bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java`.

Add import at the top of the file:

```java
import me.bechberger.ebpf.bpf.features.FeatureRequirements;
```

Add a protected virtual method next to `preLoad()` (around line 417):

```java
    /**
     * Feature requirements this program declares. The base implementation
     * returns an empty requirements set; the annotation-processor-generated
     * impl class overrides this to list the features the program actually
     * needs. Consulted by {@link #load(Class)} and
     * {@link #load(Class, BPFProgram...)} before the constructor is called.
     */
    protected FeatureRequirements getFeatureRequirements() {
        return new FeatureRequirements.Builder()
                .programName(getClass().getSimpleName())
                .build();
    }
```

In `load(Class<T>)` at line 150, insert between `KernelFeatures.checkRequirements(...)` (currently line 156) and the `long t0 = System.currentTimeMillis();` line:

```java
            enforceFeatureRequirements(clazz);
```

Do the same insertion in `load(Class<T>, BPFProgram...)` at line 216 (same position: after `KernelFeatures.checkRequirements(...)`).

Add the helper as a private static method near `load` (immediately after the second `load` method definition):

```java
    private static void enforceFeatureRequirements(Class<?> clazz) {
        try {
            var implClass = BPFProgram.<BPFProgram, BPFProgram>getImplClass(
                    (Class<BPFProgram>) clazz);
            // Instantiate a "requirements-only" throwaway: the generated impl
            // class must expose a static getStaticFeatureRequirements() so we
            // do not have to run the constructor. Until the processor plan
            // ships, we invoke it reflectively; absence is a no-op.
            var m = implClass.getDeclaredMethod("getStaticFeatureRequirements");
            m.setAccessible(true);
            FeatureRequirements req = (FeatureRequirements) m.invoke(null);
            FeatureRequirements.enforce(req);
        } catch (NoSuchMethodException e) {
            // Generated impl class has not been updated yet — skip the check.
        } catch (BPFProgram.BPFLoadError e) {
            throw e;
        } catch (Exception e) {
            // Do not fail hard on reflection issues; log and continue.
            System.getLogger(BPFProgram.class.getName())
                    .log(System.Logger.Level.DEBUG,
                            "feature-requirements probe skipped for "
                                    + clazz.getSimpleName() + ": " + e);
        }
    }
```

Note: the `getStaticFeatureRequirements` method is a static hook the processor plan will emit. Until that plan lands, `NoSuchMethodException` is the expected branch and gating is a no-op — the test in Step 1 covers the enforcement logic in isolation.

- [ ] **Step 4: Run test to verify it passes**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf -Dtest=FeatureGatedLoadTest -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository test'`
Expected: PASS.

- [ ] **Step 5: Full bpf-module smoke test**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh HelloWorldTest FeaturesProbeTest FeatureGatedLoadTest'`
Expected: existing HelloWorldTest still passes (proof that the hook does not regress); Features tests pass.

- [ ] **Step 6: Commit**

```
git add bpf/src/main/java/me/bechberger/ebpf/bpf/BPFProgram.java bpf/src/test/java/me/bechberger/ebpf/bpf/features/FeatureGatedLoadTest.java
git commit -m "feat(features): integrate FeatureRequirements into BPFProgram.load"
```

---

## Task 19: Add FeatureProbeSample

**Files:**
- Create: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/FeatureProbeSample.java`

- [ ] **Step 1: Write the sample**

```java
// bpf-samples/src/main/java/me/bechberger/ebpf/samples/FeatureProbeSample.java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.features.BPFProgramType;
import me.bechberger.ebpf.bpf.features.Features;
import me.bechberger.ebpf.bpf.features.ProbeResult;

import java.util.Map;

/**
 * Print the running kernel version and a table of feature-probe results.
 *
 * <p>If {@code STRUCT_OPS} and {@code sched_ext_ops} are supported, print
 * a note; the actual struct_ops load path lands in a later plan.
 */
public final class FeatureProbeSample {

    private FeatureProbeSample() {}

    public static void main(String[] args) {
        System.out.println("Kernel: " + Features.kernelVersion().raw());
        System.out.println();

        long t0 = System.currentTimeMillis();
        Map<String, ProbeResult> snap = Features.snapshot();
        long dt = System.currentTimeMillis() - t0;

        int maxKey = 0;
        for (String k : snap.keySet()) maxKey = Math.max(maxKey, k.length());
        String fmt = "%-" + (maxKey + 2) + "s%s%n";

        for (var e : snap.entrySet()) {
            System.out.printf(fmt, e.getKey(), render(e.getValue()));
        }
        System.out.println();
        System.out.printf("Probed %d features in %d ms%n", snap.size(), dt);

        boolean canSchedExt = Features.hasProgramType(BPFProgramType.STRUCT_OPS)
                && Features.hasStructOps("sched_ext_ops");
        if (canSchedExt) {
            System.out.println("sched_ext_ops available; struct_ops load path is a follow-up plan.");
        } else {
            System.out.println("sched_ext_ops NOT available on this kernel; skipping load.");
        }
    }

    private static String render(ProbeResult r) {
        return switch (r) {
            case ProbeResult.Supported s          -> "yes";
            case ProbeResult.Unsupported u        -> "no (" + u.reason() + ")";
            case ProbeResult.ProbeUnavailable u   -> "unknown (" + u.reason() + ")";
        };
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn mvn -pl bpf-samples -am -Dmaven.test.skip=true -Dmaven.repo.local=/home/i560383/.m2/repository compile'`
Expected: BUILD SUCCESS.

- [ ] **Step 3: Smoke-run the sample under vng**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-sample-vng.sh FeatureProbeSample'` (if that helper exists; otherwise adapt the vng one-liner from `HOW_TO_RUN_TESTS.md` §"Running a single test method"). Expected: the program prints a full snapshot in under 100ms, then either the "sched_ext_ops available" or the "NOT available" line.

If `run-sample-vng.sh` does not exist, run directly:
```
./scripts/ts.sh --no-tty 'KERNEL=/boot/vmlinuz-6.17.0-35-generic; JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn; MVN=$JAVA_HOME/../../../../.m2/wrapper/dists/apache-maven-3.8.7-bin/678cc9d4/apache-maven-3.8.7/bin/mvn; REPO=/home/i560383/code/experiments/hello-ebpf; inner="export HOME=/home/i560383 JAVA_HOME=$JAVA_HOME PATH=$JAVA_HOME/bin:\$PATH && cd $REPO && $MVN -ntp -pl bpf-samples exec:java -Dexec.mainClass=me.bechberger.ebpf.samples.FeatureProbeSample -Dmaven.repo.local=/home/i560383/.m2/repository"; vng --network user --run $KERNEL --user root --cwd $REPO -- "$inner" < /dev/null'
```

- [ ] **Step 4: Commit**

```
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/FeatureProbeSample.java
git commit -m "feat(samples): add FeatureProbeSample dumping snapshot table"
```

---

## Task 20: Final sweep — full test matrix + docs update

**Files:**
- Modify (optional): `README.md` or `docs/` — a one-paragraph mention of `Features.hasX(...)`.

- [ ] **Step 1: Run the full Features test suite on thinkstation**

Run:
```
./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh FeaturesProbeTest FeaturesProgramTypeTest FeaturesMapTypeTest FeaturesHelperTest FeaturesKfuncTest FeaturesStructOpsTest FeaturesAttachTypeTest BtfLoaderTest FeatureRequirementsTest FeatureGatedLoadTest BPFLoadErrorSubclassesTest BPFProgramTypeTest BPFAttachTypeTest BPFHelperTest ProbeResultTest ProbeKeyTest KernelVersionTest FeaturesCacheTest'
```
Expected: every class passes. Any red spot must be diagnosed before proceeding.

- [ ] **Step 2: Run the existing bpf-module suite as a regression guard**

Run: `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh HelloWorldTest ArrayMapTest HashMapTest'`
Expected: unchanged pass counts.

- [ ] **Step 3: Update README (optional)**

If the top-level `README.md` has a feature list, add one bullet:
```
- `Features.hasProgramType/hasMapType/hasHelper/hasKfunc/hasStructOps/hasAttachType(...)` — runtime BPF capability probes with a friendly `BPFLoadError.UnsupportedKernel` at load time.
```

- [ ] **Step 4: Commit docs (only if you touched them)**

```
git add README.md
git commit -m "docs: mention Features runtime capability probes"
```

- [ ] **Step 5: Push branch and open PR (only if requested by the user)**

This plan does not push automatically. The user opens the PR after local review.

---

## Verification checklist (before declaring done)

- [ ] All 20 tasks committed on a feature branch.
- [ ] `git log --oneline` shape matches the repo style (conventional, no Claude trailers, no emoji).
- [ ] `./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh'` full sweep still green.
- [ ] `Features.snapshot()` on thinkstation prints in under 100ms warm; cold JVM under 200ms (spec §14).
- [ ] `Features.hasProgramType/hasMapType/hasHelper/hasKfunc/hasStructOps/hasAttachType` all return `true` for every 6.14+-known feature listed in the spec.
- [ ] `Features.resetCacheForTest()` is package-private, not `public`.
- [ ] `BPFProgram.BPFLoadError.UnsupportedKernel` and `MissingKfunc` reachable via the public API.
- [ ] No emoji in any file introduced.

---

## Deferred / follow-up work (out of scope for this plan)

- Generated impl-class emission of `getStaticFeatureRequirements()` — separate processor plan.
- Module-kfunc probing (currently `ProbeUnavailable`) — needs BTF module loading.
- Helper-carrier fallback loop (§6.3 says "if all carriers fail, `Unsupported`"); this plan ships a single carrier per helper and marks the rest as reject-on-EINVAL. Acceptable per spec §13 "enum drift".
- `capsh --drop=cap_bpf` unit test for `ProbeUnavailable` reason strings (spec §14 success criteria bullet 3).

---
