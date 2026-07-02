# @StructOps Sub-Plan D: new consumers (`HelloCubicSample` + Qdisc/HID smoke tests)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove `@StructOps` on non-sched-ext kinds by shipping (a) a user-facing `HelloCubicSample` for `TcpCongestionControl`, (b) real-kernel smoke tests for `QdiscOps` (with a `tc qdisc add …` round-trip) and `HidBpfOps` (skippable when no HID device is exposed to vng), and (c) documentation for the four supported struct_ops kinds. After this sub-plan, `@StructOps` is a public, documented feature with a canonical sample per kind — not just a machinery migration.

**Architecture:** Each new consumer is a small `@BPF` class implementing one of the marker interfaces landed in Sub-plan A. `HelloCubicSample` is a runnable sample under `bpf-samples/src/main/java/…/samples/`; the Qdisc/HID smoke tests live in `bpf/src/test/…/structops/` alongside `StructOpsAttachTest` from Sub-plan B. The HID smoke test uses an `Assumptions.assumeThat` gate on `/sys/class/hidraw/` so environments without a HID device skip cleanly rather than failing. Documentation lands as `docs/struct-ops.md` — a single markdown page summarising the four kinds, the annotation surface, and the two escape hatches (property placeholders, `@Sleepable`).

**Tech Stack:** Java 25, existing sample-sample-test scaffolding (`bpf-samples`), `tc` CLI (already present on thinkstation via iproute2), no new external dependencies.

**Reference spec:** `docs/superpowers/specs/2026-07-02-struct-ops-design.md` §12.2 (real-kernel tests), §13 (sample), §16 (docs).

**Depends on:** Sub-plans A, B, and C landed. Specifically A's `TcpCongestionControl`, `QdiscOps`, `HidBpfOps` marker interfaces and their JSON layouts; B's `StructOpsAttach` and the manifest emission.

---

## File Structure

**New files (samples):**

- `bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java` — the user-facing sample.

**New files (tests):**

- `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/QdiscOpsSmokeTest.java` — attaches an `@BPF` class implementing `QdiscOps`, runs `tc qdisc add dev lo root handle 1: bpf_test` (or its libbpf equivalent), asserts attach + detach.
- `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/HidBpfOpsSmokeTest.java` — attaches an `@BPF` class implementing `HidBpfOps`; asserts attach succeeds; skipped when `/sys/class/hidraw/` is empty.

**New files (docs):**

- `docs/struct-ops.md` — one-page summary: the annotation, the four marker interfaces, the two escape hatches (property placeholders + `@Sleepable`), and where to look for canonical examples.

**Modified files:**

- `README.md` (top-level) — add a one-line link to `docs/struct-ops.md` in the features list.

**Decomposition rationale:** Each smoke test can be developed independently (a HID test failure doesn't block TCP CC). The sample and its smoke test are separate concerns: the sample is user-facing (has a `main`, prints instructions), the smoke test is CI-only (assumes `assertThat` on `/proc` files). Keeping them separate lets the smoke test cover corner cases the sample doesn't demonstrate.

---

## Tasks

### Task 1: `HelloCubicSample` — TCP CC user-facing sample

**Files:**
- Create: `bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java`

- [ ] **Step 1: Write the sample**

```java
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.structops.TcpCongestionControl;
import me.bechberger.ebpf.runtime.NetworkingDefinitions.sock;
import me.bechberger.ebpf.type.Ptr;

/**
 * A minimal TCP congestion-control algorithm registered as {@code hellocubic}.
 * On each {@code congAvoid} call, the program emits a {@code bpf_printk}
 * line so the trace pipe shows evidence the algorithm is active.
 *
 * <p>Usage:
 * <pre>{@code
 *   sudo java -cp ... HelloCubicSample
 *   # in another terminal:
 *   echo hellocubic | sudo tee /proc/sys/net/ipv4/tcp_congestion_control
 *   # generate some traffic (e.g. curl a large file); then:
 *   sudo cat /sys/kernel/debug/tracing/trace_pipe
 * }</pre>
 *
 * <p>The kernel accepts algorithms declared here as valid entries in
 * {@code /proc/sys/net/ipv4/tcp_available_congestion_control} for as
 * long as the program is loaded; unloading (this JVM exits) removes them.
 */
@BPF
public abstract class HelloCubicSample extends BPFProgram implements TcpCongestionControl {

    /**
     * Return the slow-start threshold. For hellocubic we use a fixed value;
     * a real algorithm would derive it from the socket state.
     */
    @Override
    public int ssthresh(Ptr<sock> sk) {
        return 4;
    }

    /**
     * Called on every ACK when the connection is in the congestion-avoidance
     * phase. hellocubic just logs; a real algorithm updates {@code snd_cwnd}.
     */
    @Override
    public void congAvoid(Ptr<sock> sk, int ack, int acked) {
        BPFJ.bpf_printk("hellocubic congAvoid ack=%u acked=%u", ack, acked);
    }

    /**
     * The kernel-visible algorithm name. Must match the {@code net.ipv4.tcp_congestion_control}
     * value users write to activate this algorithm.
     */
    @Override
    public String name() {
        return "hellocubic";
    }

    public static void main(String[] args) throws Exception {
        try (var prog = BPFProgram.load(HelloCubicSample.class)) {
            System.out.println("hellocubic registered. To activate:");
            System.out.println("  echo hellocubic | sudo tee /proc/sys/net/ipv4/tcp_congestion_control");
            System.out.println("Trace: sudo cat /sys/kernel/debug/tracing/trace_pipe");
            System.out.println("Press Ctrl-C to unregister.");
            // Block until interrupted. The struct_ops attach lives for the lifetime
            // of the BPFProgram; close() unregisters.
            Thread.sleep(Long.MAX_VALUE);
        }
    }
}
```

- [ ] **Step 2: Compile on thinkstation**

```
rsync -avz --delete --exclude=.git --exclude=target ./ thinkstation:/home/i560383/code/experiments/hello-ebpf/
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-samples -am compile -DskipTests 2>&1 | tail -15'
```

Expected: BUILD SUCCESS. If compile fails on `Ptr<sock>`: check Sub-plan A landed `NetworkingDefinitions.sock` (either a real type or an empty stub struct). If compile fails on `BPFJ.bpf_printk` with these argument types: check that `bpf_printk`'s Java signature accepts variadic `int` args — extend if not.

- [ ] **Step 3: Sanity-run under vng**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  vng -p ./vng.profile -- bash -c "cd /home/i560383/code/experiments/hello-ebpf && \
    HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
    timeout 5 mvn -pl bpf-samples exec:java -Dexec.mainClass=me.bechberger.ebpf.samples.HelloCubicSample 2>&1 | tail -40"'
```

Expected: sample prints its instructions, the `timeout 5` kills it after 5s. During those 5s, if we could run `cat /proc/sys/net/ipv4/tcp_available_congestion_control` in a second vng shell we'd see `hellocubic`. The real assertion lives in the Task 2 smoke test.

- [ ] **Step 4: Commit**

```bash
git add bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java
git commit -m "feat(samples): HelloCubicSample — TCP CC via @StructOps"
```

---

### Task 2: TCP CC smoke test — assert `/proc` visibility

**Files:**
- Modify: `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/StructOpsAttachTest.java` (created in Sub-plan B Task 10 — add a second test method) OR create a new `HelloCubicSmokeTest.java` under `bpf-samples/src/test/…`.

**Decision:** Reuse `StructOpsAttachTest` if it's still small; if it's already grown to three or more tests, split. Default: add to `StructOpsAttachTest`.

- [ ] **Step 1: Add the test**

```java
@Test
void helloCubicRegistersInAvailableList() throws Exception {
    try (var prog = BPFProgram.load(
            me.bechberger.ebpf.samples.HelloCubicSample.class)) {
        String proc = "/proc/sys/net/ipv4/tcp_available_congestion_control";
        String available = java.nio.file.Files.readString(java.nio.file.Path.of(proc));
        assertThat(available).contains("hellocubic");

        var infos = prog.structOpsInfo();
        assertThat(infos).hasSize(1);
        assertThat(infos.get(0).kernelName()).isEqualTo("tcp_congestion_ops");
        assertThat(infos.get(0).mapName()).isEqualTo("HelloCubicSample");
    }
    // Post-close: algorithm is gone.
    String after = java.nio.file.Files.readString(java.nio.file.Path.of(
            "/proc/sys/net/ipv4/tcp_available_congestion_control"));
    assertThat(after).doesNotContain("hellocubic");
}
```

Note: this test-source is inside `bpf/`, which normally doesn't depend on `bpf-samples`. If the classpath doesn't already include `bpf-samples`, either (a) add a `test`-scope Maven dep on `bpf-samples` in `bpf/pom.xml`, or (b) inline a `@BPF` fixture class in the test file instead of referencing `HelloCubicSample`. Prefer (b) for smoke-test independence — the test class can define its own `@BPF static class HelloCcFixture extends BPFProgram implements TcpCongestionControl { … name() { return "hellocubicsmoke"; } … }` — this decouples the smoke test from any future refactoring of the sample.

Revised test (inline fixture):

```java
@BPF
abstract static class HelloCcFixture extends BPFProgram implements TcpCongestionControl {
    @Override public int ssthresh(Ptr<sock> sk) { return 4; }
    @Override public void congAvoid(Ptr<sock> sk, int ack, int acked) {}
    @Override public String name() { return "hellocubicsmoke"; }
}

@Test
void tcpCongRegistersInAvailableList() throws Exception {
    try (var prog = BPFProgram.load(HelloCcFixture.class)) {
        String proc = "/proc/sys/net/ipv4/tcp_available_congestion_control";
        assertThat(java.nio.file.Files.readString(java.nio.file.Path.of(proc)))
                .contains("hellocubicsmoke");
    }
    assertThat(java.nio.file.Files.readString(java.nio.file.Path.of(
            "/proc/sys/net/ipv4/tcp_available_congestion_control")))
            .doesNotContain("hellocubicsmoke");
}
```

- [ ] **Step 2: Run on thinkstation vng**

```
rsync -avz --delete --exclude=.git --exclude=target ./ thinkstation:/home/i560383/code/experiments/hello-ebpf/
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf StructOpsAttachTest#tcpCongRegistersInAvailableList 2>&1 | tail -25'
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/structops/StructOpsAttachTest.java
git commit -m "test(bpf): TCP CC smoke covers /proc visibility + close cleanup"
```

---

### Task 3: `QdiscOps` smoke test — attach a `Qdisc_ops`

**Files:**
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/QdiscOpsSmokeTest.java`

- [ ] **Step 1: Write the test**

`Qdisc_ops` requires `CONFIG_NET_SCH_BPF` and a kernel ≥ 6.10. thinkstation is 6.14+, so both are satisfied.

Callbacks include `enqueue`, `dequeue`, `init`, `reset`, `destroy`. The minimum viable set for a load-only test is `enqueue` returning `NET_XMIT_SUCCESS` (= 0) and `init` returning 0. Signatures come from the BTF layout in Sub-plan A's `Qdisc_ops.json`.

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class QdiscOpsSmokeTest {

    /**
     * Minimum viable Qdisc_ops. Passing sk_buff and Qdisc as opaque
     * Ptr — we don't need to inspect fields, just satisfy the attach.
     */
    @BPF
    abstract static class MinimalQdisc extends BPFProgram implements QdiscOps {
        @Override public int enqueue(Ptr<sk_buff> skb, Ptr<Qdisc> sch, Ptr<sk_buff> free_list) {
            return 0;   // NET_XMIT_SUCCESS
        }
        @Override public int init(Ptr<Qdisc> sch, Ptr<nlattr> opt, Ptr<netlink_ext_ack> extack) {
            return 0;
        }
        @Override public String id() { return "bpftest_qdisc"; }
    }

    @Test
    void attachSucceedsAndDetachesCleanly() throws Exception {
        try (var prog = BPFProgram.load(MinimalQdisc.class)) {
            var infos = prog.structOpsInfo();
            assertThat(infos).hasSize(1);
            assertThat(infos.get(0).kernelName()).isEqualTo("Qdisc_ops");
            assertThat(infos.get(0).mapName()).isEqualTo("MinimalQdisc");
            assertThat(infos.get(0).bpfLinkId()).isNotZero();
        }
        // Post-close: no leftover state — inspecting /proc/net/tc… is fragile
        // across kernels, so we simply assert the load+close round-trip worked
        // without throwing.  (A tc qdisc add invocation would be nice but
        // introduces vng-shell brittleness we don't need for a load-smoke.)
    }
}
```

Note on `id` vs `name`: `Qdisc_ops` uses a `char[16] id` slot rather than `name` (see Sub-plan A's layout JSON). If the layout says the field is `id`, the Java method is `id()`; the synthesizer emits `.id = "bpftest_qdisc"`. Adjust field name to match the layout — if unclear, `cat bpf-compiler-plugin/src/main/resources/struct-ops-layouts/Qdisc_ops.json | grep -A2 '"kind": "data"'`.

- [ ] **Step 2: Ensure required type stubs land**

`sk_buff`, `Qdisc`, `nlattr`, `netlink_ext_ack` — likely already exist as stubs in `NetworkingDefinitions` or need adding as opaque empty structs to `bpf/src/main/java/me/bechberger/ebpf/runtime/`. Grep first:

```
grep -rn "class sk_buff\|struct sk_buff\|class Qdisc\|class nlattr\|class netlink_ext_ack" \
    bpf/src/main/java bpf-samples/src/main/java 2>/dev/null | head
```

If missing, add empty `@Type public static class Qdisc {}` stubs. Sub-plan A should have already added `sk_buff` for other users; if not, that's a Sub-plan A regression, not a fix here.

- [ ] **Step 3: Run on thinkstation vng**

```
rsync -avz --delete --exclude=.git --exclude=target ./ thinkstation:/home/i560383/code/experiments/hello-ebpf/
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf QdiscOpsSmokeTest 2>&1 | tail -25'
```

Expected: PASS. If load fails with "kernel does not support struct_ops Qdisc_ops": verify `CONFIG_NET_SCH_BPF=y` in the vng kernel config. If it's disabled, mark the test `@EnabledIf("Qdisc_ops feature-probe positive")` — using the `Features.hasStructOps("Qdisc_ops")` gate as a JUnit 5 `assumeTrue`.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/structops/QdiscOpsSmokeTest.java
# plus any type-stub additions
git commit -m "test(bpf): QdiscOpsSmokeTest — minimal Qdisc_ops attach round-trip"
```

---

### Task 4: `HidBpfOps` smoke test — attach with hardware gate

**Files:**
- Create: `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/HidBpfOpsSmokeTest.java`

- [ ] **Step 1: Write the test**

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class HidBpfOpsSmokeTest {

    @BPF
    abstract static class MinimalHid extends BPFProgram implements HidBpfOps {
        @Override public int hidRawEvent(Ptr<hid_bpf_ctx> ctx) {
            return 0;
        }
    }

    @Test
    void attachSucceedsWhenHidraw() throws Exception {
        // The hid_bpf_ops attach path itself doesn't require a HID device;
        // however, real interactions (device binding) do.  We skip when the
        // vng environment doesn't expose a HID device, because a failed
        // attach in that shape is environmental, not a code bug.
        assumeTrue(Files.list(Path.of("/sys/class/hidraw")).findAny().isPresent(),
                "no HID device exposed to vng");

        try (var prog = BPFProgram.load(MinimalHid.class)) {
            var infos = prog.structOpsInfo();
            assertThat(infos).hasSize(1);
            assertThat(infos.get(0).kernelName()).isEqualTo("hid_bpf_ops");
            assertThat(infos.get(0).mapName()).isEqualTo("MinimalHid");
        }
    }
}
```

- [ ] **Step 2: Verify the `hid_bpf_ctx` type stub**

Same as Task 3 — grep the tree for `hid_bpf_ctx`. If missing, add an empty `@Type` stub in an appropriate package under `bpf/src/main/java/me/bechberger/ebpf/runtime/`. If Sub-plan A didn't include this, add it here — small enough not to warrant a separate sub-plan revision.

- [ ] **Step 3: Run on thinkstation vng**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf HidBpfOpsSmokeTest 2>&1 | tail -25'
```

Expected: SKIPPED (`vng` typically doesn't expose HID devices). If PASS, we got a hardware pass by luck — great, but not required for the sub-plan.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/test/java/me/bechberger/ebpf/bpf/structops/HidBpfOpsSmokeTest.java
git commit -m "test(bpf): HidBpfOpsSmokeTest — attach with /sys/class/hidraw assumption"
```

---

### Task 5: Documentation — `docs/struct-ops.md`

**Files:**
- Create: `docs/struct-ops.md`
- Modify: `README.md` (top-level features list)

- [ ] **Step 1: Write `docs/struct-ops.md`**

```markdown
# `@StructOps`: implementing kernel struct_ops in Java

A `@StructOps` interface bundles the kernel's C-level callback table for a
`bpf_struct_ops` kind (sched-ext, TCP congestion control, qdisc, HID) into
a Java interface. Extending a class with the interface, overriding the
callbacks you care about, and loading via `BPFProgram.load(YourClass.class)`
compiles a struct_ops BPF program, attaches it, and registers it with the
kernel — all in one step.

## Supported kinds

| Java interface           | Kernel struct           | Kernel since |
|--------------------------|-------------------------|-------------:|
| `SchedExtOps`            | `sched_ext_ops`         |         6.12 |
| `TcpCongestionControl`   | `tcp_congestion_ops`    |          5.6 |
| `QdiscOps`               | `Qdisc_ops`         |         6.10 |
| `HidBpfOps`              | `hid_bpf_ops`           |         6.11 |

hello-ebpf's kernel floor is 6.14, so all four are available without
compile-time gating.

## The annotation

```java
@StructOps(
    value = "tcp_congestion_ops",       // required — the kernel struct name
    sectionPrefix = "struct_ops/",       // optional — override for non-standard prefixes
    instanceName = ""                    // optional — override the emitted map name
)
public interface TcpCongestionControl { … }
```

Values default to sensible sched-ext / TCP defaults; you rarely need to
override.

## Method-to-field mapping

- Java method name → C field name via camelCase → snake_case (`congAvoid` → `cong_avoid`).
- Return type and arg types validated against the BTF layout at compile time.
- Un-overridden default methods are omitted from the emitted struct — the
  kernel accepts NULL for optional slots.
- A `String name()` method emits `.name = "…"` as a literal initializer,
  not a synthesized program.

## `@Sleepable`

Some struct_ops methods are declared sleepable in their BTF metadata
(e.g. sched-ext's `sched_init`). Mark the Java override with
`@Sleepable` and the plugin emits `SEC("struct_ops.s/<field>")` instead
of `SEC("struct_ops/<field>")`.

```java
@BPF public abstract class MyScheduler extends BPFProgram implements SchedExtOps {
    @Override @Sleepable public int schedInit() { return 0; }
}
```

## Property placeholders (sched-ext only)

Sched-ext historically supports `__property_<name>` placeholders for the
`flags`, `timeout_ms`, and `name` fields — resolved at load time from
`@PropertyDefinition` annotations. These are preserved verbatim by the
struct-ops synthesizer; you don't need to declare them anywhere.

## Runtime attach

`BPFProgram.load(YourClass.class)` handles the full lifecycle:

1. Compile and load the BPF object file (existing behaviour).
2. For each `@StructOps` interface implemented by the class, call
   `bpf_map__attach_struct_ops(…)`.
3. Populate `prog.structOpsInfo()` with `(kernelName, mapName, mapFd, bpfLinkId)`
   entries — useful for diagnostics.
4. On `close()`, all attached links are detached automatically.

If the running kernel doesn't advertise the struct_ops kind (via
`Features.hasStructOps(name)`), load throws
`BPFLoadError.UnsupportedKernel(name, since)` before touching the BPF
object.

## Canonical examples

| Kind                    | Sample                                                                       |
|-------------------------|------------------------------------------------------------------------------|
| `SchedExtOps`           | `bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java` |
| `TcpCongestionControl`  | `bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloCubicSample.java` |
| `QdiscOps`              | `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/QdiscOpsSmokeTest.java`  |
| `HidBpfOps`             | `bpf/src/test/java/me/bechberger/ebpf/bpf/structops/HidBpfOpsSmokeTest.java` |

## Escape hatches

- Hand-writing a `SEC("struct_ops/…")` method directly on a `@BPF` class
  (via `@BPFFunction(section = "…", headerTemplate = "…")`) still works.
  The plugin only intercepts methods that are `@Override`s of a
  `@StructOps` interface — a manually annotated method sitting alongside
  is left untouched.
- To emit a struct_ops kind not yet covered by a marker interface,
  declare your own interface annotated `@StructOps("your_kind")`. You
  must also add a `your_kind.json` layout under
  `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/` for BTF
  validation — see `struct-ops-layouts/README.md` for the schema.
```

- [ ] **Step 2: Add a link to the README**

Read the top-level `README.md` and add one line to the features list — e.g. `- **struct_ops in Java** — implement sched-ext, TCP CC, qdisc, or HID BPF via a Java interface; [see docs/struct-ops.md](docs/struct-ops.md).`

- [ ] **Step 3: Commit**

```bash
git add docs/struct-ops.md README.md
git commit -m "docs: struct-ops guide + README pointer"
```

---

### Task 6: End-of-plan verification

Not a code task — a final round-trip on thinkstation before merging the branch.

- [ ] **Step 1: Full plugin + bpf + samples build**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin,bpf,bpf-samples -am install -DskipTests 2>&1 | tail -20'
```

BUILD SUCCESS across all three modules.

- [ ] **Step 2: All struct-ops-related tests under vng**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf "StructOpsAttachTest,StructOpsFeatureGateTest,QdiscOpsSmokeTest,HidBpfOpsSmokeTest,SchedulerCodegenParityTest" 2>&1 | tail -40'
```

Expected: TCP CC + sched-ext parity + feature gate PASS; Qdisc PASS (or SKIPPED with a specific reason if `CONFIG_NET_SCH_BPF` is off); HID SKIPPED (no hardware) or PASS.

- [ ] **Step 3: The scheduler regression sweep**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  ./scripts/run-tests-vng.sh bpf-samples "SchedulerSmokeTest,SchedulerBehaviorTest" 2>&1 | tail -30'
```

All PASS with same or better numbers than pre-@StructOps baseline.

- [ ] **Step 4: HelloCubic manual smoke** (optional but recommended)

Run the sample under vng and, from a second vng shell, verify `/proc/sys/net/ipv4/tcp_available_congestion_control` contains `hellocubic` while the sample is running. This is manual because the sample's `main()` blocks on `Thread.sleep`; automating it is what Task 2's smoke test already does.

- [ ] **Step 5: No commit for this task** — verification only.

---

## Verification

**Acceptance criteria** (from spec §12):

1. `HelloCubicSample` loads without error, registers `hellocubic` in
   `/proc/sys/net/ipv4/tcp_available_congestion_control`, and un-registers
   on close.
2. `QdiscOpsSmokeTest` passes (or skips with a documented reason).
3. `HidBpfOpsSmokeTest` skips when no HID device is exposed to vng, passes
   otherwise.
4. Every existing scheduler sample still loads and runs — no regression
   from the Sub-plan C migration.
5. `docs/struct-ops.md` exists and is linked from the top-level `README.md`.

## Out of scope

- **Cubic-derivation algorithm.** `HelloCubicSample.congAvoid` is a
  bpf_printk stub, not a working cubic clone. Anyone using this as a
  starting point for a real algorithm follows the linked kernel
  documentation.
- **Multi-kind class** (a class implementing both `TcpCongestionControl`
  and `QdiscOps`). The plugin already supports this shape — nothing in
  Sub-plans A/B/C blocks it — but there's no in-tree consumer motivating
  a test. Defer.
- **`Sleepable` on Qdisc/HID methods.** No current kernel BTF marks any
  Qdisc or HID method sleepable, so no test coverage is needed. If it
  changes upstream, `Sub-plan C`'s `@Sleepable` handles it automatically.
- **CI integration.** Wiring the vng test runs into GitHub Actions is
  handled elsewhere (there's a separate `ci-vng` workflow track).
