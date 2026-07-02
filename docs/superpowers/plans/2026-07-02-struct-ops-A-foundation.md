# @StructOps Sub-Plan A: BTF layouts + `@StructOps` annotation + marker interfaces

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the pure-data foundation for the generic `@StructOps` runtime — a resource-shipped BTF-derived layout catalogue for four kernel struct_ops kinds, plus the `@StructOps` annotation and four marker interfaces (`SchedExtOps`, `TcpCongestionControl`, `QdiscOps`, `HidBpfOps`). Sub-plans B/C/D layer plugin codegen, sched-ext migration, and new consumers on top of this. Standalone success: everything compiles, layouts parse in a unit test, but no user code changes behaviour yet.

**Architecture:** Ship pre-dumped BTF layouts (JSON) under `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/` — one file per struct_ops kind. A small `StructOpsLayout` record class in the plugin reads and validates them at load time. The `@StructOps` source-retention annotation lives in the annotations module; the marker interfaces live in `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/`. No plugin behaviour changes yet — later sub-plans read the layouts and drive C emission.

**Tech Stack:** Java 25, Jackson (already on the plugin classpath — check via `mvn dependency:tree` at Task 0), JUnit 5 + AssertJ, `bpftool` (thinkstation-only) for the initial dump.

**Reference spec:** `docs/superpowers/specs/2026-07-02-struct-ops-design.md` §5, §7, §19 step 1-2.

---

## File Structure

**New files:**

- `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/StructOps.java` — the annotation (SOURCE retention, TYPE target).
- `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/sched_ext_ops.json` — field list for `sched_ext_ops`.
- `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/tcp_congestion_ops.json` — field list for `tcp_congestion_ops`.
- `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/bpf_qdisc_ops.json` — field list for `bpf_qdisc_ops`.
- `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/hid_bpf_ops.json` — field list for `hid_bpf_ops`.
- `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/README.md` — refresh procedure.
- `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsLayout.java` — record + JSON loader.
- `bpf-compiler-plugin/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsLayoutTest.java` — unit tests.
- `scripts/extract-struct-ops-layouts.py` — dump helper that pipes from `bpftool btf dump file … format c` to JSON, run manually on thinkstation to refresh.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/SchedExtOps.java` — marker interface `@StructOps("sched_ext_ops")`.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/TcpCongestionControl.java` — marker interface.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/QdiscOps.java` — marker interface.
- `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/HidBpfOps.java` — marker interface.

**Files NOT touched in this sub-plan:** `Scheduler.java`, `SchedulerBase.java`, `BPFProgram.java`, `CompilerPlugin.java`, `TypeProcessor.java`. Those come in Sub-plans B and C.

**Decomposition rationale:** Each marker interface is its own file because their method surfaces are unrelated — grouping four in one file would defeat "one clear responsibility." The JSON layouts are ordered by kind for the same reason. `StructOpsLayout` is one file because it's one loader with one record type; splitting the record and the loader would be premature.

---

## Tasks

### Task 0: Discovery — Jackson on the plugin classpath?

**Files:** none (read-only)

- [ ] **Step 1: Check for Jackson**

Run on thinkstation:
```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin dependency:tree -DoutputType=text 2>&1 | grep -iE "jackson|gson|json"'
```

- [ ] **Step 2: Note the result**

Expected: one of
- Jackson is present transitively → use `com.fasterxml.jackson.databind.ObjectMapper`.
- Gson is present transitively → use `com.google.gson.Gson`.
- Neither → the JSON is small and fixed-shape; hand-roll a minimal parser in `StructOpsLayout` using `java.util.regex` OR add a dependency (prefer Jackson if we add).

Record the finding in this file inline as a comment above Task 1 so the implementer knows which API to use. Do NOT commit at this step — it feeds Task 1.

---

### Task 1: `StructOpsLayout` record + JSON loader

**Files:**
- Create: `bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsLayout.java`
- Test: `bpf-compiler-plugin/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsLayoutTest.java`

- [ ] **Step 1: Write the failing test**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StructOpsLayoutTest {

    @Test
    void loadsBundledSchedExtOps() {
        StructOpsLayout layout = StructOpsLayout.load("sched_ext_ops");
        assertEquals("sched_ext_ops", layout.kernelName());
        assertEquals("6.12", layout.since());
        // Spot-check three well-known fields exist.
        assertTrue(layout.hasField("enqueue"));
        assertTrue(layout.hasField("select_cpu"));
        assertTrue(layout.hasField("name"));
        StructOpsLayout.Field enq = layout.field("enqueue");
        assertEquals("function", enq.kind());
        assertEquals("void", enq.returnType());
        assertEquals(2, enq.args().size());
        assertEquals("struct task_struct *", enq.args().get(0).type());
    }

    @Test
    void unknownKindThrows() {
        var ex = assertThrows(IllegalArgumentException.class,
                () -> StructOpsLayout.load("no_such_ops"));
        assertTrue(ex.getMessage().contains("no_such_ops"));
        assertTrue(ex.getMessage().contains("supported"));
    }

    @Test
    void nameFieldIsDataKind() {
        StructOpsLayout layout = StructOpsLayout.load("tcp_congestion_ops");
        StructOpsLayout.Field name = layout.field("name");
        assertEquals("data", name.kind());
        assertEquals("char[16]", name.returnType());
    }

    @Test
    void allFourLayoutsLoadClean() {
        for (String k : java.util.List.of("sched_ext_ops",
                                         "tcp_congestion_ops",
                                         "bpf_qdisc_ops",
                                         "hid_bpf_ops")) {
            StructOpsLayout l = StructOpsLayout.load(k);
            assertEquals(k, l.kernelName());
            assertFalse(l.fields().isEmpty(), k + " has no fields");
            assertNotNull(l.since(), k + " missing since");
        }
    }
}
```

- [ ] **Step 2: Run the test — expect FAIL**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin -Dtest=StructOpsLayoutTest test 2>&1 | tail -30'
```
Expected: compile failure (`cannot find symbol class StructOpsLayout`).

- [ ] **Step 3: Implement `StructOpsLayout`**

```java
package me.bechberger.ebpf.bpf.compiler.structops;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A pre-dumped BTF layout for one kernel struct_ops kind (e.g.
 * {@code sched_ext_ops}, {@code tcp_congestion_ops}). Loaded from
 * {@code struct-ops-layouts/<kernelName>.json} on the plugin classpath.
 *
 * <p>Layouts are static data: they describe the kernel struct's shape
 * (field names, kinds, prototypes) at the version they were dumped from.
 * Runtime feature-probing (via {@code Features.hasStructOps}) confirms
 * the running kernel still has the struct before load.
 */
public record StructOpsLayout(
        String kernelName,
        String since,
        List<Field> fields) {

    public record Field(String name, String kind, String returnType, List<Arg> args) {
        public record Arg(String name, String type) {}
    }

    private static final Set<String> SUPPORTED = Set.of(
            "sched_ext_ops", "tcp_congestion_ops", "bpf_qdisc_ops", "hid_bpf_ops");

    public static StructOpsLayout load(String kernelName) {
        if (!SUPPORTED.contains(kernelName)) {
            throw new IllegalArgumentException(
                    "unknown struct_ops kind '" + kernelName + "' — supported: "
                            + String.join(", ", SUPPORTED)
                            + ". Refresh bpf-compiler-plugin/src/main/resources/struct-ops-layouts/ "
                            + "if you're adding a new one.");
        }
        String path = "/struct-ops-layouts/" + kernelName + ".json";
        try (InputStream in = StructOpsLayout.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException(
                        "bundled layout missing: " + path
                                + " — this is a hello-ebpf build error, please report.");
            }
            byte[] bytes = in.readAllBytes();
            return parse(new String(bytes, java.nio.charset.StandardCharsets.UTF_8));
        } catch (java.io.IOException e) {
            throw new IllegalStateException("failed to read " + path, e);
        }
    }

    public boolean hasField(String name) {
        return fields.stream().anyMatch(f -> f.name.equals(name));
    }

    public Field field(String name) {
        return fields.stream().filter(f -> f.name.equals(name)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "no field '" + name + "' in " + kernelName));
    }

    static StructOpsLayout parse(String json) {
        // Delegate to whichever JSON library Task 0 identified.
        // Fill in when Task 0 result is known — see the note at the top of Task 1.
        // If neither Jackson nor Gson is on the classpath, use a hand-rolled
        // parser sized to this specific schema (kernelName/since/fields[] shape).
        throw new UnsupportedOperationException("stub — filled in per Task 0 result");
    }
}
```

- [ ] **Step 4: Fill in `parse` per Task 0 result**

Whichever library Task 0 identified, use it here. If Jackson: `new ObjectMapper().readValue(json, StructOpsLayout.class)` with a static-nested `@JsonCreator` on `Field` and `Arg`. If Gson: `new Gson().fromJson(json, StructOpsLayout.class)`. If neither: hand-roll — the schema is `{"kernelName": "...", "since": "...", "fields": [{"name":"...", "kind":"...", "returnType":"...", "args":[{"name":"...", "type":"..."}]}]}`, which a 60-line recursive descent parser can handle.

- [ ] **Step 5: Run the test — expect FAIL (layouts don't exist yet)**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin -Dtest=StructOpsLayoutTest test 2>&1 | tail -30'
```
Expected: `IllegalStateException: bundled layout missing`. Loader compiles; layouts absent.

- [ ] **Step 6: Commit**

```bash
git add bpf-compiler-plugin/src/main/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsLayout.java
git add bpf-compiler-plugin/src/test/java/me/bechberger/ebpf/bpf/compiler/structops/StructOpsLayoutTest.java
git commit -m "feat(plugin): StructOpsLayout record + JSON loader"
```

---

### Task 2: `extract-struct-ops-layouts.py` — dump script

**Files:**
- Create: `scripts/extract-struct-ops-layouts.py`

- [ ] **Step 1: Write the script**

The script parses `bpftool btf dump file /sys/kernel/btf/vmlinux format c` output for the four struct_ops kinds. `bpftool` emits each as a C `struct <name> { … };` declaration. Parse the four target structs by name; for each field, classify as `function` (pointer-to-function prototype) or `data` (scalar / char array); emit one JSON per kind.

Script layout (mac-writable, thinkstation-executable):

```python
#!/usr/bin/env python3
"""
Extract per-kind struct_ops layouts as JSON.

Usage:
    sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
    python3 scripts/extract-struct-ops-layouts.py /tmp/vmlinux.h \
        bpf-compiler-plugin/src/main/resources/struct-ops-layouts/

Writes one <kernelName>.json per supported kind. Overwrites existing files.
"""

import json
import re
import sys
from pathlib import Path

TARGETS = {
    "sched_ext_ops":     "6.12",
    "tcp_congestion_ops": "5.6",   # below our 6.14 floor; effectively no gate
    "bpf_qdisc_ops":     "6.10",
    "hid_bpf_ops":       "6.11",
}

STRUCT_RE = re.compile(
    r"struct\s+(\w+)\s*\{(.+?)\}\s*;",
    re.DOTALL,
)
FUNCPTR_RE = re.compile(
    r"^\s*(?P<ret>[\w\s\*]+?)\s*\(\s*\*\s*(?P<name>\w+)\s*\)\s*\((?P<args>.*?)\)\s*;",
    re.DOTALL,
)
DATA_RE = re.compile(
    r"^\s*(?P<type>[\w\s\*]+?)\s+(?P<name>\w+)(?P<arr>\[\d+\])?\s*;",
)

def parse_args(argstr: str):
    argstr = argstr.strip()
    if argstr == "" or argstr == "void":
        return []
    out = []
    # Split on commas at paren depth 0
    depth = 0
    cur = []
    for ch in argstr + ",":
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            piece = "".join(cur).strip()
            if piece:
                # "struct task_struct *p" → name="p", type="struct task_struct *"
                m = re.match(r"^(.+?)(\w+)\s*$", piece)
                if m:
                    type_part = m.group(1).strip()
                    name_part = m.group(2).strip()
                    if type_part.endswith("*") or " " in type_part:
                        out.append({"name": name_part, "type": type_part})
                    else:
                        # Anonymous or scalar type without a name (rare)
                        out.append({"name": "arg" + str(len(out)), "type": piece})
                else:
                    out.append({"name": "arg" + str(len(out)), "type": piece})
            cur = []
            continue
        cur.append(ch)
    return out

def extract(vmlinux_c: str, kind: str):
    for match in STRUCT_RE.finditer(vmlinux_c):
        name = match.group(1)
        if name != kind:
            continue
        body = match.group(2)
        fields = []
        # Split fields by top-level `;` — but we already have a per-field regex.
        # Split lines carefully: some function-pointer decls span multiple lines.
        # Walk paren depth to split on `;` at depth 0.
        depth = 0
        cur = []
        raw_fields = []
        for ch in body + ";":
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if ch == ";" and depth == 0:
                piece = "".join(cur).strip()
                if piece:
                    raw_fields.append(piece + ";")
                cur = []
                continue
            cur.append(ch)
        for raw in raw_fields:
            fm = FUNCPTR_RE.match(raw)
            if fm:
                fields.append({
                    "name": fm.group("name"),
                    "kind": "function",
                    "returnType": fm.group("ret").strip(),
                    "args": parse_args(fm.group("args")),
                })
                continue
            dm = DATA_RE.match(raw)
            if dm:
                t = dm.group("type").strip()
                arr = dm.group("arr") or ""
                fields.append({
                    "name": dm.group("name"),
                    "kind": "data",
                    "returnType": t + arr,
                    "args": [],
                })
        return fields
    return None

def main():
    if len(sys.argv) != 3:
        print("usage: extract-struct-ops-layouts.py <vmlinux.h> <out-dir>", file=sys.stderr)
        sys.exit(2)
    vmlinux_h = Path(sys.argv[1]).read_text()
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    for kind, since in TARGETS.items():
        fields = extract(vmlinux_h, kind)
        if fields is None:
            print(f"warn: struct {kind} not found in vmlinux; skipping", file=sys.stderr)
            continue
        payload = {"kernelName": kind, "since": since, "fields": fields}
        out = out_dir / f"{kind}.json"
        out.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"wrote {out} ({len(fields)} fields)")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Test-run on thinkstation**

```
ssh thinkstation 'sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h && \
  wc -l /tmp/vmlinux.h'
```
Expected: ~200k+ lines. (If `bpftool` is missing, install with `sudo apt-get install -y linux-tools-common linux-tools-generic`.)

- [ ] **Step 3: Commit**

```bash
git add scripts/extract-struct-ops-layouts.py
chmod +x scripts/extract-struct-ops-layouts.py
git commit -m "feat(scripts): extract-struct-ops-layouts.py for BTF→JSON"
```

---

### Task 3: Generate and land the four JSON layouts

**Files:**
- Create: `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/sched_ext_ops.json`
- Create: `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/tcp_congestion_ops.json`
- Create: `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/bpf_qdisc_ops.json`
- Create: `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/hid_bpf_ops.json`

- [ ] **Step 1: Sync worktree to thinkstation and run the extractor**

```
rsync -avz --delete --exclude=.git --exclude=target ./ thinkstation:/home/i560383/code/experiments/hello-ebpf/
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h && \
  python3 scripts/extract-struct-ops-layouts.py /tmp/vmlinux.h \
    bpf-compiler-plugin/src/main/resources/struct-ops-layouts/'
```

- [ ] **Step 2: Pull the four JSONs back to the mac**

```
rsync -avz thinkstation:/home/i560383/code/experiments/hello-ebpf/bpf-compiler-plugin/src/main/resources/struct-ops-layouts/*.json \
    bpf-compiler-plugin/src/main/resources/struct-ops-layouts/
```

- [ ] **Step 3: Sanity-check the sched_ext_ops layout against Scheduler.java**

Cross-check: does the generated `sched_ext_ops.json` contain every field name referenced in `Scheduler.java:200-236` (the `SCX_OPS_DEFINE(sched_ops, .select_cpu = ..., .enqueue = ...)` block)? Expected fields: `select_cpu`, `enqueue`, `dispatch`, `update_idle`, `init_task`, `init`, `exit`, `runnable`, `running`, `enable`, `disable`, `stopping`, `dequeue`, `tick`, `quiescent`, `cpu_acquire`, `cpu_release`, `cpu_online`, `cpu_offline`, `core_sched_before`, `yield`, `set_weight`, `set_cpumask`, `exit_task`, `dump`, `dump_cpu`, `dump_task`, `cgroup_init`, `cgroup_exit`, `cgroup_prep_move`, `cgroup_cancel_move`, `cgroup_move`, `cgroup_set_weight`, `cgroup_set_bandwidth`, `flags`, `timeout_ms`, `name`.

Also confirm `tcp_congestion_ops.name` has `kind = "data"` and `returnType` starts with `char[`. If not, the extractor's `DATA_RE` needs tuning — fix it inline before proceeding.

- [ ] **Step 4: Re-run the unit test — expect PASS**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin -Dtest=StructOpsLayoutTest test 2>&1 | tail -20'
```
Expected: 4/4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add bpf-compiler-plugin/src/main/resources/struct-ops-layouts/*.json
git commit -m "feat(plugin): BTF-derived struct_ops layouts for four kinds"
```

---

### Task 4: Layouts README

**Files:**
- Create: `bpf-compiler-plugin/src/main/resources/struct-ops-layouts/README.md`

- [ ] **Step 1: Write it**

```markdown
# struct_ops layouts

Pre-dumped BTF layouts for the kernel struct_ops kinds hello-ebpf supports.
Consumed at plugin-compile time by `StructOpsLayout.load(kind)`; not consulted
at runtime.

## Refresh procedure

Run against a live 6.14+ kernel (thinkstation qualifies):

```
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/vmlinux.h
python3 scripts/extract-struct-ops-layouts.py /tmp/vmlinux.h \
    bpf-compiler-plugin/src/main/resources/struct-ops-layouts/
```

Verify no unexpected field additions/removals:

```
git diff bpf-compiler-plugin/src/main/resources/struct-ops-layouts/
```

Land the refresh in a commit of its own with a note in the message about
which kernel version the dump was taken from.

## When to refresh

- A new kernel adds a field to one of the four supported kinds → refresh, land,
  and consider bumping the `since` for that field (fine-grained gating is a
  future roadmap item — today's `since` is per-kind, not per-field).
- A kernel renames a field → the plugin will emit a compile error for
  existing user code that overrides that name. Refresh, and update the
  matching marker interface's method name.
- Adding a new supported kind → dump-script needs an entry in `TARGETS`,
  a new marker interface, a new codegen test.
```

- [ ] **Step 2: Commit**

```bash
git add bpf-compiler-plugin/src/main/resources/struct-ops-layouts/README.md
git commit -m "docs(plugin): struct-ops-layouts refresh procedure"
```

---

### Task 5: `@StructOps` annotation

**Files:**
- Create: `annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/StructOps.java`

- [ ] **Step 1: Write the annotation**

```java
package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an interface as the Java mirror of a kernel {@code bpf_struct_ops}
 * table. The interface's methods are the struct_ops callback slots; their
 * names lower to kernel field names via camelCase → snake_case.
 *
 * <p>When a {@code @BPF} class implements a {@code @StructOps}-annotated
 * interface, the hello-ebpf compiler plugin:
 * <ol>
 *   <li>Loads the BTF-derived layout for {@link #value()} from
 *       {@code bpf-compiler-plugin/src/main/resources/struct-ops-layouts/}.</li>
 *   <li>Validates each overridden method's return/arg types against the
 *       kernel field prototype.</li>
 *   <li>Emits one BPF program per overridden method plus a
 *       {@code SEC(".struct_ops.link")} struct instance for attach.</li>
 * </ol>
 *
 * <p>Un-overridden interface methods (defaults) emit nothing; the kernel
 * accepts NULL for optional callbacks. The interface itself must be
 * annotated directly — the plugin does not follow chains of extending
 * interfaces.
 */
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
@Documented
public @interface StructOps {

    /** Kernel BTF type name of the struct_ops kind, e.g.
     *  {@code "sched_ext_ops"}, {@code "tcp_congestion_ops"},
     *  {@code "bpf_qdisc_ops"}, {@code "hid_bpf_ops"}. Must match a
     *  bundled layout file. */
    String value();

    /** BPF section prefix used for each callback's {@code SEC(...)}.
     *  Default {@code "struct_ops/"}. Set to {@code "struct_ops.s/"} for
     *  sleepable kinds. Rarely overridden per-interface; users typically
     *  don't touch it. */
    String sectionPrefix() default "struct_ops/";

    /** Optional override for the C-side struct instance variable name.
     *  Defaults to the implementing {@code @BPF} class's simple name.
     *  Used for the {@code SEC(".struct_ops.link") struct <kind> <name>}
     *  declaration and matches libbpf's map-name lookup. */
    String instanceName() default "";
}
```

- [ ] **Step 2: Verify it compiles**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl annotations -am compile 2>&1 | tail -15'
```
Expected: BUILD SUCCESS.

- [ ] **Step 3: Commit**

```bash
git add annotations/src/main/java/me/bechberger/ebpf/annotations/bpf/StructOps.java
git commit -m "feat(annotations): @StructOps interface annotation"
```

---

### Task 6: `SchedExtOps` marker interface (a copy-of-Scheduler shape, without behaviour)

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/SchedExtOps.java`

Purpose: forward-compat marker for future users who want to write a scheduler *without* extending `SchedulerBase`. Existing `Scheduler` keeps working; Sub-plan C is where Scheduler.java itself becomes `@StructOps("sched_ext_ops")`. This file exists so users can `implements SchedExtOps` today.

- [ ] **Step 1: Write it**

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.ScxDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.runtime.helpers.BpfDefinitions;
import me.bechberger.ebpf.runtime;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code sched_ext_ops}. Implement on a {@code @BPF}
 * class to write a sched-ext scheduler that does not extend
 * {@code SchedulerBase} — the plugin emits every overridden callback as a
 * {@code SEC("struct_ops/<field>")} program and attaches via
 * {@code bpf_map__attach_struct_ops}.
 *
 * <p>Every method has an empty default; users override only what they need.
 * The kernel requires at least {@code enqueue}, so failing to override
 * that is a load-time failure (surfaced as
 * {@code BPFLoadError.StructOpsAttachFailed}).
 *
 * <p>The existing {@link me.bechberger.ebpf.bpf.Scheduler} interface remains
 * for backwards compatibility with in-tree consumers; new schedulers may
 * use either. Sub-plan C consolidates them.
 */
@StructOps("sched_ext_ops")
public interface SchedExtOps {

    default int selectCpu(Ptr<TaskDefinitions.task_struct> p, int prevCpu, long wakeFlags) { return prevCpu; }
    default void enqueue(Ptr<TaskDefinitions.task_struct> p, long enqFlags) { }
    default void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) { }
    default void updateIdle(int cpu, boolean idle) { }
    default int  initTask(Ptr<TaskDefinitions.task_struct> p, Ptr<ScxDefinitions.scx_init_task_args> args) { return 0; }
    default int  init() { return 0; }
    default void exit(Ptr<ScxDefinitions.scx_exit_info> ei) { }
    default void runnable(Ptr<TaskDefinitions.task_struct> p, @Unsigned long enqFlags) { }
    default void running(Ptr<TaskDefinitions.task_struct> p) { }
    default void enable(Ptr<TaskDefinitions.task_struct> p) { }
    default void disable(Ptr<TaskDefinitions.task_struct> p) { }
    default void stopping(Ptr<TaskDefinitions.task_struct> p, boolean runnable) { }
    default void dequeue(Ptr<TaskDefinitions.task_struct> p, @Unsigned long deqFlags) { }
    default void tick(Ptr<TaskDefinitions.task_struct> p) { }
    default void quiescent(Ptr<TaskDefinitions.task_struct> p, @Unsigned long enqFlags) { }
    default void cpuAcquire(int cpu, Ptr<ScxDefinitions.scx_cpu_acquire_args> args) { }
    default void cpuRelease(int cpu, Ptr<ScxDefinitions.scx_cpu_release_args> args) { }
    default void cpuOnline(int cpu) { }
    default void cpuOffline(int cpu) { }
    default boolean coreSchedBefore(Ptr<TaskDefinitions.task_struct> a, Ptr<TaskDefinitions.task_struct> b) { return false; }
    default boolean yield(Ptr<TaskDefinitions.task_struct> from, Ptr<TaskDefinitions.task_struct> to) { return false; }
    default void setWeight(Ptr<TaskDefinitions.task_struct> p, @Unsigned int weight) { }
    default void setCpumask(Ptr<TaskDefinitions.task_struct> p, Ptr<runtime.cpumask> cpumask) { }
    default void exitTask(Ptr<TaskDefinitions.task_struct> p, Ptr<ScxDefinitions.scx_exit_task_args> args) { }
    default void dump(Ptr<ScxDefinitions.scx_dump_ctx> dumpCtx) { }
    default void dumpCpu(Ptr<ScxDefinitions.scx_dump_ctx> dumpCtx, int cpu, boolean idle) { }
    default void dumpTask(Ptr<ScxDefinitions.scx_dump_ctx> dumpCtx, Ptr<TaskDefinitions.task_struct> p) { }
    default int  cgroupInit(Ptr<runtime.cgroup> cgrp, Ptr<ScxDefinitions.scx_cgroup_init_args> args) { return 0; }
    default void cgroupExit(Ptr<runtime.cgroup> cgrp) { }
    default int  cgroupPrepMove(Ptr<TaskDefinitions.task_struct> p, Ptr<runtime.cgroup> from, Ptr<runtime.cgroup> to) { return 0; }
    default void cgroupCancelMove(Ptr<TaskDefinitions.task_struct> p) { }
    default void cgroupMove(Ptr<TaskDefinitions.task_struct> p) { }
    default void cgroupSetWeight(Ptr<runtime.cgroup> cgrp, @Unsigned int weight) { }
    default void cgroupSetBandwidth(Ptr<runtime.cgroup> cgrp, @Unsigned long period, @Unsigned long quota, @Unsigned long burst) { }
    // "name" is a data field — String default; plugin lowers to char[16].
    default String name() { return "hello_ext"; }
}
```

- [ ] **Step 2: Verify it compiles**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf -am compile 2>&1 | tail -20'
```
Expected: BUILD SUCCESS. If the `runtime.cgroup` / `runtime.cpumask` imports don't resolve, adjust to the correct package based on what `Scheduler.java` uses (grep it) — the intent is: same types as `Scheduler`.

- [ ] **Step 3: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/structops/SchedExtOps.java
git commit -m "feat(structops): SchedExtOps marker interface"
```

---

### Task 7: `TcpCongestionControl` marker interface

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/TcpCongestionControl.java`

- [ ] **Step 1: Look up the `sock` and `rate_sample` types**

Grep for existing bindings; if not present, use `runtime.NetworkingDefinitions.sock` or the closest existing pattern. Record what you find so Task 8 does the same for `sk_buff`/`Qdisc`.

```
grep -rn "class sock\b\|record sock\b\|struct sock" bpf-runtime/src/main/java/ 2>&1 | head -10
grep -rn "class rate_sample\|record rate_sample" bpf-runtime/src/main/java/ 2>&1 | head -10
```

If missing: add a placeholder like `runtime.NetworkingDefinitions.sock` empty struct in `bpf-runtime` (a new `@Type` empty class is the minimum). Do this in a small commit before the interface itself so the interface compiles.

- [ ] **Step 2: Write the interface**

Assumption from spec §5.2: methods `init`, `release`, `ssthresh`, `congAvoid`, `setState`, `cwndEvent`, `undoCwnd`, `pktsAcked`, `minTso`, and data field `name`.

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.NetworkingDefinitions.sock;
import me.bechberger.ebpf.runtime.NetworkingDefinitions.rate_sample;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code tcp_congestion_ops}. Implement on a
 * {@code @BPF} class to register a TCP congestion-control algorithm.
 * After {@code BPFProgram.load()}, the algorithm's {@link #name()} appears
 * in {@code /proc/sys/net/ipv4/tcp_available_congestion_control} and can
 * be selected system-wide via {@code sysctl}.
 *
 * <p>The kernel accepts NULL for optional callbacks; only override what
 * you implement. {@link #name()} is required and must be unique across
 * loaded CC algorithms.
 */
@StructOps("tcp_congestion_ops")
public interface TcpCongestionControl {

    default void init(Ptr<sock> sk)                 { }
    default void release(Ptr<sock> sk)              { }
    default @Unsigned int ssthresh(Ptr<sock> sk)    { return 0; }
    default void congAvoid(Ptr<sock> sk, @Unsigned int ack, @Unsigned int acked) { }
    default void setState(Ptr<sock> sk, @Unsigned int newState) { }
    default void cwndEvent(Ptr<sock> sk, @Unsigned int event) { }
    default @Unsigned int undoCwnd(Ptr<sock> sk)    { return 0; }
    default void pktsAcked(Ptr<sock> sk, Ptr<rate_sample> rs) { }
    default @Unsigned int minTso(Ptr<sock> sk)      { return 0; }

    /** Algorithm name. Registered as the identifier the kernel selects on. */
    default String name() { return "hello_cc"; }
}
```

- [ ] **Step 3: Verify it compiles**

Same command as Task 6 step 2. If missing bindings surface, add them in a preceding commit and re-run.

- [ ] **Step 4: Commit**

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/structops/TcpCongestionControl.java
# Include any new @Type stubs from Step 1:
git add bpf-runtime/src/main/java/me/bechberger/ebpf/runtime/NetworkingDefinitions.java
git commit -m "feat(structops): TcpCongestionControl marker interface"
```

---

### Task 8: `QdiscOps` marker interface

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/QdiscOps.java`

- [ ] **Step 1: Confirm `sk_buff` and `Qdisc` types**

Same procedure as Task 7 step 1. `sk_buff` almost certainly exists in `bpf-runtime`; `Qdisc` (aka `struct Qdisc`) may not. If missing, add an empty `@Type` stub in `NetworkingDefinitions.java`.

- [ ] **Step 2: Write the interface**

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.NetworkingDefinitions.sk_buff;
import me.bechberger.ebpf.runtime.NetworkingDefinitions.Qdisc;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code bpf_qdisc_ops}. Implement to register a
 * BPF-driven queueing discipline (qdisc) — used by the traffic-control
 * subsystem to queue and dequeue packets on a network interface.
 *
 * <p>{@link #enqueue(Ptr, Ptr)} returns an {@code __u32} kernel status
 * ({@code NET_XMIT_SUCCESS} = 0, {@code NET_XMIT_DROP} = 1, etc.).
 */
@StructOps("bpf_qdisc_ops")
public interface QdiscOps {

    default int  enqueue(Ptr<sk_buff> skb, Ptr<Qdisc> sch) { return 0; /* NET_XMIT_SUCCESS */ }
    default Ptr<sk_buff> dequeue(Ptr<Qdisc> sch)           { return null; }
    default int  init(Ptr<Qdisc> sch)                      { return 0; }
    default void reset(Ptr<Qdisc> sch)                     { }
    default void destroy(Ptr<Qdisc> sch)                   { }
}
```

- [ ] **Step 3: Verify + commit**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf -am compile 2>&1 | tail -15'
```

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/structops/QdiscOps.java
# plus any @Type stubs from Step 1
git commit -m "feat(structops): QdiscOps marker interface"
```

---

### Task 9: `HidBpfOps` marker interface

**Files:**
- Create: `bpf/src/main/java/me/bechberger/ebpf/bpf/structops/HidBpfOps.java`

- [ ] **Step 1: Look up HID context types**

`hid_bpf_ctx` is the callback context. Same pattern: grep bpf-runtime, add a stub if missing.

- [ ] **Step 2: Write the interface**

Kernel field set (from BTF 6.14+): `hid_device_event`, `hid_rdesc_fixup`, `hid_hw_request`, plus data fields `name` and `hid_id`. Verify against the generated `hid_bpf_ops.json` in Task 3 before writing — that JSON is authoritative for the field names.

```java
package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.hid_bpf_ctx;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code hid_bpf_ops}. Implement to intercept and
 * modify HID (Human Interface Device) reports before they reach userspace.
 *
 * <p>{@link #hidDeviceEvent(Ptr, int)} returns bytes of report modified,
 * or a negative errno on failure.
 */
@StructOps("hid_bpf_ops")
public interface HidBpfOps {

    default int hidDeviceEvent(Ptr<hid_bpf_ctx> ctx, int type)          { return 0; }
    default int hidRdescFixup(Ptr<hid_bpf_ctx> ctx)                     { return 0; }
    default int hidHwRequest(Ptr<hid_bpf_ctx> ctx, int reportnum,
                             int rtype, int reqtype)                    { return 0; }

    /** Program name (registered with the HID subsystem). */
    default String name()   { return "hello_hid"; }
    /** HID device identifier (0 = any). */
    default int   hidId()   { return 0; }
}
```

Adjust field names to match what `hid_bpf_ops.json` actually contains — the JSON wins.

- [ ] **Step 3: Verify + commit**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf -am compile 2>&1 | tail -15'
```

```bash
git add bpf/src/main/java/me/bechberger/ebpf/bpf/structops/HidBpfOps.java
# plus any @Type stubs from Step 1
git commit -m "feat(structops): HidBpfOps marker interface"
```

---

### Task 10: End-to-end compile check

**Files:** none (validation only)

- [ ] **Step 1: Full build**

```
rsync -avz --delete --exclude=.git --exclude=target ./ thinkstation:/home/i560383/code/experiments/hello-ebpf/
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl annotations,bpf-compiler-plugin,bpf -am install -DskipTests 2>&1 | tail -30'
```
Expected: BUILD SUCCESS across the three modules.

- [ ] **Step 2: Run the layout unit test one more time**

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  mvn -pl bpf-compiler-plugin -Dtest=StructOpsLayoutTest test 2>&1 | tail -20'
```
Expected: 4/4 tests pass.

- [ ] **Step 3: Confirm no in-tree behaviour changed**

Any existing test that was passing before this sub-plan should still pass. Sanity check with a scheduler smoke test that we know is stable:

```
ssh thinkstation 'cd /home/i560383/code/experiments/hello-ebpf && \
  PATH=/home/i560383/.local/bin:$PATH \
  HOME=/home/i560383 JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn \
  ./scripts/run-tests-vng.sh bpf-samples MinimalSchedulerSample 2>&1 | tail -25'
```
Expected: same pass/fail state as before this sub-plan.

- [ ] **Step 4: No commit** — this task is validation only.

---

## Verification

**All artifacts produced by this sub-plan:**

- `StructOpsLayout.java` loader + record → unit-tested against bundled JSONs.
- Four JSON files with kernel field lists → loader test spot-checks the sched_ext_ops and tcp_congestion_ops shapes.
- `@StructOps` annotation → compiles in `annotations`.
- Four marker interfaces (`SchedExtOps`, `TcpCongestionControl`, `QdiscOps`, `HidBpfOps`) → compile in `bpf`.
- Refresh script (`extract-struct-ops-layouts.py`) + README → documented.

**What this sub-plan does NOT do (intentionally deferred):**

- Plugin codegen change — the marker interfaces do not yet drive any C emission. That's Sub-plan B.
- Runtime attach — no `StructOpsAttach` yet. That's Sub-plan B.
- Scheduler migration — `Scheduler.java` still uses its bespoke inline emission. That's Sub-plan C.
- New consumers — no smoke tests for TcpCongestionControl/QdiscOps/HidBpfOps yet. That's Sub-plan D.

**Success criterion:** A `@BPF` class can `implements TcpCongestionControl` today, the code compiles, but *nothing changes in the generated .c* (because no plugin pass consumes the annotation yet). This is the pure-foundation gate.

## Out of scope (deferred to later sub-plans)

- Method-to-field validation diagnostics (Sub-plan B).
- The `BPF_PROG(...)` wrapper macro emission (Sub-plan B).
- `.struct_ops.link` struct instance emission (Sub-plan B).
- `bpf_map__attach_struct_ops` FFI wiring (Sub-plan B).
- Deleting `Scheduler.attachScheduler()` (Sub-plan C).
- `HelloCubicSample` and per-kind smoke tests (Sub-plan D).
