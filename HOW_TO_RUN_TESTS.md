# How to run hello-ebpf tests (for AI agents)

This repo runs **only on thinkstation** (Ubuntu 25.10, kernel 6.17). Edits
happen on the mac; builds and tests happen on thinkstation. Never try to
build or test on the local mac.

## TL;DR

```sh
# From the mac, repo root:
./scripts/sync.sh                                              # mac → thinkstation
./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh'       # all bpf classes
./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh HelloWorldTest'   # one
./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh HelloWorldTest ArrayMapTest'   # subset
```

`run-tests-vng.sh` boots one virtme-ng VM per test class (host kernel +
host rootfs CoW) and runs each class from the `bpf` module under root.
Aggregates surefire counts into a summary table; per-class logs land in
`/tmp/vng-test-logs/<ClassName>.log` on thinkstation (also reachable as
`.vng-test-logs/` in the repo via a symlink).

## Why per-class virtme-ng

Most of the bpf tests need root (CAP_SYS_ADMIN for `bpf(2)` —
`/proc/sys/kernel/unprivileged_bpf_disabled = 2` on thinkstation). The
host has no NOPASSWD sudoers entry. virtme-ng boots the host kernel as
root in qemu with the host rootfs as a copy-on-write snapshot, which gives:

- root inside the VM
- the host's `~/.m2`, `~/.sdkman`, JDK 25, mvn 3.8.7, and source tree
  available read-write but isolated (CoW means VM-side mutations don't
  poison the host)
- one VM per class so a stuck/leaky bpf program can't poison the next
  class

## Running a subset

The default class list is hard-coded in the script. Pass class names as
positional args to override:

```sh
./scripts/ts.sh --no-tty 'bash scripts/run-tests-vng.sh HelloWorldTest TypeProcessingTest'
```

Anything surefire's `-Dtest=` accepts also works (e.g. globs like
`Hello*` quoted), since the arg is forwarded to mvn unchanged.

## Running a single test method (no per-class wrapper)

```sh
./scripts/ts.sh --no-tty '
KERNEL=/boot/vmlinuz-6.17.0-35-generic
JAVA_HOME=/home/i560383/.sdkman/candidates/java/25-sapmchn
MVN=/home/i560383/.m2/wrapper/dists/apache-maven-3.8.7-bin/678cc9d4/apache-maven-3.8.7/bin/mvn
REPO=/home/i560383/code/experiments/hello-ebpf
inner="export HOME=/home/i560383 JAVA_HOME=$JAVA_HOME PATH=$JAVA_HOME/bin:\$PATH && cd $REPO && $MVN -ntp -pl bpf test -Dtest=HelloWorldTest#methodName -Dmaven.test.skip=false -DskipTests=false -Dmaven.repo.local=/home/i560383/.m2/repository"
vng --network user --run $KERNEL --user root --cwd $REPO -- "$inner" < /dev/null
'
```

## Required mvn flags (gotchas)

- `-Dmaven.test.skip=false -DskipTests=false` — parent pom hardcodes
  `<maven.test.skip>true</maven.test.skip>` at line 118; without this,
  surefire is skipped.
- `-Dmaven.repo.local=/home/i560383/.m2/repository` — inside vng,
  `$HOME` defaults to `/run/tmp/roothome`, so Maven's local repo path
  resolves wrong. Override explicitly. (We also export `HOME=/home/i560383`
  but `-Dmaven.repo.local` is the safety net.)
- `-pl bpf` — scope the reactor to the `bpf` module. The full reactor
  pulls in `bpf-samples` which has spring-boot transitive deps that are
  not always cached.
- `JAVA_HOME=.../25-sapmchn` (not `.../current`) — the sdkman `current`
  symlink may point at JDK 17. The bpf module needs JDK 22+. Pin the
  full path.
- `vng --network user` — required because mvn online-resolves missing
  POMs from Maven Central. With `--network none` the build fails on any
  artifact whose `_remote.repositories` marker is missing.
- `vng ... < /dev/null` — without this, the loop runs vng with stdin
  attached to the script's stdin, which gets eaten by qemu and breaks
  the next iteration.

## CoW gotcha — write logs to /tmp

vng overlays `/` with a CoW snapshot **for the duration of the VM**.
Any writes to the host filesystem under the rootfs (e.g. inside the
repo dir) **get rolled back when the VM exits — even writes the host
shell did before vng started, if the path is inside the overlay**.

`/tmp` is outside the overlay on this host, so the script writes logs
to `/tmp/vng-test-logs/` and symlinks `<repo>/.vng-test-logs` to it.

If you write your own vng wrapper, never put output anywhere inside
the repo or `$HOME` — use `/tmp`.

## Running everything not in `bpf`

The other modules (annotations, bpf-processor, bpf-compiler-plugin,
bpf-gen, shared) don't need root and run fine on the host directly:

```sh
./scripts/ts.sh ./mvnw -pl annotations,bpf-processor,bpf-compiler-plugin,bpf-gen,shared test
```

Only the bpf-module integration tests need vng.

## Inspecting results after a sweep

```sh
./scripts/ts.sh --no-tty 'ls -la /tmp/vng-test-logs/'
./scripts/ts.sh --no-tty 'tail -30 /tmp/vng-test-logs/HelloWorldTest.log'
```

Failure summary line in each log:
`[INFO] Tests run: N, Failures: F, Errors: E, Skipped: S`

The runner parses this and prints `run/fail/err/skip` per class plus a
TOTAL row at the end. `VM_OR_BUILD_FAILED` means the log is empty or
maven didn't reach a surefire summary line; tail the log to diagnose.

## When a class hangs

Kill the bash task and re-run with just the missing classes. Each VM
is independent — a hung VM only loses that class.
