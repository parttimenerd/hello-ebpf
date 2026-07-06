# Install & Prerequisites

## 1. Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Linux kernel | 6.14 |
| clang / llvm | 19 |
| libbpf-dev | 1.0 |
| bpftool | optional (debugging) |
| JDK | 22 |
| Privileges | root or CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN |

The framework requires kernel 6.14. Most distro kernels ship with `CONFIG_BPF=y` and
`CONFIG_BPF_SYSCALL=y`; verify with:

```bash
grep CONFIG_BPF /boot/config-$(uname -r)
```

Install native dependencies on Debian/Ubuntu:

```bash
sudo apt install -y clang-19 llvm-19 libbpf-dev bpftool \
    linux-headers-$(uname -r) linux-tools-$(uname -r)
```

!!! warning "macOS"
    eBPF programs run in the Linux kernel. Build and run on Linux only.
    Use the Lima VM workflow described in `hello-ebpf.yaml` for Mac hosts.

## 2. Quick start with the archetype

The `bpf-archetype` generates a ready-to-build project skeleton:

```bash
mvn archetype:generate \
  -DarchetypeGroupId=me.bechberger \
  -DarchetypeArtifactId=hello-ebpf-archetype \
  -DarchetypeVersion=0.1.4 \
  -DgroupId=com.example \
  -DartifactId=my-bpf-app \
  -Dversion=1.0-SNAPSHOT \
  -DinteractiveMode=false
```

Build and run:

```bash
cd my-bpf-app
mvn package
sudo java --enable-native-access=ALL-UNNAMED -cp target/my-bpf-app.jar com.example.App
```

The archetype's generated `pom.xml` includes the `bpf` dependency, the
annotation processor, and the `BPFCompilerPlugin` compiler arg — no further
configuration is needed.

## 3. Manual setup

To add hello-ebpf to an existing Maven project, declare the runtime dependency:

```xml
<dependency>
  <groupId>me.bechberger</groupId>
  <artifactId>bpf</artifactId>
  <version>0.1.4</version>
</dependency>
```

The annotation processor and compiler plugin must both be wired into
`maven-compiler-plugin`:

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-compiler-plugin</artifactId>
  <version>3.8.0</version>
  <configuration>
    <annotationProcessors>
      <annotationProcessor>me.bechberger.ebpf.bpf.processor.Processor</annotationProcessor>
    </annotationProcessors>
    <compilerArgs>
      <arg>-Xplugin:BPFCompilerPlugin</arg>
    </compilerArgs>
  </configuration>
</plugin>
```

## 4. Verify the setup

Run `mvn package`. A successful build writes a `.bpf.c` file under
`target/generated-sources/annotations/`. Its presence confirms the plugin ran:

```bash
find target/generated-sources -name "*.bpf.c"
```

If the file is absent, check that both `annotationProcessor` and
`-Xplugin:BPFCompilerPlugin` are present in the compiler configuration and
that the `bpf` jar (which bundles the plugin classes) is on the compile
classpath.

---

## Further reading

- [Your First BPF Program](hello.md) — write and run your first eBPF program in Java
- [How the Plugin Works](how-it-works.md) — the full build pipeline explained
- [Feature Matrix](../feature-matrix.md) — minimum kernel versions per feature

---

*Next: [Your First BPF Program](hello.md)*
