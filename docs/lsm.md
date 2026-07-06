# LSM & Cgroup Hooks

**Blog series:** [Part 20 — BPF LSM security hooks](https://mostlynerdless.de/blog/2025/01/27/helle-ebpf-writing-an-lsm-policy-in-pure-java-20/)  
**Javadoc:** [`LSMHook`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/LSMHook.html) · [`CGroupHook`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/CGroupHook.html)  
**Source:** [`LSMHook.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/LSMHook.java) · [`CGroupHook.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/CGroupHook.java)  
**See also:** [TC Hook](tc.md) · [XDP Hook](xdp.md) · [BPF Maps](maps.md)

![eBPF hooks across the full Linux kernel: XDP, TC, socket, tracepoints, kprobes, LSM](https://files.speakerdeck.com/presentations/6e75aaa3377e4650b6108f49a9241249/preview_slide_32.jpg)

## BPF LSM

BPF LSM (Linux Security Module) lets you attach BPF programs to the same hook points as
traditional LSM modules like SELinux and AppArmor. This gives you fine-grained, programmable
security policies without recompiling the kernel.

### Prerequisites

- `CONFIG_BPF_LSM=y` in kernel config
- `lsm=bpf` in kernel boot parameters (or `lsm=...,bpf` appended to existing list)

Verify:
```bash
cat /sys/kernel/security/lsm          # should include "bpf"
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
```

### Implementing LSMHook

```java
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.LSMHook;
import me.bechberger.ebpf.type.Ptr;
import static me.bechberger.ebpf.bpf.raw.Lib_1.*;

@BPF(license = "GPL")
public abstract class FileOpenRestrict extends BPFProgram implements LSMHook {

    /** PIDs to block (set from Java). */
    @BPFMapDefinition(maxEntries = 256)
    final BPFHashMap<Integer, Integer> blockedPids = BPFHashMap.newInstance();

    @Override
    @BPFFunction
    public int onFileOpen(Ptr<file> file) {
        int pid = BPFJ.currentPid();
        if (blockedPids.bpf_get(pid) != null) {
            return -EACCES;   // deny
        }
        return 0;             // allow
    }
}
```

### Available LSM hooks

LSM hooks correspond to the `security_*` functions in the kernel. Common ones:

| Method | Fires when |
|--------|-----------|
| `onFileOpen(Ptr<file>)` | A process opens a file |
| `onFilePermission(Ptr<file>, int mask)` | A file permission check (read/write/exec) |
| `onBpf(int cmd, Ptr<?> attr, int size)` | A process calls the `bpf()` syscall |
| `onBprmCheckSecurity(Ptr<linux_binprm>)` | A process calls execve |
| `onSocketCreate(int family, int type, int protocol, int kern)` | A process creates a socket |
| `onSocketConnect(Ptr<socket>, Ptr<sockaddr>, int)` | A socket connects |

Return `0` to allow, a negative errno to deny (e.g. `-EACCES`, `-EPERM`).
Standard errno constants are available via `import static me.bechberger.ebpf.bpf.raw.Lib_1.*`.

### Attaching

```java
public static void main(String[] args) throws Exception {
    try (FileOpenRestrict prog = BPFProgram.load(FileOpenRestrict.class)) {
        prog.autoAttachPrograms();

        // Block PID 12345
        prog.blockedPids.put(12345, 1);

        System.out.println("LSM active. Ctrl-C to stop.");
        Thread.currentThread().join();
    }
}
```

!!! warning "CAP_MAC_ADMIN required"
    Loading BPF LSM programs requires `CAP_MAC_ADMIN` in addition to `CAP_BPF`. Run as root
    or grant the capability explicitly.

---

## Cgroup Hooks

Cgroup BPF programs attach to cgroup v2 hierarchies and filter traffic for all processes in
a cgroup. They are useful for per-container network policies.

### Implementing CGroupHook

```java
@BPF(license = "GPL")
public abstract class CGroupFilter extends BPFProgram implements CGroupHook {

    @BPFMapDefinition(maxEntries = 1024)
    final BPFHashMap<Integer, Long> byteCount = BPFHashMap.newInstance();

    @Override
    @BPFFunction
    public CGroupAction cgroupHandleIngress(Ptr<__sk_buff> skb) {
        int mark = skb.val().mark;
        Ptr<Long> c = byteCount.bpf_get(mark);
        if (c != null) {
            c.set(c.val() + skb.val().len);
        } else {
            long len = skb.val().len;
            byteCount.bpf_put(mark, len);
        }
        return CGroupAction.PASS;
    }

    @Override
    @BPFFunction
    public CGroupAction cgroupHandleEgress(Ptr<__sk_buff> skb) {
        return CGroupAction.PASS;
    }
}
```

The context type is `__sk_buff` (same as TC). Return `CGroupAction.PASS` to allow or
`CGroupAction.DROP` to drop.


### Attaching to a cgroup

```java
public static void main(String[] args) throws Exception {
    try (CGroupFilter prog = BPFProgram.load(CGroupFilter.class)) {
        // Attach to root cgroup (affects all processes)
        prog.cgroupAttachIngress("/sys/fs/cgroup");
        prog.cgroupAttachEgress("/sys/fs/cgroup");

        // Or a specific cgroup
        prog.cgroupAttachIngress("/sys/fs/cgroup/mycontainer");

        System.out.println("Cgroup hook active.");
        Thread.currentThread().join();
    }
}
```

!!! note "Cgroup v2 required"
    Cgroup BPF hooks require cgroup v2 (unified hierarchy). Check with:
    ```bash
    mount | grep cgroup2
    ```

### Available cgroup hook types

| Method | BPF attach type | Description |
|--------|----------------|-------------|
| `cgroupHandleIngress` | `BPF_CGROUP_INET_INGRESS` | Incoming packets for cgroup sockets |
| `cgroupHandleEgress` | `BPF_CGROUP_INET_EGRESS` | Outgoing packets from cgroup sockets |
| `cgroupSockCreate` | `BPF_CGROUP_INET_SOCK_CREATE` | Socket creation |
| `cgroupSockRelease` | `BPF_CGROUP_INET_SOCK_RELEASE` | Socket close |
| `cgroupConnect4` | `BPF_CGROUP_INET4_CONNECT` | IPv4 connect() |
| `cgroupConnect6` | `BPF_CGROUP_INET6_CONNECT` | IPv6 connect() |

---

## Examples

- [`LSMDemo.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/LSMDemo.java) — BPF LSM hook demo
- [`CGroupBlockHTTPEgress.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/CGroupBlockHTTPEgress.java) — cgroup egress filter

---

## Further reading

- [BPF LSM program type — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/)
- [Cgroup BPF programs — docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SKB/)
- [TC Hook](tc.md) · [XDP Hook](xdp.md)
