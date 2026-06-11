# Global Variables & Types

hello-ebpf provides a rich type system for sharing structured data between BPF programs and
Java. This page covers `GlobalVariable<T>`, `@Type` records, `@Size(N)`, and `@Unsigned`.

## GlobalVariable<T>

`GlobalVariable<T>` creates a BPF array map of size 1 that is mmap'd into user-space. Both the
BPF program and the Java side can read and write it with low overhead (no syscall on the read path).

### Declaration

```java
@BPF(license = "GPL")
public abstract class MyProg extends BPFProgram {

    // Primitive wrappers
    final GlobalVariable<Long>    counter  = new GlobalVariable<>(0L);
    final GlobalVariable<Integer> flags    = new GlobalVariable<>(0);
    final GlobalVariable<Boolean> enabled  = new GlobalVariable<>(true);

    // Struct (use @Type record — see below)
    final GlobalVariable<Config>  config   = new GlobalVariable<>(new Config(0, 0));
}
```

The initial value passed to the constructor is written into the map at load time.

### BPF-side access (inside `@BPFFunction`)

```java
@BPFFunction
public int xdpHandlePacket(Ptr<xdp_md> ctx) {
    if (!enabled.get()) return XDP_PASS;

    long c = counter.get();
    counter.set(c + 1);

    return XDP_PASS;
}
```

The compiler plugin translates `.get()` to a BPF map lookup dereference and `.set(v)` to
a map element write.

### Java-side access

```java
// Read
long c = prog.counter.get();

// Write
prog.counter.set(42L);

// Atomic operations (Java side only, via Unsafe)
prog.counter.incrementAndGet();
prog.counter.addAndGet(10L);
prog.counter.compareAndSet(42L, 0L);   // CAS
```

!!! note "Thread safety"
    Java-side reads and writes to `GlobalVariable` are not atomic by default because they go
    through mmap. Use `incrementAndGet()` / `compareAndSet()` for concurrent Java access.
    BPF-side atomics require explicit `__sync_fetch_and_add` (see Atomics section in helpers).

---

## @Type records

`@Type` records map directly to C structs. Use them as map values, ring buffer elements,
or `GlobalVariable` types.

```java
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;

@Type
record Event(
    int   pid,
    int   tgid,
    long  timestampNs,
    @Size(256) String filename,   // char filename[256]
    @Unsigned int returnCode      // u32 returnCode
) {}
```

The compiler plugin generates:
```c
struct Event {
    int   pid;
    int   tgid;
    __u64 timestampNs;
    char  filename[256];
    __u32 returnCode;
};
```

### Nested structs

```java
@Type
record IpPort(int addr, short port) {}

@Type
record Connection(IpPort src, IpPort dst, long bytes) {}
```

Generates nested C structs. The outer struct is padded according to C alignment rules
(which match Java `@Type` record layout).

### Creating instances in BPF code

```java
@BPFFunction
public void handleEvent(Ptr<some_ctx> ctx) {
    // Allocate on stack
    Event e = new Event();
    e.pid  = BPFJ.currentPid();
    e.tgid = BPFJ.currentTgid();
    // ... fill fields ...
    events.bpf_put_some_key(e);   // or ring buffer submit
}
```

---

## @Size(N) — fixed-length strings

Java `String` fields in `@Type` records must be annotated with `@Size(N)` to specify the
character array length. Without `@Size`, the compiler plugin will reject the type.

```java
@Type
record ProcessInfo(
    int pid,
    @Size(16) String comm,       // char comm[16] — fits TASK_COMM_LEN
    @Size(256) String cmdline    // char cmdline[256]
) {}
```

### Initialising string buffers in BPF code

Use `BPFJ.charBuf(N)` to create a zero-initialised stack buffer of exactly N bytes:

```java
@BPFFunction
public void captureComm() {
    // Stack-allocated char buf[16] = {}
    var buf = BPFJ.charBuf(16);
    BPFJ.getCurrentComm(buf);
    // buf now contains the current process name, null-terminated
}
```

---

## @Unsigned

Java integers are signed. Use `@Unsigned` to tell the compiler plugin to treat the value
as an unsigned type in generated C.

| Java annotation | C type |
|----------------|--------|
| `@Unsigned byte` | `__u8` |
| `@Unsigned short` | `__u16` |
| `@Unsigned int` | `__u32` |
| `@Unsigned long` | `__u64` |

```java
@Type
record PacketStats(
    @Unsigned long rxBytes,   // __u64
    @Unsigned long txBytes,   // __u64
    @Unsigned int  drops      // __u32
) {}
```

---

## Class-level constants

Compile-time constants on a `@BPF` class become `static const` in generated C:

```java
@BPF(license = "GPL")
public abstract class MyProg extends BPFProgram {

    // These become: static const int MAX_ENTRIES = 1024;
    //               static const int THRESHOLD = 100;
    static final int MAX_ENTRIES = 1024;
    static final int THRESHOLD   = 100;

    @BPFMapDefinition(maxEntries = MAX_ENTRIES)
    final BPFArray<Long> buckets = BPFArray.newInstance();

    @BPFFunction
    public void process(int value) {
        if (value > THRESHOLD) {
            // ...
        }
    }
}
```

Only `static final` fields with primitive types and compile-time constant expressions are
supported. Non-constant initialisers will cause a compiler plugin error.

---

## Padding and alignment

C structs may have implicit padding between fields for alignment. The `@Type` annotation
generates structs that match the standard C ABI (same as what GCC/clang would produce).
When sharing structs across the Java/BPF boundary, field order matters:

- Place 8-byte fields (`long`, `__u64`) first
- Then 4-byte fields (`int`, `__u32`)
- Then 2-byte fields (`short`)
- Then 1-byte fields (`byte`, `char`)
- String arrays (`@Size(N) String`) count as N bytes

This avoids padding holes and ensures the Java and C representations match without manual
`__attribute__((packed))` annotations.
