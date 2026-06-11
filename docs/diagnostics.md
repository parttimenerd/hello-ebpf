# Diagnostics — Compiler Plugin Errors

This page documents every error the hello-ebpf javac compiler plugin can emit, what causes
each one, and how to fix it.

All errors are emitted at compile time (during `javac` / `mvn compile`). They refer to
specific lines in your `@BPFFunction` methods.

---

## Unsupported return type

**Error prefix:** `Unsupported return type`

**Cause:** A `@BPFFunction` method declares a return type that the compiler plugin cannot
translate to a C type. Only primitive types (`int`, `long`, `void`) and `Ptr<T>` of a
supported type are allowed as return types of BPF functions.

**Minimum reproducer:**
```java
@BPFFunction
public String unsupported() {   // String without @Size is not supported
    return "hello";
}
```

**Fix:** Use a supported return type. Return `Ptr<Byte>` for string-like returns, or use
a `@Type` record wrapped in `Ptr<T>`.

---

## Unsupported parameter type

**Error prefix:** `Unsupported parameter type`

**Cause:** A `@BPFFunction` method has a parameter whose type cannot be translated.
Supported parameter types are: primitives, `Ptr<T>` where T is a known struct/primitive, and
`@Type` record types.

**Minimum reproducer:**
```java
@BPFFunction
public int process(Object obj) {   // Object is not a BPF type
    return 0;
}
```

**Fix:** Replace `Object` with a concrete `@Type` record type or a `Ptr<T>`.

---

## Unsupported binary operator

**Error prefix:** `Unsupported binary operator`

**Cause:** A binary expression inside a `@BPFFunction` uses an operator that has no
direct C equivalent or that the translator has not yet implemented.

**Minimum reproducer:**
```java
@BPFFunction
public int process(int a, int b) {
    // >>> is unsigned right shift — use >> and cast to @Unsigned instead
    return a >>> b;
}
```

**Fix:** Rewrite using supported operators. For unsigned right shift, use `@Unsigned int`
parameters and plain `>>`.

---

## Unsupported unary operator

**Error prefix:** `Unsupported unary operator`

**Cause:** A unary expression uses an operator that cannot be translated (e.g., prefix/postfix
`++`/`--` on a dereferenced pointer field).

**Fix:** Rewrite as an explicit assignment:
```java
// Instead of:
p.val().counter++;
// Use:
Ptr.of(p.val().counter).set(p.val().counter + 1);
```

---

## Unsupported type cast

**Error prefix:** `Unsupported type cast`

**Cause:** A Java cast expression `(T) expr` was used inside a `@BPFFunction`. Java casts
between pointer types are not directly translatable. Use `Ptr.cast()` instead.

**Minimum reproducer:**
```java
@BPFFunction
public int process(Ptr<xdp_md> ctx) {
    Ptr<ethhdr> eth = (Ptr<ethhdr>) ctx;  // ERROR — use Ptr.cast()
    return XDP_PASS;
}
```

**Fix:**
```java
Ptr<ethhdr> eth = Ptr.cast(Ptr.of(ctx.val().data));
```

---

## Unsupported constructor call — only @Type records and BPFJ.charBuf()

**Error prefix:** `Unsupported constructor call`

**Cause:** A `new X()` expression inside a `@BPFFunction` used a class that is neither a
`@Type` record nor the result of `BPFJ.charBuf()`.

**Minimum reproducer:**
```java
@BPFFunction
public int process() {
    ArrayList<Integer> list = new ArrayList<>();  // ERROR
    return 0;
}
```

**Fix:** Only allocate `@Type` records (stack-allocated structs) or use `BPFJ.charBuf(N)`
for character buffers. BPF programs cannot use the Java heap.

---

## Unsupported method invocation — not a method symbol

**Error prefix:** `Unsupported method invocation (not a method symbol)`

**Cause:** The compiler plugin encountered a method call expression where the method could
not be resolved to a concrete symbol. This can happen with lambda-captured methods or calls
through interfaces that are not BPF-aware.

**Fix:** Ensure the method is either:
- Another `@BPFFunction` on the same `@BPF` class, or
- A known BPF helper in `BPFJ`, or
- A map operation (`bpf_get`, `bpf_put`, etc.)

---

## Unsupported method invocation — no BPF lowering

**Error prefix:** `Unsupported method invocation (no BPF lowering)`

**Cause:** The method exists and is resolvable, but the compiler plugin has no rule to
translate it to C. This covers most standard Java library methods.

**Minimum reproducer:**
```java
@BPFFunction
public int process(int x) {
    return Math.abs(x);   // Math.abs has no BPF lowering
}
```

**Fix:** Rewrite using primitive operations or a BPFJ helper:
```java
return x < 0 ? -x : x;
```

---

## Lambdas only supported in calls to built-in functions

**Error prefix:** `Lambdas only supported in calls to built-in functions`

**Cause:** A lambda expression was used somewhere other than an argument to a BPFJ built-in
(like `BPFJ.bpf_loop`). General lambda usage is not supported inside `@BPFFunction` methods
because BPF programs do not have a heap or closures.

**Minimum reproducer:**
```java
@BPFFunction
public int process() {
    Runnable r = () -> {};   // ERROR
    return 0;
}
```

**Fix:** Extract the lambda body into a dedicated `@BPFFunction` method.

---

## Unsupported literal value

**Error prefix:** `Unsupported literal value`

**Cause:** A literal of an unsupported type was used (e.g., a `double` or `float` literal
inside a `@BPFFunction`). BPF programs do not support floating-point arithmetic on most
hooks.

**Fix:** Use integer arithmetic. If you need fixed-point math, scale by a power of 10 or 2.

---

## Array sizes have to be integer constants

**Error prefix:** `Array sizes have to be integer constants`

**Cause:** An array declaration inside a `@BPFFunction` used a non-constant size expression.
BPF programs require all stack array sizes to be compile-time constants for the verifier.

**Minimum reproducer:**
```java
@BPFFunction
public int process(int n) {
    var buf = BPFJ.charBuf(n);   // ERROR — n is not a constant
    return 0;
}
```

**Fix:** Use a constant:
```java
static final int BUF_SIZE = 256;

@BPFFunction
public int process(int n) {
    var buf = BPFJ.charBuf(BUF_SIZE);   // OK
    return 0;
}
```

---

## Method is not annotated with @BPFFunction

**Error prefix:** `Method is not annotated with @BPFFunction`

**Cause:** A `@BPFFunction` method called another method on the same class that is not also
annotated with `@BPFFunction`. Only methods that have been compiled to BPF can be called
from BPF.

**Minimum reproducer:**
```java
private int helper(int x) {   // Missing @BPFFunction
    return x + 1;
}

@BPFFunction
public int process(int x) {
    return helper(x);   // ERROR
}
```

**Fix:** Add `@BPFFunction` to `helper`:
```java
@BPFFunction
private int helper(int x) {
    return x + 1;
}
```

---

## General troubleshooting

1. **Enable dumpC** to see the generated C code:
   ```xml
   <!-- In pom.xml compiler plugin config -->
   <compilerArg>-AdumpC=true</compilerArg>
   ```
   Or pass `-AdumpC=true` to javac directly.

2. **Check clang errors** — the compiler plugin prints clang's stderr when compilation fails.
   These are often more informative than the plugin's own errors.

3. **Verify BTF** is available if using fentry/fexit:
   ```bash
   ls -la /sys/kernel/btf/vmlinux
   ```

4. **Check the verifier log** at runtime if the program loads but behaves incorrectly:
   ```java
   BPFProgram.load(MyProg.class, BPFProgram.LoadOptions.withVerifierLog());
   ```
