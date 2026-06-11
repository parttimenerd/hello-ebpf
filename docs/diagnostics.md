# Compiler Plugin Diagnostics

This page documents every error the hello-ebpf compiler plugin can emit, with a minimum reproducer and fix for each.

When submitting a new diagnostic in a PR, add a corresponding entry here in the same commit.

---

## Unsupported return type

**Error**: `Unsupported return type: X as BPF does not support returning structs from functions`
or `Unsupported return type: X`

**Cause**: A `@BPFFunction` returns a type that cannot be represented in BPF. BPF functions may only return `int`, `long`, `void`, enum types, or `Ptr<T>`. Returning a struct by value is not supported.

**Reproducer**:
```java
@BPFFunction
record Pair(int a, int b) myHelper() {  // error: returning struct
    return new Pair(1, 2);
}
```

**Fix**: Return a `Ptr<Pair>` (pointer to a stack-allocated value), or write the result into a map/ring-buffer slot.

---

## Unsupported parameter type

**Error**: `Unsupported parameter type: X`

**Cause**: A `@BPFFunction` parameter has a type the plugin cannot lower to C. All parameters must be primitives (`int`, `long`, `boolean`, etc.), `Ptr<T>`, `@Type` record, `String` (as `char*`), or `char[]`.

**Fix**: Wrap complex types in `Ptr<T>` or flatten them into primitives.

---

## Unsupported binary operator

**Error**: `Unsupported binary operator DIVIDE: x / y`

**Cause**: BPF does not support certain operators (typically floating-point division, modulo on floats, or other ops the verifier rejects). The specific operator is named in the error.

**Fix**: Replace with integer arithmetic, or decompose into supported operations.

---

## Unsupported unary operator

**Error**: `Unsupported unary operator UNARY_PLUS: +x`

**Cause**: The unary operator has no BPF equivalent.

**Fix**: Remove the operator (for `+x`, just use `x`).

---

## Unsupported type cast

**Error**: `Unsupported type cast to X, use 'Ptr::cast' instead`
or `Unsupported type cast to X, use 'Ptr.<Type>cast(...)' instead`

**Cause**: Java-style casts on pointer types are not supported. Use `Ptr.cast()` instead.

**Reproducer**:
```java
Ptr<Long> p = ...;
Ptr<Integer> q = (Ptr<Integer>) p;  // error
```

**Fix**:
```java
Ptr<Integer> q = Ptr.cast(p);
// or
Ptr<Integer> q = p.<Integer>cast();
```

---

## Unsupported constructor call

**Error**: `Unsupported constructor call: new X(...)`

**Cause**: Only `@Type` record constructors and `BPFJ.charBuf(N)` are supported inside `@BPFFunction` bodies. `new String()` is a common mistake.

**Reproducer**:
```java
@Size(16) String comm = new String();  // error
```

**Fix**:
```java
@Size(16) char[] comm = BPFJ.charBuf(16);  // correct
// or
@Size(16) String comm = "";  // also accepted
```

---

## Unsupported method invocation (not a method symbol)

**Error**: `Unsupported method invocation (not a method symbol): x.y()`

**Cause**: The expression being called is not a concrete method — it may be a field reference, a class literal, or a synthetic expression the plugin can't resolve.

**Fix**: Ensure the call target is a concrete method annotated with `@BPFFunction` or `@BuiltinBPFFunction`.

---

## Unsupported method invocation

**Error**: `Unsupported method invocation: foo.bar()`

**Cause**: The called method has no BPF lowering. It's either a plain Java method (not `@BPFFunction`), an instance method on a non-BPF type, or a method the plugin doesn't know how to translate.

**Fix**:
- For user-defined helpers: annotate with `@BPFFunction`.
- For Java SDK methods: there is no BPF equivalent; restructure the logic using BPF-safe constructs.
- For libbpf helpers: check `BPFHelpers` and `BPFJ` for a provided wrapper.

---

## Lambdas only supported in built-in function calls

**Error**: `Lambdas are only supported in calls to built-in functions: ...`

**Cause**: A lambda expression appears in a position the plugin doesn't yet support — only lambdas passed directly to `@BuiltinBPFFunction` methods (like `bpf_for_each_map_elem`) are allowed.

**Fix**: Extract the lambda body into a `@BPFFunction` method, or wait for full lambda support (Phase D of the roadmap).

---

## Unsupported literal value

**Error**: `Unsupported literal value NaN`

**Cause**: NaN, Infinity, and non-representable float literals cannot be used in BPF.

**Fix**: Use integer arithmetic, or represent the special value as a sentinel integer constant.

---

## Array sizes must be integer constants

**Error**: `Array sizes have to be integer constants, not X`

**Cause**: The array dimension is a runtime expression, not a compile-time constant. BPF requires all array sizes to be known at compile time.

**Reproducer**:
```java
int n = 16;
char[] buf = new char[n];  // error: n is not a compile-time constant
```

**Fix**:
```java
@Size(16) char[] buf = BPFJ.charBuf(16);  // use @Size annotation
// or
static final int N = 16;
char[] buf = new char[N];  // N is a static final constant
```

---

## Method is not annotated with @BPFFunction

**Error**: `Method is not annotated with @BPFFunction`

**Cause**: A method in a `@BPF` class is being invoked from BPF code, but the method itself doesn't have `@BPFFunction`. The plugin won't translate it.

**Fix**: Add `@BPFFunction` to the method. If it's a helper that should always be inlined, add `@BPFFunction` alone (it defaults to `__always_inline`). To opt out of inlining: `@BPFFunction(inline = false)`.
