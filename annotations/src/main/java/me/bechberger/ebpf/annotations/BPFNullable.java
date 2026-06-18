package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a BPF-context return value as potentially null (e.g. a map lookup that misses).
 *
 * <p>The BPF compiler plugin uses this annotation to enforce that callers guard against
 * null before dereferencing the returned pointer. Dereferencing a {@code @BPFNullable}
 * value without a preceding {@code if (x != null)} check is a compile error.
 *
 * <p>This annotation is meaningful only on methods annotated with {@link bpf.BuiltinBPFFunction}
 * or {@link bpf.BPFFunctionAlternative} — i.e., methods that execute inside the BPF VM.
 * Java-side callers are unaffected.
 */
@Target({ElementType.METHOD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface BPFNullable {
}
