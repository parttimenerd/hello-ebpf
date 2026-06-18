package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a BPF helper method for forced inlining ({@code __always_inline}).
 * Equivalent to {@link me.bechberger.ebpf.annotations.AlwaysInline}; prefer
 * this annotation when importing from the {@code bpf} annotation package.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface BPFInline {
}
