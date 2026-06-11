package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for an fexit BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(section = "fexit/<symbol>", autoAttach = true)
 * }</pre>
 *
 * <p>Requires BTF support in the kernel.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Fexit {
    /** Kernel function to attach to. */
    String value();
}
