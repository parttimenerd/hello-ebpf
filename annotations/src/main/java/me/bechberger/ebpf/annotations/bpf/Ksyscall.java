package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a ksyscall BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(section = "ksyscall/<syscall>", autoAttach = true)
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Ksyscall {
    /** Syscall name without architecture prefix (e.g. {@code "openat"}). */
    String value();
}
