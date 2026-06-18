package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a kretprobe BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(section = "kretprobe/<symbol>", autoAttach = true)
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Kretprobe {
    /** Kernel symbol to attach to. */
    String value();
}
