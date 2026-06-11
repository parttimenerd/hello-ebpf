package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a kprobe BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(section = "kprobe/<symbol>", autoAttach = true)
 * }</pre>
 *
 * <p>The method return type should be {@code int} and the first parameter
 * should be {@code Ptr<PtDefinitions.pt_regs>} (or another context type).
 *
 * <p>Example:
 * <pre>{@code
 * @Kprobe("do_sys_openat2")
 * int countOpenAt(Ptr<PtDefinitions.pt_regs> ctx) {
 *     ...
 *     return 0;
 * }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Kprobe {
    /** Kernel symbol to attach to. */
    String value();
}
