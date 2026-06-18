package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a uprobe (user-space probe) BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(section = "uprobe/<path>:<offset>", autoAttach = true)
 * }</pre>
 *
 * <p>The {@link #path} is the path to the binary or shared library, and
 * {@link #symbol} is the function symbol name to probe (alternatively, use
 * {@link #offset} for a raw offset instead of a symbol). The method return
 * type should be {@code int} and the first parameter should be
 * {@code Ptr<PtDefinitions.pt_regs>}.
 *
 * <p>Example:
 * <pre>{@code
 * @Uprobe(path = "/usr/lib/libc.so.6", symbol = "malloc")
 * int traceMalloc(Ptr<PtDefinitions.pt_regs> ctx) {
 *     ...
 *     return 0;
 * }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Uprobe {
    /** Path to the binary or shared library. */
    String path();

    /** Symbol name to probe (mutually exclusive with {@link #offset}). */
    String symbol() default "";

    /** Raw byte offset within the binary (used when {@link #symbol} is empty). */
    long offset() default 0L;
}
