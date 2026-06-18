package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a uretprobe (user-space return probe) BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(section = "uretprobe/<path>:<symbol>", autoAttach = true)
 * }</pre>
 *
 * <p>The {@link #path} is the path to the binary or shared library and
 * {@link #symbol} is the function symbol name (or use {@link #offset} for a raw offset).
 *
 * <p>Example:
 * <pre>{@code
 * @Uretprobe(path = "/usr/lib/libc.so.6", symbol = "malloc")
 * int traceMallocRet(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Uretprobe {
    /** Path to the binary or shared library. */
    String path();

    /** Symbol name to probe (mutually exclusive with {@link #offset}). */
    String symbol() default "";

    /** Raw byte offset within the binary (used when {@link #symbol} is empty). */
    long offset() default 0L;
}
