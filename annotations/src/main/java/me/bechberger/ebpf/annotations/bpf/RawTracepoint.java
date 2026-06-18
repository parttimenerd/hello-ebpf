package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a raw_tracepoint BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(
 *     headerTemplate = "int BPF_PROG($name, $params)",
 *     lastStatement = "return 0;",
 *     section = "raw_tracepoint/<name>",
 *     autoAttach = true
 * )
 * }</pre>
 *
 * <p>Example:
 * <pre>{@code
 * @RawTracepoint("sys_enter")
 * void syscallEnter(Ptr<PtDefinitions.pt_regs> regs, @Unsigned long syscallNr) { ... }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RawTracepoint {
    /** Tracepoint name (e.g. {@code "sys_enter"}). */
    String value();
}
