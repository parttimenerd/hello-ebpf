package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a tracepoint BPF program that is automatically attached.
 *
 * <p>Equivalent to:
 * <pre>{@code
 * @BPFFunction(
 *     headerTemplate = "int $name($params)",
 *     section = "tp/<category>/<name>",
 *     autoAttach = true
 * )
 * }</pre>
 *
 * <p>Example:
 * <pre>{@code
 * @Tracepoint(category = "syscalls", name = "sys_enter_openat")
 * int onOpenAt(Ptr<OpenAt2Ctx> ctx) { ... }
 * }</pre>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Tracepoint {
    /** Tracepoint category (e.g. {@code "syscalls"}). */
    String category();

    /** Tracepoint name (e.g. {@code "sys_enter_openat"}). */
    String name();
}
