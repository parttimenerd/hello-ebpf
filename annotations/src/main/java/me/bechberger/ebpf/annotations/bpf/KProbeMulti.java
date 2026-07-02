package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a {@code kprobe.multi} BPF program. Emits
 * {@code SEC("kprobe.multi/<glob>")} (or {@code kretprobe.multi/<glob>} when
 * {@link #retprobe()} is true). Attach is NOT automatic - call
 * {@code BPFProgram.attachKProbeMulti(prog, symbols, cookies, retprobe)} at
 * runtime with the resolved symbol list.
 *
 * <p>Requires kernel &ge; 5.18 and attach type {@code BPF_TRACE_KPROBE_MULTI}
 * (id 42).
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface KProbeMulti {
    /**
     * Optional glob pattern used only as the section-suffix label
     * (documentation for the ELF section). The actual symbol list is
     * passed to {@code attachKProbeMulti(...)} at runtime.
     * Defaults to {@code "*"}.
     */
    String value() default "*";

    /** {@code true} to emit {@code kretprobe.multi} (return probe). */
    boolean retprobe() default false;
}
