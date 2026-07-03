package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Shorthand for a {@code uprobe.multi} BPF program. Emits
 * {@code SEC("uprobe.multi/<glob>")} (or {@code uretprobe.multi/<glob>} when
 * {@link #retprobe()} is true). Attach is NOT automatic - call
 * {@code BPFProgram.attachUprobeMulti(prog, binaryPath, funcs, cookies, retprobe)}
 * at runtime.
 *
 * <p>Requires kernel &ge; 6.6 and attach type {@code BPF_TRACE_UPROBE_MULTI}
 * (id 48).
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface UProbeMulti {
    /** Section-suffix glob label (documentation only). Defaults to {@code "*"}. */
    String value() default "*";

    /** {@code true} to emit {@code uretprobe.multi} (return probe). */
    boolean retprobe() default false;
}
