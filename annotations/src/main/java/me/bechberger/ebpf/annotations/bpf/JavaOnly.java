package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks a {@code static final} field in a {@link BPF} program class as
 * Java-only, preventing the annotation processor from emitting a
 * corresponding {@code #define} in the generated C source.
 *
 * <p>Without this annotation every {@code static final} primitive or
 * {@code String} constant is mirrored as a C {@code #define} so that BPF
 * helper code can reference it by name.  Constants that are only used on
 * the Java side (e.g. syscall numbers, buffer sizes for Panama FFI calls,
 * HTML template strings) should be annotated with {@code @JavaOnly} to
 * keep the generated C file clean.
 *
 * <pre>{@code
 * @JavaOnly
 * private static final long __NR_perf_event_open = 298L;
 * }</pre>
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.SOURCE)
@Documented
public @interface JavaOnly {
}
