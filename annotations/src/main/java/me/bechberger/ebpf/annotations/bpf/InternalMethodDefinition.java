package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Used by the compiler plugin for the code generated for implemented methods in interfaces
 * <p>
 * <b>Don't set it's value, use {@link BPFInterface#before()} for interfaces instead</b>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface InternalMethodDefinition {
    String value();

    /**
     * Names of the {@code @InArena} arena fields this method's body transitively
     * dereferences (e.g. {@code idleMask}).
     * <p>
     * Persisted at base-compile time so that a cross-module {@code @BPF} subclass which
     * inherits this method as a raw-C body (via {@link #value()}) can re-inject the
     * per-arena association call {@code bpf_arena_associate_<N>();} and re-emit the
     * corresponding helper. Empty for methods that reach no arena (or non-{@code struct_ops}
     * helpers). Only inherited {@code struct_ops} entries with a non-empty set are acted on.
     */
    String[] arenas() default {};
}
