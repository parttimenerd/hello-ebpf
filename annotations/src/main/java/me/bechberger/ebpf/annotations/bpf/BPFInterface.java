package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Annotates an interface that a BPF program can implement.
 * <p>
 * This annotation also allows to specify code that should be added before and after the generated eBPF program.:
 * <verb>
 * #include ...
 * $before
 * ...
 * $after
 * </verb>
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFInterface {

    String before() default "";

    String after() default "";
}
