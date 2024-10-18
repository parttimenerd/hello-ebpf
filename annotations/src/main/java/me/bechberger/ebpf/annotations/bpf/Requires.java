package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target(ElementType.TYPE)
@Retention(RUNTIME)
@Documented
/**
 * The required kernel features, if one of these isn't available the program will neither be loaded
 * <b>nor compiled</b>
 */
public @interface Requires {

    /** Require sched-ext support in the kernel */
    boolean sched_ext() default false;
}
