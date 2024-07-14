package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Marks an integer type as unsigned
 */
@Target({ElementType.TYPE_USE, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Unsigned {
}