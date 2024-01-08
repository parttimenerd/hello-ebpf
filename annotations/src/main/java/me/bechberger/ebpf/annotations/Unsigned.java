package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an integer type as unsigned
 */
@Target({ElementType.TYPE_USE, ElementType.TYPE})
@Retention(RetentionPolicy.CLASS)
public @interface Unsigned {
}
