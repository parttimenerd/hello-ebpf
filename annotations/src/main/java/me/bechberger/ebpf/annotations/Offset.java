package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Offset in bytes for a field in a struct, from the start of the struct
 */
@Target({ElementType.TYPE, ElementType.TYPE_USE})
@Retention(RetentionPolicy.CLASS)
public @interface Offset {
    /**
     * Offset in bytes
     */
    int value();
}
