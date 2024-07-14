package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Offset in bytes for a field in a struct, from the start of the struct
 */
@Target({ElementType.TYPE, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Offset {
    /**
     * Offset in bytes
     */
    int value();
}