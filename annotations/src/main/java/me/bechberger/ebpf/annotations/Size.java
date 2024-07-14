package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Size of an array
 */
@Target({ElementType.TYPE_USE, ElementType.TYPE})
@Repeatable(Sizes.class)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Size {
    int value();
}