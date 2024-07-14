package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * (Implicitely) used when defining arrays of sized types
 */
@Target({ElementType.TYPE_USE, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Sizes {
    Size[] value();
}