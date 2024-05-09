package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * (Implicitely) used when defining arrays of sized types
 */
@Target({ElementType.TYPE_USE, ElementType.TYPE})
@Retention(RetentionPolicy.CLASS)
public @interface Sizes {
    Size[] value();
}
