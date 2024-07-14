package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/** The current type is used here under a different name */
@Target({ElementType.TYPE, ElementType.TYPE_USE})
@Repeatable(OriginalNames.class)
@Retention(RetentionPolicy.RUNTIME)
public @interface OriginalName {
    /** The original name of the type here */
    String value();
}