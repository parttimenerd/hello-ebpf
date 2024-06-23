package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Target;

/** The current type is used here under a different name */
@Target({ElementType.TYPE, ElementType.TYPE_USE})
@Repeatable(OriginalNames.class)
public @interface OriginalName {
    /** The original name of the type here */
    String value();
}
