package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Target;

@Target({ElementType.TYPE, ElementType.TYPE_USE})
public @interface OriginalNames {
    OriginalName[] value();
}