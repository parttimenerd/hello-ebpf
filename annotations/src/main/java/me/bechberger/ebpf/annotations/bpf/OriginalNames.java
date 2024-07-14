package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
public @interface OriginalNames {
    OriginalName[] value();
}