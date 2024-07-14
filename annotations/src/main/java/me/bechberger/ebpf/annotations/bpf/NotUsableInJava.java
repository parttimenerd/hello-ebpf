package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/** Annotates everything that should not be used in Java */
@Target({ElementType.METHOD, ElementType.TYPE, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface NotUsableInJava {
}