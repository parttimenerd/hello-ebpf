package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Annotates a method that should always be inlined */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface AlwaysInline {
}
