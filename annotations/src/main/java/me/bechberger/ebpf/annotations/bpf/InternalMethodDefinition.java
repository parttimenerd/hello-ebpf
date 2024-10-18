package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Used by the compiler plugin for the code generated for implemented methods in interfaces
 * <p>
 * <b>Don't set it's value, use {@link BPFInterface#before()} for interfaces instead</b>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface InternalMethodDefinition {
    String value();
}
