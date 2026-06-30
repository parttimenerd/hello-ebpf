package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Escape hatch for {@code Ptr.directVal()}. Annotate a local variable
 * declaration or an enclosing {@code @BPFFunction}-annotated method to
 * silence the plugin's structural check that {@code directVal()} must be
 * followed by a field access.
 */
@Target({ElementType.LOCAL_VARIABLE, ElementType.METHOD})
@Retention(RetentionPolicy.SOURCE)
public @interface AllowDirectVal {
}
