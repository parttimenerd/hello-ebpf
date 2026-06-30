package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Marker for kfunc parameter declarations that require a trusted pointer.
 * When this annotation is present on a parameter, {@code Ptr.directVal()}
 * may be used in the argument expression without raising a plugin diagnostic,
 * even if the result is not immediately followed by a field access.
 *
 * <p>This is purely documentary metadata; the BPF runtime does not see this
 * annotation. The compiler plugin reads it during structural validation of
 * {@code directVal()} call sites.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.SOURCE)
public @interface TrustedPtr {
}
