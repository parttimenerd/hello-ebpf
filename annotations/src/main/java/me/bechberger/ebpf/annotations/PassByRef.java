package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Opt out of {@code PtrCoercionInference}'s automatic {@code TAKE_ADDRESS} / {@code DEREFERENCE}
 * insertion at this parameter. The Translator will pass the argument unchanged.
 *
 * <p>Used at sites where the caller really does mean to pass the literal value (e.g. atomics
 * whose semantics depend on identity) rather than letting the compiler insert {@code &} / {@code *}.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface PassByRef {
}
