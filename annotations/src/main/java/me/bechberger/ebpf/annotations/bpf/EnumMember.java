package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to specify the value of an enum member
 * <p>
 * Example: {@snippet :
 *     @Type
 *     enum Kind implements Enum<Kind> {
 *         A, @EnumMember(value = 23, name = "KIND_A") B, C, D
 *     }
 * }
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface EnumMember {
    int value() default -1;

    String name() default "";
}
