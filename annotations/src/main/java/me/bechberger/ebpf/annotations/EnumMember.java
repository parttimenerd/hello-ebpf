package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Annotation to specify the value of an enum member
 * <p>
 * Example: {@snippet :
 *     import me.bechberger.ebpf.annotations.Type;@Type
 *     enum Kind implements Enum<Kind> {
 *         A, @EnumMember(value = 23, name = "KIND_A") B, C, D
 *     }
 *}
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EnumMember {
    long value() default -1;

    String name() default "";
}