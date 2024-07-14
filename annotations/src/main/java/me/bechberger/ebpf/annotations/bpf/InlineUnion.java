package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to specify that a struct member is part of an inline union
 * <p>
 * Members for a specific union have to directly follow each other in the struct.
 * <p>
 * Be aware that it's not fully supported to write to a union member in non C-code
 * <p>
 * Example: {@snippet :
 *     @Type
 *     class Event extends Struct {
 *        @Unsigned int pid;
 *        @InlineUnion(1) UINT128 ipv6;
 *        @InlineUnion(1) UINT128 ipv4;
 *     }
 *}
 */
@Target({ElementType.FIELD, ElementType.TYPE_USE, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface InlineUnion {
    /** Identifier of the inlined union */
    int value();
}