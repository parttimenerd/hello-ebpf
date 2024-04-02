package me.bechberger.ebpf.annotations.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotates a record for with a BPFStructType is generated
 * <p>
 * Currently only supported directly inside {@link BPF} annotated classes
 * <p>
 * Example:
 * {@snippet :
 *     record Event(@Unsigned int pid, @Size(256) String filename, @Size(16) String comm) {}
 * }
 * <p>
 * Members can be one of the following:
 * <ul>
 *     <li>integer types (int, long, ...), optionally annotated with {@link Unsigned} if unsigned</li>
 *     <li>String types, annotated with {@link Size} to specify the size</li>
 *     <li>Other {@link Type} annotated types</li>
 * </ul>
 */
@Target(ElementType.TYPE)
public @interface Type {

    /** Name of the generated BPFStructType, uses the type as default */
    String name() default "";

    /** Don't generate C code and insert it into the ebpf program string */
    boolean noCCodeGeneration() default false;
}