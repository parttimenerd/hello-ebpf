package me.bechberger.ebpf.annotations.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotates a record for with a struct or union type is generated
 * <p>
 * Example:
 * {@snippet :
 *     // struct
 *     @Type
 *     record Event(@Unsigned int pid, @Size(256) String filename, @Size(16) String comm) {}
 *     // which can also be written as, with 'extends Struct' being optional
 *     @Type
 *     static class Event extends Struct {
 *       @Unsigned int pid;
 *       @Size(256) String filename;
 *       @Size(16) String comm;
 *     }
 *
 *     // union
 *     @Type
 *     static class Address extends Union {
 *        @Unsigned int ipv4;
 *        @Size(16) byte[] ipv6;
 *     }
 * }
 * <p>
 * Members can be one of the following:
 * <ul>
 *     <li>integer types (int, long, ...), optionally annotated with {@link Unsigned} if unsigned</li>
 *     <li>String types, annotated with {@link Size} to specify the size</li>
 *     <li>Other {@link Type} annotated types or types that satisfy all criteria of type annotated ones</li>
 *     <li>Arrays of all of the above, annotated with {@link Size} to specify the size</li>
 * </ul>
 */
@Target(ElementType.TYPE)
public @interface Type {

    /** Name of the generated BPFStructType, uses the type as default */
    String name() default "";

    /** Don't generate C code and insert it into the ebpf program string */
    boolean noCCodeGeneration() default false;
}