package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Annotates a record or a class for with a struct, union or typedef type is generated
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
 *
 *     // typedef
 *     @Type
 *     record IntArray(@Size(10) int[] val) implements Typedef<@Size(10) int[]> {}
 *
 *     // enum
 *     @Type
 *     enum Kind implements Enum<Kind> {
 *        A, B, C, D
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
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Type {

    /** Name of the generated BPFStructType, uses the type as default */
    String name() default "";

    /** Don't generate C code and insert it into the ebpf program string */
    boolean noCCodeGeneration() default false;

    /**
     * Don't add {@code struct} or {@code union} when using the type in C, and use
     * {@code typedef ... name;} when defining it
     */
    boolean typedefed() default false;

    /**
     * Use the given C type instead of the generated one, might contain placeholders
     * <p>
     * Placeholders:
     * <ul>
     *     <li>{@code $T1, ...}: Template parameters of the type</li>
     * </ul>
     */
    String cType() default "";
}