package me.bechberger.ebpf.annotations;

import java.lang.annotation.*;

/**
 * Annotates a class that can be used like a {@link Type} annotated record,
 * but is not a record itself and specifies a BPFType
 * to be used and the C code to be generated.
 * <p>
 * Example:
 * {@snippet :
 * public static BPFStructType<IntPair> INT_PAIR = BPFStructType.autoLayout("IntPair",
 *         List.of(new BPFType.UBPFStructMember<>("x", INT32, IntPair::x),
 *                 new BPFType.UBPFStructMember<>("y", INT32, IntPair::y)),
 *         new BPFType.AnnotatedClass(IntPair.class, List.of()),
 *         fields -> new IntPair((int) fields.get(0), (int) fields.get(1)));
 *
 * @CustomType(
 *         isStruct = true,
 *         specFieldName = "$outerClass.INT_PAIR", cCode = """
 *         struct $name {
 *           int x;
 *           int y;
 *         };
 *         """)
 * record IntPair(int x, int y) {}
 * }
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CustomType {
    /** Name of the type in C, uses the class name by default */
    String name() default "";

    boolean isStruct();

    /**
     * BPFType field that contains the related BPFType
     * <p>
     * $class is replaced with the fully qualified class name, and $outerClass is replaced with the outer class name
     */
    String specFieldName();

    /**
     * C code that should be generated for this type
     * <p>
     * $name is replaced with the specified C name
     */
    String cCode() default "";
}