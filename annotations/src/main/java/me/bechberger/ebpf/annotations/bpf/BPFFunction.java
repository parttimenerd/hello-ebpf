package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Specify a function that is callable from C code and has an implementation
 * or an interface.
 * <p>
 * {@snippet :
 *    @BPFFunction(
 *        headerTemplate = "int BPF_PROG(do_unlinkat, int dfd, struct filename *name)",
 *        lastStatement = "return 0;",
 *        section = "fentry/do_unlinkat"
 *    )
 *    public default void enterUnlinkat(int dfd, Ptr<filename> name) {
 *        throw new MethodIsBPFRelatedFunction();
 *    }
 * }
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFFunction {

    /**
     * Template for generating calls in C to this function.
     * <p>
     * The format is specified as in {@link BuiltinBPFFunction#value()}
     */
    String callTemplate() default "$name";

    /**
     * Template for generating the header of the function in C.
     * <p>
     * The header is defined with the following placeholders:
     * <ul>
     *     <li>{@code $name}: name of the function in C (either {@link BPFFunction#name()} or the method name)</li>
     *     <li>{@code $return}: return type of the function</li>
     *     <li>{@code $paramNameN}: name of the parameter N, starting at one</li>
     *     <li>{@code $paramTypeN}: type of the parameter N</li>
     *     <li>{@code $paramN}: parameter N with type</li>
     *     <li>{@code $params}: parameters with types, comma separated</li>
     * </ul>
     * if only {@code $name} is given, then this will be treated as {@code $return $name($params)}.
     * <p>
     * Example: {@code int BPF_PROG($name, int dfd, struct filename *name)}
     */
    String headerTemplate() default "$name";

    /** Template for the end of the function in C, e.g. {@code return 1} */
    String lastStatement() default "";

    /** Section to place the function in, like the {@code SEC} annotation in C */
    String section() default "";

    /**
     * Whether the function should be automatically attached to a program when
     * using {@code BPPProgram::autoAttachPrograms}.
     * <p>
     * If used, then the function name has to be the result of {@code $name}
     * (so either the name of the method or the name specified in {@link BPFFunction#name()}).
     *
     * @return whether the function should be automatically attached
     */
    boolean autoAttach() default false;

    /**
     * Name of the function in C
     */
    String name() default "";
}
