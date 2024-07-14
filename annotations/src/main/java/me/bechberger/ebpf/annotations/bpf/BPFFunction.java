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
     * The format is specified as in {@link BuiltinBPFFunction#value()},
     * additionally the following variables are available:
     * <ul>
     *     <li>{@code $returnType} - the return type of the function</li>
     *     <li>{@code $argTypeN} - the type of the parameter N, starting at one</li>
     * </ul>
     * If no parameters are specified, then the existing parameter types and name will be used.
     * Be aware that changing the parameters might cause problems.
     * <p>
     * Example: {@code int BPF_PROG($name, int dfd, struct filename *name)}
     */
    String headerTemplate() default "$name";

    /** Template for the end of the function in C */
    String lastStatement() default "";

    /** Section to place the function in, like the {@code SEC} annotation in C */
    String section() default "";
}