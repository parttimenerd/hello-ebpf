package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks a function as a builtin BPF function, which is not defined in the program.
 * <p>
 * Example: {@snippet :
 *    class Test {
 *    @BuiltinBPFFunction
 *    static void bpf_trace_printk(String fmt, Object... args) {}
 *    }
 *
 *    // with this the following code in Java
 *    Test.bpf_trace_printk("Hello, %s!", "world");
 *    // will be translated into the following C code
 *    bpf_trace_printk("Hello, %s!", "world");
 * }
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BuiltinBPFFunction {

    /**
     * Call template to call the function in C, or just the function name to call with the arguments directly.
     * <p>
     * The method body has to throw a {@link me.bechberger.ebpf.annotations.MethodIsBPFRelatedFunction} exception.
     * <p>
     * The signature is defined via a template with the following placeholders:
     * <ul>
     *     <li>$return: The return type</li>
     *     <li>$name: The name of the function</li>
     *     <li>$args: The arguments of the function, comma separated</li>
     *     <li>$argN: Argument N, starting at one</li>
     *     <li>$argsN_: Arguments N to the last argument, comma separated</li>
     * </ul>
     * <p>
     * if only an identifier is given, then this will be treated as {@code <identifier>($args)}
     * <p>
     * Example: {@snippet :
     *    @BuiltinBPFFunction("$name($args)")
     *    void func(int a, int b);
     *    func(1, 2)
     *    // will be translated to
     *    func(1, 2)
     *
     *    @BuiltinBPFFunction("((int)function($args))")
     *    int func(int a, int b);
     *    func(1, 2)
     *    // will be translated to
     *    ((int)function(1, 2))
     *
     *    @BuiltinBPFFunction("func($arg1, $args2_, $arg1)")
     *    void func(int a, int b, int c);
     *    func(1, 2, 3)
     *    // will be translated to
     *    func(1, 2, 3, 1)
     * }
     */
    String value() default "$name";
}