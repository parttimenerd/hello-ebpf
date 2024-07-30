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
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BuiltinBPFFunction {

    /**
     * Call template to call the function in C, or just the function name to call with the arguments directly.
     * <p>
     * The method body has to throw a {@link MethodIsBPFRelatedFunction} exception.
     * <p>
     * The signature is defined via a template with the following placeholders:
     * <ul>
     *     <li>{@code $return}: The return type</li>
     *     <li>{@code $name}: The name of the function</li>
     *     <li>{@code $args}: The arguments of the function, comma separated</li>
     *     <li>{@code $argN}: Argument N, starting at one</li>
     *     <li>{@code $argsN_}: Arguments N to the last argument, comma separated</li>
     *     <li>{@code $this}: The object the method is called on</li>
     *     <li>{@code $T1, $T2, ...}: Type parameters</li>
     *     <li>{@code $C1, $C2, ...}: Type parameters of the type of {@code $this}</li>
     *     <li>{@code $strlen$this}: length of the {@code $this} interpreted as a string literal</li>
     *     <li>{@code $strlen$argN}: length of the {@code $argN} interpreted as a string literal</li>
     *     <li>{@code $str$argN}: Asserts that {@code $argN} is a string literal</li>
     *     <li>{@code $pointery$argN}: if {@code $argN} is not a pointer (or an array or a string), then prefix it with {@code &} and assume that it is an lvalue</li>
     * </ul>
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
     *
     *    @BuiltinBPFFunction("func($str$arg1, sizeof($arg1))")
     *    void func(String a);
     *    func("abc")
     *    // will be translated to
     *    func("abc", sizeof("abc"))
     * }
     */
    String value() default "$name($args)";
}
