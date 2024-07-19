package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Add more includes to the generated eBPF program.
 * <p>
 * Example: {@snippet :
 *    @BPF
 *    @Includes("stdio.h")
 *    abstract class HelloWorld extends BPFProgram {
 *    }
 * }
 * Results in {@code EBPF_PROGRAM} containing {@code #include <stdio.h>}
 * <p>
 * This also works if it is used on interfaces that the BPF program implements.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Includes {

    /**
     * The includes to add to the generated eBPF program.
     */
    String[] value();
}
