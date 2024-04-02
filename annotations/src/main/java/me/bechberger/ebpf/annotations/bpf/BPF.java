package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Target;

/**
 * This annotation is used trigger processing of classes that extend BPFProgram
 * <p>
 * Example:
 * {@snippet :
 * @BPF
 * public static abstract class HelloWorldProgram extends BPFProgram {
 *     static final String EBPF_PROGRAM = """ ... """;
 *     public static void main(String[] args) {
 *          try (HelloWorldProgram program = new HelloWorldProgramImpl()) {
 *               program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
 *               program.tracePrintLoop();
 *          }
 *     }
 * }
 */
@Target(ElementType.TYPE)
public @interface BPF {
    /**
     * License of the eBPF program, the EBPF_PROGRAM contains a <code>SEC("license")</code> variable
     * only iff this license is not present. Typically, the license is GPL.
     */
    String license() default "";
}
