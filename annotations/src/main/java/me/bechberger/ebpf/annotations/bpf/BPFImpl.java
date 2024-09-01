package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * This annotation marks a class as a an annotation processor generated implementation of a BPF program (annoted
 * with {@link BPF}).
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFImpl {

    String before();

    String after();
}
