package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.ElementType;
import java.lang.annotation.Target;

/**
 * This annotation is used trigger processing of classes that extend BPFProgram
 */
@Target(ElementType.TYPE)
public @interface BPF {
}
