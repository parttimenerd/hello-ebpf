package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a BPF-context pointer as originating from kernel space.
 *
 * <p>When the compiler plugin sees a dereference ({@code ptr.val()}) on a {@code @BPFKernelMemory}
 * pointer, it will (in a future pass) automatically emit
 * {@code bpf_probe_read_kernel(&dst, sizeof(dst), ptr)} instead of a direct load for
 * pointers the verifier does not track directly.
 *
 * @see BPFUserMemory
 */
@Target({ElementType.PARAMETER, ElementType.LOCAL_VARIABLE})
@Retention(RetentionPolicy.RUNTIME)
public @interface BPFKernelMemory {
}
